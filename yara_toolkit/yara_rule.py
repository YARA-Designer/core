import copy
import json
import os
import re
from pathlib import Path
from typing import List, Union

import yara
from yara import WarningError as YaraWarningError
from yara import TimeoutError as YaraTimeoutError

from handlers.log_handler import create_logger
from yara_toolkit.utils import sanitize_identifier, determine_value_type, is_hex_esc_sequence
from yara_toolkit.yara_meta import YaraMeta
from yara_toolkit.yara_string import YaraString, TEXT_TYPE, HEX_TYPE, REGEX_TYPE, VALID_MOD_KEYWORDS, MODS_WITH_PAYLOAD, \
    XOR, BASE64, BASE64_WIDE
from yara_toolkit.keywords import KEYWORDS
from handlers.config_handler import CONFIG

log = create_logger(__name__)

INVALID_IDENTIFIERS = [].extend(KEYWORDS)  # FIXME: Implement validity check against reserved kw.

YARA_VAR_SYMBOL = "$"
CONDITION_INDENT_LENGTH = 8
SOURCE_FILE_EXTENSION = ".yar"
COMPILED_FILE_EXTENSION = ".bin"
RULES_DIR = os.path.join(CONFIG["theoracle_local_path"], CONFIG["theoracle_repo_rules_dir"])
STRING_PLACEHOLDER = "#"
REGEX_PLACEHOLDER = "~"
HEXADECIMAL_PLACEHOLDER = "¤"
COMMENT_LINE_PLACEHOLDER = "@"
COMMENT_BLOCK_PLACEHOLDER = "%"


class YaraRuleSyntaxError(Exception):
    def __init__(self, message: Union[str, None], yara_syntax_error_exc: yara.SyntaxError = None, rule=None, line_number=None,
                 column_number=None, column_range=None, word=None):
        super().__init__(message)

        if message is None:
            if yara_syntax_error_exc is None:
                self.message = "Column number: {column_number} (columns: " \
                    "{column_number}-{column_range}, word: '{word}')".format(
                        column_number=column_number,
                        column_range=column_range,
                        word=word)
            else:
                # Parse syntax error reason out of the SyntaxError message.
                log.debug(str(yara_syntax_error_exc))
                log.debug(str(yara_syntax_error_exc).split(':'))
                self.reason = str(yara_syntax_error_exc).split(':')[1][1:]
                log.debug(self.reason)

                self.message = "{reason} in string '{word}', columns: " \
                               "{column_number}-{column_range}.".format(
                                reason=self.reason,
                                column_number=column_number,
                                column_range=column_range,
                                word=word)
                log.debug(self.message)
        else:
            self.message = message

        self.rule = rule
        self.line_number = line_number
        self.column_number = column_number
        self.column_range = column_range
        self.word = word

    def __str__(self):
        return self.message


class YaraRuleParserSyntaxError(Exception):
    def __init__(self, message: str, line=None):
        super().__init__(message)

        self.message = message
        self.line = line

    def __str__(self):
        return self.message


class YaraMatchCallback:
    """
    Class to use with yara.Rules.match in order to avoid messy globals that has issues if more than one
    YaraRule uses it at the same time.

    Usage: Initialise it, then pass the callback function reference to yara.Rules.match(callback=...)

    Official documentation: https://yara.readthedocs.io/en/latest/yarapython.html
    """
    def __init__(self):
        self.log = create_logger(__name__)

        self.matches = None
        self.rule = None
        self.namespace = None
        self.tags = None
        self.meta = None
        self.strings = None

    def callback(self, callback_dict: dict):
        """
        Function to be passed to yara.Rules.match.

        :param callback_dict:   The passed dictionary will be something like this:
                                    {
                                      'tags': ['foo', 'bar'],
                                      'matches': True,
                                      'namespace': 'default',
                                      'rule': 'my_rule',
                                      'meta': {},
                                      'strings': [(81L, '$a', 'abc'), (141L, '$b', 'def')]
                                    }

                                The matches field indicates if the rule matches the data or not.
                                The strings fields is a list of matching strings, with vectors of the form:
                                    (<offset>, <string identifier>, <string data>)



        :return yara.CALLBACK_ABORT:    Stop after the first rule, as we only have one.
        """
        self.log.info("YaraMatchCallback.callback({})".format(callback_dict))

        if "matches" in callback_dict:
            self.matches = callback_dict["matches"]
        if "rule" in callback_dict:
            self.rule = callback_dict["rule"]
        if "namespace" in callback_dict:
            self.namespace = callback_dict["namespace"]
        if "tags" in callback_dict:
            self.tags = callback_dict["tags"]
        if "meta" in callback_dict:
            self.meta = callback_dict["meta"]
        if "strings" in callback_dict:
            self.strings = callback_dict["strings"]

        # Stop applying rules to your data.
        return yara.CALLBACK_ABORT


class YaraRule:
    def __init__(self, name: str, tags: List[str] = None, meta: List[YaraMeta] = None,
                 strings: List[YaraString] = None, condition: str = None, namespace: str = None,
                 compiled_blob: yara.Rules = None, compiled_path: str = None,
                 compiled_match_source: bool = None):
        """
        YARA rule object.

        :param name:            Rule name.
        :param tags:            List of tags.
        :param meta:            Metadata.
        :param strings:         List of strings (variables).
        :param condition:       Condition string.
        :param namespace:       Namespace of YARA rule.
        :param compiled_blob:   Raw yara.Rules object generated by yara.compile
                                (usually set when spawned by cls from_compiled_file).
        :param compiled_path:   Path to the compiled YARA rule
                                (usually set when spawned by cls from_compiled_file).
        """
        self.log = create_logger(__name__)

        self.name: str = sanitize_identifier(name)

        if tags is not None:
            self.tags: list = [sanitize_identifier(x) for x in tags]

        self.meta: List[YaraMeta] = meta
        self.strings: List[YaraString] = strings

        if condition is not None:
            # Sanitize every identifier in the condition string.
            if len(condition) > 0:
                self.condition = \
                    " ".join([part[0] + sanitize_identifier(part[1:])
                              if part[0] == YARA_VAR_SYMBOL else part for part in condition.split(' ')])
            else:
                self.condition = condition

        self.namespace = namespace
        self.compiled_blob = compiled_blob
        self.compiled_path = compiled_path
        self.compiled_match_source = compiled_match_source

    @classmethod
    def from_dict(cls, dct: dict):
        """
        Initialize YaraRule from a dict.

        :param dct: Dict on the form of:
                    {
                        name: str,
                        tags: List[str],
                        meta: {identifier, value, value_type},
                        strings: [{identifier, value, value_type, string_type, modifiers, modifier_str, str}]
                        condition: str
                    }.
        :return:
        """
        return cls(name=dct["name"],
                   tags=dct["tags"],
                   meta=[YaraMeta(ym["identifier"], ym["value"], ym["value_type"]) for ym in dct["meta"]],
                   strings=
                   [YaraString(ys["identifier"], ys["value"], ys["value_type"], ys["string_type"], ys["modifiers"])
                    for ys in dct["strings"]],
                   condition=dct["condition"])

    @staticmethod
    def abstract_source_body(body):
        """
        Generate a string safe copy of the body, which won't contain irrelevant extra ':' chars etc.

        This function takes a source body and replaces various parts with safe placeholders, in order to avoid
        parsing issues with unpredictable wildcard content in strings and whatnot.

        :param body:
        :return:
        """
        # Create a copy of body to break down in order to find the true meta and string keywords
        modified_body = copy.deepcopy(body)

        # Make a pass to replace all string values with placeholders.
        inside_quoted_string = False
        inside_regex_string = False
        inside_hex_string = False
        inside_escape_sequence = False
        inside_multichar_escape_sequence = False
        inside_comment_line = False
        comment_line = ""
        comment_lines = []
        inside_comment_block = False
        comment_block = ""
        comment_blocks = []
        string_safe_body = ""
        escape_terminators = ['\\', '"', 't', 'n']
        escape_chars_not_to_replace = ['\n', '\t', '\r', '\b', '\f']
        chars_not_to_replace = escape_chars_not_to_replace
        chars_not_to_replace.extend(' ')
        separators = [' ', '\n', '\t']

        last_line_start_index = 0
        line = ""
        for i in range(len(modified_body)):
            c = modified_body[i]  # Helps on readability.
            line += c
            if c == '\n':
                # log.debug("line: {}".format(modified_body[last_line_start_index:i]))
                last_line_start_index = i + 1
                line = ""

            if inside_quoted_string:
                if inside_escape_sequence:
                    if inside_multichar_escape_sequence:
                        if is_hex_esc_sequence(modified_body[i - 3:i + 1]):
                            inside_escape_sequence = False
                            inside_multichar_escape_sequence = False
                    else:
                        if c in escape_terminators:
                            inside_escape_sequence = False
                        else:
                            # If the char after \ isn't a terminator, then this is a hex/multichar escape sequence.
                            inside_multichar_escape_sequence = True
                else:
                    if c == '\\':
                        inside_escape_sequence = True
                    elif c == '"':
                        inside_quoted_string = False

                # Replace current char with safe placeholder.
                string_safe_body += STRING_PLACEHOLDER
            elif inside_regex_string:
                if c == '/' and modified_body[i + 1] in separators:
                    inside_regex_string = False

                # Replace current char with safe placeholder.
                string_safe_body += REGEX_PLACEHOLDER
            elif inside_hex_string:
                if c == '}' and modified_body[i + 1] in separators:
                    inside_hex_string = False

                # Replace current char with safe placeholder.
                string_safe_body += HEXADECIMAL_PLACEHOLDER
            elif inside_comment_line:
                comment_line += c

                if c == '\n':
                    string_safe_body += c
                    log.info("comment line: {}".format(comment_line))
                    comment_lines.append(comment_line)
                    comment_line = ""
                    inside_comment_line = False
                else:
                    string_safe_body += COMMENT_LINE_PLACEHOLDER
            elif inside_comment_block:
                comment_block += c

                if c == '/' and modified_body[i - 1] == '*':
                    log.info("comment block:\n{}".format(comment_block))
                    string_safe_body += COMMENT_BLOCK_PLACEHOLDER
                    comment_blocks.append(comment_block)
                    comment_block = ""
                    inside_comment_block = False
                else:
                    string_safe_body += COMMENT_BLOCK_PLACEHOLDER if c not in chars_not_to_replace else c
            else:
                if c == '"':
                    inside_quoted_string = True
                    string_safe_body += STRING_PLACEHOLDER
                elif c == '/' and modified_body[i + 1] != '/' and modified_body[i + 1] != '*':
                    inside_regex_string = True
                elif c == '{':
                    inside_hex_string = True
                elif c == '/' and modified_body[i + 1] == '/':
                    inside_comment_line = True
                    comment_line += c
                    string_safe_body += COMMENT_LINE_PLACEHOLDER
                elif c == '/' and modified_body[i + 1] == '*':
                    inside_comment_block = True
                    comment_block += c
                    string_safe_body += COMMENT_BLOCK_PLACEHOLDER
                else:
                    string_safe_body += c

        return string_safe_body

    @staticmethod
    def parse_strings_body(strings_body):
        """
        Generate a string safe copy of the body, which won't contain irrelevant extra ':' chars etc.

        This function takes a source body and replaces various parts with safe placeholders, in order to avoid
        parsing issues with unpredictable wildcard content in strings and whatnot.

        :param strings_body:
        :return:
        """
        # Create a copy of body to break down in order to find the true meta and string keywords
        modified_body = copy.deepcopy(strings_body)

        inside_identifier = False
        inside_quoted_string = False
        inside_regex_string = False
        inside_hex_string = False
        inside_escape_sequence = False
        inside_multichar_escape_sequence = False
        inside_comment_line = False
        inside_comment_block = False
        inside_possible_modifiers_segment = False
        inside_modifier_payload_segment = False
        inside_base64_modifier_payload_segment = False
        inside_xor_modifier_payload_segment = False

        comment_line = ""
        comment_lines = []
        comment_block = ""
        comment_blocks = []
        string_safe_body = ""
        escape_terminators = ['\\', '"', 't', 'n']
        escape_chars_not_to_replace = ['\n', '\t', '\r', '\b', '\f']
        chars_not_to_replace = escape_chars_not_to_replace
        chars_not_to_replace.extend(' ')
        separators = [' ', '\n', '\t']

        identifier = ""
        value = ""
        string_type = ""
        modifier_string = ""
        modifier_payload_string = ""
        modifiers = []
        strings = []

        has_processed_at_least_one_item = False
        last_line_start_index = 0
        line = ""

        # def clear_modifier_string(s):
        #     """"Destructively clear string s"""
        #     s = ""

        def add_modifier(kw, data, mod_list):
            mod_list.append({
                "keyword": kw,
                "data": data
            })

            # kw = ""

        for i in range(len(modified_body)):
            c = modified_body[i]  # Helps on readability.
            line += c
            if c == '\n':
                log.debug("line: {}".format(modified_body[last_line_start_index:i]))
                last_line_start_index = i + 1
                line = ""

            if inside_identifier:
                if c in separators or c == '=':
                    # If there is any sort of spacing or we get the assignment operator,
                    # then we know for sure that the identifier has terminated.
                    inside_identifier = False
                else:
                    identifier += c
            elif inside_quoted_string:
                if inside_escape_sequence:
                    if inside_multichar_escape_sequence:
                        if is_hex_esc_sequence(modified_body[i - 3:i + 1]):
                            inside_escape_sequence = False
                            inside_multichar_escape_sequence = False
                    else:
                        if c in escape_terminators:
                            inside_escape_sequence = False
                        else:
                            # If the char after \ isn't a terminator, then this is a hex/multichar escape sequence.
                            inside_multichar_escape_sequence = True
                else:
                    if c == '\\':
                        inside_escape_sequence = True
                    elif c == '"':
                        inside_quoted_string = False

                        # We're now in a segment where modifiers may exist, but we're not really sure.
                        # So we'll run the code for modifier parsing and have it be terminated by the next
                        # YARA_VAR_SYMBOL.
                        inside_possible_modifiers_segment = True

                if inside_quoted_string:
                    # Omit the single case where c == '"' to avoid adding redundant end quote.
                    value += c
            elif inside_regex_string:
                if c == '/' and modified_body[i + 1] in separators:
                    inside_regex_string = False
                else:
                    value += c
            elif inside_hex_string:
                if c == '}' and modified_body[i + 1] in separators:
                    inside_hex_string = False
                else:
                    value += c
            elif inside_possible_modifiers_segment:
                if inside_xor_modifier_payload_segment:
                    if c == ')':
                        if len(modifier_string) > 0:
                            add_modifier(modifier_string, modifier_payload_string, modifiers)
                            modifier_string = ""
                            modifier_payload_string = ""
                        inside_xor_modifier_payload_segment = False
                    else:
                        # We're still inside the XOR payload segment.
                        modifier_payload_string += c
                elif inside_base64_modifier_payload_segment:
                    # Make sure there exists more characters ahead, before attempting inner lookahead logic.
                    if len(modified_body) > i + 1:
                        # Base64 has a custom alphabet which makes determining the true termination rather tricky..
                        # So we'll have to check for that the string ends in '")' followed by a separator.
                        if c == ')' and modified_body[i-1] == '"' and modified_body[i+1] in separators:
                            if len(modifier_string) > 0:
                                add_modifier(modifier_string, modifier_payload_string, modifiers)
                                modifier_string = ""
                                modifier_payload_string = ""
                            inside_base64_modifier_payload_segment = False
                        else:
                            # We're still inside the BASE64 payload segment.
                            modifier_payload_string += c
                    else:
                        # In this case there exists no separator to check for ahead, but since we're at the end,
                        # it's pretty certain that this is the terminating char after all.
                        if c == ')' and modified_body[i-1] == '"':
                            if len(modifier_string) > 0:
                                add_modifier(modifier_string, modifier_payload_string, modifiers)
                                modifier_string = ""
                                modifier_payload_string = ""
                            inside_base64_modifier_payload_segment = False
                        else:
                            raise YaraRuleParserSyntaxError(
                                "Unterminated YARA string modifier payload on this line: {}".format(line), line=line)
                else:
                    if c == '(':
                        # Perform check for possible payload segment.
                        for keyword in MODS_WITH_PAYLOAD:
                            # Knowing that we need an identifier, assignment op and value in front,
                            # we can safely assume that i needs to be longer than keyword for us to
                            # be in the modifier payload segment (saving us from accidentally going out of range).
                            if i > len(keyword):
                                backtracked_keyword = modified_body[i-len(keyword):i]
                                print(backtracked_keyword)
                                if backtracked_keyword == keyword:
                                    inside_modifier_payload_segment = True

                                    # Different modifier payload needs different handling,
                                    # especially in terms of how to recognise terminator.
                                    if keyword == XOR:
                                        inside_xor_modifier_payload_segment = True
                                    elif keyword == BASE64 or keyword == BASE64_WIDE:
                                        inside_base64_modifier_payload_segment = True
                                    else:
                                        raise ValueError(
                                            "Invalid backtracked modifier payload segment: {}".format(keyword))

                    # Make sure there exists more characters ahead, before attempting inner lookahead logic.
                    if len(modified_body) > i+1:
                        if c not in separators and c != '':
                            modifier_string += c

                        # Look ahead one char in order to not block the vital 'else'
                        # condition that needs to be triggered when c == YARA_VAR_SYMBOL.
                        if modified_body[i+1] == YARA_VAR_SYMBOL:
                            if len(modifier_string) > 0:
                                # modifiers.append({
                                #     "keyword": modifier_string,
                                #     "data": None
                                # })
                                #
                                add_modifier(modifier_string, None, modifiers)
                                modifier_string = ""

                            inside_possible_modifiers_segment = False
                        elif modified_body[i+1] in separators:
                            # Modifier item boundary reached
                            # (but more may exist ahead as we're still in the modifiers segment)
                            if len(modifier_string) > 0:
                                add_modifier(modifier_string, None, modifiers)
                                modifier_string = ""
                    else:
                        # If we're at the end, then we can safely assume
                        # that the modifiers segment ends on this char.
                        if c not in separators and c != '':
                            modifier_string += c

                        if len(modifier_string) > 0:
                            # modifiers.append({
                            #     "keyword": modifier_string,
                            #     "data": None
                            # })
                            #
                            add_modifier(modifier_string, None, modifiers)
                            modifier_string = ""

                        inside_possible_modifiers_segment = False

            elif inside_comment_line:
                comment_line += c

                if c == '\n':
                    log.info("comment line: {}".format(comment_line))
                    comment_lines.append(comment_line)
                    comment_line = ""
                    inside_comment_line = False
            elif inside_comment_block:
                comment_block += c

                if c == '/' and modified_body[i - 1] == '*':
                    log.info("comment block:\n{}".format(comment_block))
                    comment_blocks.append(comment_block)
                    comment_block = ""
                    inside_comment_block = False
            else:
                if c == YARA_VAR_SYMBOL:
                    if has_processed_at_least_one_item:
                        # If this isn't the first item, add the previous to the list
                        _ = {
                            "identifier": identifier,
                            "value": value,
                            "string_type": string_type,
                            "modifiers": modifiers
                        }

                        log.info("Adding YARA String '{identifier}':\n{js}".format(
                            identifier=identifier, js=json.dumps(_, indent=4)))

                        strings.append(_)

                        # Reset per-item variables.
                        identifier, value, string_type, modifier_string, modifiers = "", "", "", "", []
                    else:
                        # Technically not entirely true (yet), but the only way to tell that
                        # you hit the boundary is when you hit the next YARA_VAR_SYMBOL.
                        has_processed_at_least_one_item = True

                    inside_identifier = True
                elif c == '"':
                    inside_quoted_string = True
                    string_type = TEXT_TYPE
                elif c == '/' and modified_body[i + 1] != '/' and modified_body[i + 1] != '*':
                    inside_regex_string = True
                    string_type = REGEX_TYPE
                elif c == '{':
                    inside_hex_string = True
                    string_type = HEX_TYPE
                elif c == '/' and modified_body[i + 1] == '/':
                    inside_comment_line = True
                    comment_line += c
                elif c == '/' and modified_body[i + 1] == '*':
                    inside_comment_block = True
                    comment_block += c

        return strings

    @classmethod
    def from_source_file(cls, source_path=None):
        """Initialize YaraRule from sourcecode using own custom written parser."""
        try:
            source_code = None
            with open(source_path, 'r') as f:
                source_code = f.read()

            log.debug(source_code)

            constructor_line_pattern = re.compile(
                r"(?P<rule_keyword>rule)\s+(?P<rule_identifier>\w+)(?P<tag_body>(?P<tag_delimiter>:)\s+(?P<tags>[\s+\w]+))?\{(?P<rule_body>.*)\}",
                re.MULTILINE | re.DOTALL)

            constructor_line_match = constructor_line_pattern.search(source_code)

            rule_pattern = re.compile(
                r"(?P<rule_keyword>rule)\s+(?P<rule_identifier>\w+)"
                r"(?P<tag_body>(?P<tag_delimiter>:)\s+(?P<tags>[\s+\w]+))?"
                r"\{(?P<body>.*(?P<meta_body>(?P<meta_constructor>meta:)\s+(?P<meta_content>.*\w))?\s+"
                r"(?P<strings_body>(?P<strings_constructor>strings:)\s+(?P<strings_content>.*[\w\}\)]))?.*)"
                r"(?P<condition_body>(?P<condition_constructor>condition:)\s+(?P<condition_content>.*)).*\}",
                re.MULTILINE | re.DOTALL
            )

            rule_match = constructor_line_pattern.search(source_code)

            log.debug(rule_match.groupdict())

            name = rule_match.groupdict()["rule_identifier"]

            # Only add valid tags to tags list (apply some sanitation on the matched string).
            tags = []
            for tag in rule_match.groupdict()["tags"].strip('\n').replace('\t', ' ').split(' '):
                if tag != ' ' and tag != '':
                    tags.append(tag)

            # If no tags were added, set it to None for a more clean approach.
            if len(tags) == 0:
                tags = None

            # condition = rule_match.groupdict()["condition_content"]
            condition = None

            body = rule_match.groupdict()["rule_body"]

            log.debug("body:\n{}".format(body))

            # ###### Seek thru the whole shebang until you match keyword.

            # Generate a string safe copy of the body, which won't contain irrelevant extra ':' chars etc.
            string_safe_body = cls.abstract_source_body(body)

            log.info("string-safe body:\n{}".format(string_safe_body))

            # Get index of meta and strings (if either is present)
            meta_index = string_safe_body.find("meta:")
            strings_index = string_safe_body.find("strings:")
            condition_index = string_safe_body.find("condition:")

            log.info("Meta @ {m}, Strings @ {s}, Condition @ {c}".format(
                m=meta_index, s=strings_index, c=condition_index))

            # Make a second pass with a pattern that doesn't use dotall, in order to better parse each sub-body,
            # FIXME: Check if meta can go after string in a rule (read: more headache if-spaghetti needed if so...)
            meta = None
            strings = None
            if meta_index > -1:
                if strings_index > -1:
                    # If we have strings, then that is our body part cutoff.
                    meta_body = body[meta_index+len("meta:"):strings_index]
                    log.info("meta body:\n{}".format(meta_body))
                else:
                    # If we don't have strings then condition will be our body part cutoff.
                    meta_body = body[meta_index+len("meta:"):condition_index]
                    log.info("meta body:\n{}".format(meta_body))

                # Parse meta body items into a list of regex match group dicts.:
                p = re.compile(
                    r"\s*(?P<full>(?P<identifier>\w+)\s*=\s*(?P<value>\".*\"|true|false|[0-9]*)).*",
                    re.MULTILINE)

                # Use finditer() to get a sequence of match objects, in order to get the groupdict for each match.
                match_dicts = [m.groupdict() for m in p.finditer(meta_body)]
                log.info("meta body match dict:\n{}".format(json.dumps(match_dicts, indent=4)))

                # Parse matched dicts into a list of YaraMeta objects.
                meta = []
                for d in match_dicts:
                    identifier = d["identifier"]
                    value = d["value"]
                    value_type = determine_value_type(value)

                    if value_type is str:
                        # If value type is a string, strip the redundant quotes,
                        # which will just make a mess of things.
                        value = value[1:-1]

                    meta.append(YaraMeta(identifier, value, value_type))

                log.info("Parsed YaraMeta objects:\n{}".format(json.dumps([repr(o) for o in meta], indent=4)))

            if strings_index > -1:
                strings_body = body[strings_index+len("strings:"):condition_index]
                log.info("strings body:\n{}".format(strings_body))

                # Parse strings programmatically (wildcard content makes regex approach exceedingly hard)
                strings = cls.parse_strings_body(strings_body)
                log.info("Parsed YARA strings:\n{}".format(json.dumps(strings, indent=4)))

                # Parse strings body items into a list of regex match group dicts.:
                # p = re.compile(
                #     r"\s*(?P<item>(?P<identifier>\w+)\s*=\s*(?P<value>\".*\"|true|false|[0-9]*)).*",
                #     re.MULTILINE)

                # Use finditer() to get a sequence of match objects, in order to get the groupdict for each match.
                # match_dicts = [m.groupdict() for m in p.finditer(strings_body)]
                # log.info("strings body match dict:\n{}".format(json.dumps(match_dicts, indent=4)))

                # Parse matched dicts into a list of YaraMeta objects.
                # strings = [YaraString(d["identifier"], d["value"]) for d in match_dicts]

            # FIXME: Insert condition parsing here.

            parsed_source = {
                "name": name,
                "tags": tags,
                "meta": [repr(o) for o in meta] if isinstance(meta, list) else None,
                "strings": [repr(o) for o in strings] if isinstance(strings, list) else None,
                "condition": condition
            }
            log.info("parsed_source:\n{}".format(json.dumps(parsed_source, indent=4)))

            return None

            return cls(name, tags, meta, strings, condition)

        except Exception as exc:
            log.exception("YaraRule.from_source_file exc", exc_info=exc)
            return None

    @classmethod
    def from_source_file_yara_python(cls, source_path=None):
        """Initialize YaraRule from sourcecode using the limited yara-python API."""
        try:
            # Compile the YARA source code (only way to get yara-python to parse the thing)
            yar_compiled = yara.compile(filepath=source_path)

            # Get the parsed source code via yara.Rules.match
            yar_src = yar_compiled.match(filepath=source_path)[0]

            name = yar_src.rule
            namespace = yar_src.namespace
            tags = yar_src.tags
            meta = [YaraMeta(identifier, value) for identifier, value in yar_src.meta.items()]
            strings = [YaraString(identifier, value.decode('utf-8')) for offset, identifier, value in yar_src.strings]

            # Get condition from the sourcecode file by hand due to it not being part of yara.Rules.
            condition = None
            this_is_the_condition = False
            with open(source_path, 'r') as f:
                for line in f.readlines():
                    if this_is_the_condition:
                        # Strip leading whitespace/indent.
                        for i in range(len(line)):
                            if line[i] == ' ':
                                continue
                            else:
                                condition = line[i:].strip('\n')
                                break
                        break

                    if 'condition' in line.lower():
                        # Next line will contain the actual condition, this one just has the declaration.
                        this_is_the_condition = True

            log.debug(condition)

            return cls(name, tags, meta, strings, condition, namespace=namespace)

        except Exception as exc:
            log.exception("YaraRule.from_source_file_yara_python exc", exc_info=exc)
            return None

    @classmethod
    def from_compiled_file(cls, yara_rules: Union[yara.Rules, str],
                           source_filename=None, compiled_filepath=None,
                           condition: str = None, rules_dir=RULES_DIR, timeout=60):
        """
        Initialize YaraRule from a compiled (binary) file.

        :param timeout:             If the match function does not finish before the specified number
                                    of seconds elapsed, a TimeoutError exception is raised.
        :param compiled_filepath:
        :param source_filename:
        :param condition:
        :param yara_rules: yara.Rules object or path to a compiled yara rules .bin
        :param rules_dir:
        :return:
        """
        if condition is None:
            # It looks like compiled YARA rules don't have a condition,
            # so we have to apply it ourselves or leave it blank.
            condition = ""

        if isinstance(yara_rules, yara.Rules):
            if source_filename is None:
                raise ValueError("yara.Rules object was given, but source_filename was not set!")

            # Load rules from yara.Rules object.
            compiled_blob: yara.Rules = yara_rules
        elif isinstance(yara_rules, str):
            compiled_filepath = os.path.join(rules_dir, yara_rules + COMPILED_FILE_EXTENSION)
            # Set source filename.
            source_filename = yara_rules + SOURCE_FILE_EXTENSION

            # Load rules from file.
            compiled_blob: yara.Rules = yara.load(
                filepath=compiled_filepath)
        else:
            raise ValueError("yara_rules must be 'yara.Rules' object or 'str' filepath to a compiled yara rules .bin")

        # The match method returns a list of instances of the class Match.
        # Instances of this class have the same attributes as the dictionary passed to the callback function,
        # with the exception of 'matches' which is ONLY passed to the callback function!
        yara_match_callback = YaraMatchCallback()
        matches: yara.Match = compiled_blob.match(filepath=os.path.join(rules_dir, source_filename),
                                                  callback=yara_match_callback.callback,
                                                  timeout=timeout)

        meta = [YaraMeta(identifier, value) for identifier, value in yara_match_callback.meta.items()]
        namespace = yara_match_callback.namespace
        name = yara_match_callback.rule
        strings = [
            YaraString(identifier, value.decode('utf-8')) for offset, identifier, value in yara_match_callback.strings]
        tags = yara_match_callback.tags

        if not yara_match_callback.matches:
            log.error("Compiled YARA does *NOT* match source code!")
            # raise
        else:
            log.info("Compiled YARA matches source code.")
            match = matches[0]
            log.info("match: {}".format(match))

        if isinstance(yara_rules, yara.Rules) and compiled_filepath is None:
            log.warning("yara.Rules object was given, but compiled_filepath was not set, "
                        "assuming same name as rule name!")
            compiled_filepath = os.path.join(rules_dir, name + COMPILED_FILE_EXTENSION)

        return cls(name, tags, meta, strings, condition,
                   namespace=namespace, compiled_blob=compiled_blob,
                   compiled_path=compiled_filepath, compiled_match_source=yara_match_callback.matches)

    def get_referenced_strings(self) -> List[YaraString]:
        """
        In YARA it is a SyntaxError to have unreferenced strings/vars,
        so these need to be rinsed out before rule compilation.

        :return: Returns dict of strings that are referenced in the conditional statement.
        """
        # Find all occurrences of words starting with $ (i.e. variable names)
        r = re.compile(r'\$[\w]*\b\S+')
        matched_condition_strings = r.findall(self.condition)

        # Get rid of mismatches by making a list of items that only matches the actual strings/vars list.
        confirmed_items = []
        for matched_condition_identifier, yara_string in zip(matched_condition_strings, self.strings):
            if sanitize_identifier(matched_condition_identifier[1:]) == yara_string.identifier:
                confirmed_items.append(yara_string)

        return confirmed_items

    def condition_as_lines(self) -> str:
        """
        Takes a condition string and returns a string with each condition on a separate line.

        :return:
        """
        return self.condition.replace(' ', '\n')

    def __str__(self, condition_as_lines=False) -> str:
        """
        Generates a YARA rule on string form.
    
        example format:
            rule RuleIdentifier
            {
                meta:
                    description = ""
    
                strings:
                    $observable1 = ""
    
                condition:
                    $observable1
            }
    
        :return:
        """
        indent = 4 * " "
        identifier_line = "rule {name}".format(name=self.name)
        meta = ""
        strings = ""
        if condition_as_lines:
            condition = "{indent}condition:\n{indent}{indent}{condition}".format(
                indent=indent, condition=self.condition_as_lines())
        else:
            condition = "{indent}condition:\n{indent}{indent}{condition}".format(
                indent=indent, condition=self.condition)
    
        # Append tags to rule line, if provided.
        tags_str = ""
        if self.tags is not None:
            if len(self.tags) > 0:
                tags_str = (": " + " ".join(self.tags))
    
        # Add the meta info block, if provided.
        if self.meta is not None:
            if bool(self.meta):
                meta = "{indent}meta:".format(indent=indent)
                for ym in self.meta:
                    meta += "\n{indent}{indent}{yara_meta}".format(indent=indent, yara_meta=str(ym))
    
        # Add the strings (read: variables) block, id provided.
        if self.strings is not None:
            if bool(self.strings):
                strings = "{indent}strings:".format(indent=indent)
                for ys in self.get_referenced_strings():
                    strings += "\n{indent}{indent}{yara_string}".format(indent=indent, yara_string=str(ys))

        # Compile the entire rule block string.
        rule_string = \
            "{identifier_line}{tags_str}\n" \
            "{start}\n" \
            "{meta}\n" \
            "\n" \
            "{strings}\n" \
            "\n" \
            "{condition}\n" \
            "{end}\n".format(identifier_line=identifier_line, tags_str=tags_str,
                             meta=meta, strings=strings, condition=condition, start='{', end='}')
    
        log.debug(rule_string)
        return rule_string

    def save_source(self, filename: str = None, file_ext=SOURCE_FILE_EXTENSION, rules_dir=RULES_DIR) -> str:
        """
        Saves source (plaintext) YARA rules to file.

        :param filename:
        :param file_ext:
        :param rules_dir:
        :return: saved filepath as a Path(PurePath) object.
        """
        if filename is None:
            filename = self.name

        # If destination directory does not exist, create it.
        if not os.path.isdir(rules_dir):
            os.mkdir(rules_dir)

        filepath = Path(rules_dir).joinpath(filename + file_ext)

        # Save YARA source rule to plaintext file using regular Python standard file I/O.
        with open(filepath, 'w') as f:
            f.write(self.__str__())

        self.log.info("Save YARA rules to file: {}".format(filepath))

        return str(filepath.resolve(strict=True))

    def determine_syntax_error_column(self, yara_syntax_error_exc, line_number: int, splitline_number: int,
                                      raise_exc=True) -> dict:
        """
        Determines the column (and range) that compilation failed on,
        using whitespace line number and newline line numbers to determine the character offset to the word.

        :param yara_syntax_error_exc:
        :param raise_exc:               Raises YaraRuleSyntaxError immediately upon finish.
        :param line_number:             Line number that failed in the whitespace string.
        :param splitline_number:        Line number that failed in the newline string.
        :return:                        dict: {"column_number", "column_range", "word"}
        """
        global CONDITION_INDENT_LENGTH

        # Create a list version of the conditions newline string, for convenience.
        condition_as_lines_list = self.condition_as_lines().split('\n')

        # Get index of the errored word in the conditions list.
        errored_word_index = splitline_number - line_number

        # Figure out the distance in chars from start of condition to bad word.
        # (Indent + chars-up-to-error + 1 whitespace + 1 human-readable-indexing)
        char_offset = CONDITION_INDENT_LENGTH + len(" ".join(condition_as_lines_list[:errored_word_index])) + 1 + 1

        if raise_exc:
            raise YaraRuleSyntaxError(message=None,
                                      yara_syntax_error_exc=yara_syntax_error_exc,
                                      rule=self,
                                      line_number=line_number,
                                      column_number=str(char_offset),
                                      column_range=str(char_offset + len(condition_as_lines_list[errored_word_index])),
                                      word=condition_as_lines_list[errored_word_index])
        else:
            return {
                "column_number": str(char_offset),
                "column_range": str(char_offset + len(condition_as_lines_list[errored_word_index])),
                "word": condition_as_lines_list[errored_word_index]
            }

    def compile(self, save_file=True, error_on_warning=False, **kwargs):
        """
        Compile YARA sourcecode into a binary (blob) file.

        :param save_file:           Saves compiled (binary blob) YARA rule to file.
        :param error_on_warning:    If true warnings are treated as errors, raising an exception.
        :param kwargs:              https://yara.readthedocs.io/en/latest/yarapython.html#yara.yara.compile
        :return:
        """
        try:
            self.compiled_blob: yara.Rules = yara.compile(
                source=self.__str__(), error_on_warning=error_on_warning, **kwargs)

            if save_file:
                self.save_compiled()
        except yara.SyntaxError as e:
            # Get line number (split on colon, then split first element
            # on whitespace, then grab the last element).
            line_number = str(e).split(':')[0].split(' ')[-1]

            try:
                # Attempt to determine column no:
                # Attempt a new (failed) compilation with condition as newlined strings,
                # in order to detect which word it fails on.
                self.compiled_blob: yara.Rules = yara.compile(
                    source=self.__str__(condition_as_lines=True), error_on_warning=error_on_warning, **kwargs)

            except yara.SyntaxError as yara_condition_newlined_exc:
                log.info("Caught YARA Syntax Error with newlined condition, "
                         "now determining the column (and range) that failed, "
                         "then raising an improved Syntax Exception...", exc_info=yara_condition_newlined_exc)
                splitline_number = int(str(e).split(':')[0].split(' ')[-1])

                # Determine the column (and range) that failed,
                # using line and splitline to determine the true word offset.
                self.determine_syntax_error_column(e, int(line_number), splitline_number, raise_exc=True)

    def save_compiled(self, filename: str = None, file_ext=COMPILED_FILE_EXTENSION, rules_dir=RULES_DIR):
        """
        Saves compiled (binary blob) YARA rule to file.

        :param filename:
        :param file_ext:
        :param rules_dir:
        :return:
        """
        if filename is None:
            filename = self.name

        # If destination directory does not exist, create it.
        if not os.path.isdir(rules_dir):
            os.mkdir(rules_dir)

        filepath = os.path.join(rules_dir, filename + file_ext)

        # Save compiled YARA rule to binary file using the Yara class' builtin.
        self.compiled_blob.save(filepath)

        # Store filepath in self for later reference.
        self.compiled_path = filepath

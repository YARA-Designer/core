import os
import re
from pathlib import Path
from typing import List, Union

import yara

from handlers.log_handler import create_logger
from handlers.yara_handler.utils import sanitize_identifier
from handlers.yara_handler.yara_meta import YaraMeta
from handlers.yara_handler.yara_string import YaraString
from handlers.yara_handler.keywords import KEYWORDS
from handlers.config_handler import CONFIG

log = create_logger(__name__)

INVALID_IDENTIFIERS = [].extend(KEYWORDS)  # FIXME: Implement validity check against reserved kw.

SOURCE_FILE_EXTENSION = ".yar"
COMPILED_FILE_EXTENSION = ".bin"
CALLBACK_DICTS: list = []


def compiled_rules_to_sources_str_callback(d: dict):
    """
    Callback function for when invoking yara.match method.
    The provided function will be called for every rule, no matter if matching or not.

    Function should expect a single parameter of dictionary type, and should return CALLBACK_CONTINUE
    to proceed to the next rule or CALLBACK_ABORT to stop applying rules to your data.
    :param d: Likely a dict.
    :return:
    """
    global CALLBACK_DICTS

    log.info("CALLBACK: {}".format(d))
    CALLBACK_DICTS.append(d)

    # Continue/Step
    # return CALLBACK_CONTINUE to proceed to the next rule or
    # CALLBACK_ABORT to stop applying rules to your data.
    return yara.CALLBACK_CONTINUE


class YaraRule:
    def __init__(self, name: str, tags: List[str] = None, meta: List[YaraMeta] = None,
                 strings: List[YaraString] = None, condition: str = None, namespace: str = None):
        self.log = create_logger(__name__)

        self.name: str = sanitize_identifier(name)
        if tags is not None:
            self.tags: list = [sanitize_identifier(x) for x in tags]
        self.meta = meta
        self.strings = strings
        self.condition = condition

    @classmethod
    def from_compiled_file(cls, yara_rules: Union[yara.Rules, str], condition: str = None, rules_dir=None):
        """
        Initialize YaraRule from a file

        :param yara_rules: yara.Rules object or path to a compiled yara rules .bin
        :param rules_dir:
        :return:
        """
        if condition is None:
            condition = ""

        # If no custom rules dir is given, use TheOracle's.
        if rules_dir is None:
            rules_dir = os.path.join(CONFIG["theoracle_local_path"], CONFIG["theoracle_repo_rules_dir"])

        if isinstance(yara_rules, yara.Rules):
            # Load rules from yara.Rules object.
            complied_rules: yara.Rules = yara_rules
        elif isinstance(yara_rules, str):
            # Load rules from file.
            complied_rules: yara.Rules = yara.load(
                filepath=os.path.join(rules_dir, yara_rules + COMPILED_FILE_EXTENSION))
        else:
            raise ValueError("yara_rules must be 'yara.Rules' object or 'str' filepath to a compiled yara rules .bin")

        # The match method returns a list of instances of the class Match.
        # Instances of this class have the same attributes as the dictionary passed to the callback function.
        matches: yara.Match = complied_rules.match(filepath=os.path.join(rules_dir, yara_rules + SOURCE_FILE_EXTENSION),  # FIXME: 'yara_rules' will fail for yara.Rules which is not a str!
                                                   callback=compiled_rules_to_sources_str_callback)

        # Copy Matches attributes and misc over to a more malleable dict.
        # match = match_to_dict(matches[0], condition=condition, matches=CALLBACK_DICTS[0]["matches"])

        relevant_match = matches[0]

        # Returned values from yara.Match.match() is a list of Match objects on the form of:
        # Match.meta: dict
        meta = [YaraMeta(identifier, value) for identifier, value in relevant_match.meta.items()]
        # Match.namespace: str
        namespace = relevant_match.namespace
        # Match.rule: str
        name = relevant_match.rule
        # Match.strings: List[Tuples]:
        #   Tuple: (some_int: int, identifier: str, data: binary encoded str)
        strings = \
            [YaraString(identifier, value.decode('utf-8')) for some_int, identifier, value in relevant_match.strings]
        # Match.tags: list
        tags = relevant_match.tags

        if condition is None:
            condition = ""

        global CALLBACK_DICTS
        matches = CALLBACK_DICTS[0]["matches"]

        # Reset the global callback data list.
        CALLBACK_DICTS = []

        log.info("match: {}".format(relevant_match))

        log.debug("compiled_rules_to_source_strings matches: {}".format(matches))  # FIXME: Debug

        return cls(name, tags, meta, strings, condition, namespace=namespace)

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

    def condition_as_lines(self):
        """
        Takes a condition string and returns a string with each condition on a separate line.

        :return:
        """
        return self.condition.replace(' ', '\n')

    def save_compiled(self, rules: yara.Rules, filename: str, file_ext=COMPILED_FILE_EXTENSION, rules_dir=None):
        """
        Saves compiled (binary) YARA rules to file.

        :param rules:
        :param filename:
        :param file_ext:
        :param rules_dir:
        :return:
        """
        # If no custom rules dir is given, use TheOracle's.
        if rules_dir is None:
            rules_dir = os.path.join(CONFIG["theoracle_local_path"], CONFIG["theoracle_repo_rules_dir"])

        # If destination directory does not exist, create it.
        if not os.path.isdir(rules_dir):
            os.mkdir(rules_dir)

        filepath = os.path.join(rules_dir, filename + file_ext)

        if isinstance(rules, yara.Rules):
            # Save compiled YARA rule to binary file using the Yara class' builtin.
            rules.save(filepath)
        else:
            raise ValueError("save_compiled: rules must be 'yara.Rules' object.")

    def save_source(self, rules: str, filename: str, file_ext=SOURCE_FILE_EXTENSION, rules_dir=None):
        """
        Saves source (plaintext) YARA rules to file.

        :param rules:
        :param filename:
        :param file_ext:
        :param rules_dir:
        :return: saved filepath as a Path(PurePath) object.
        """
        # If no custom rules dir is given, use TheOracle's.
        if rules_dir is None:
            rules_dir = os.path.join(CONFIG["theoracle_local_path"], CONFIG["theoracle_repo_rules_dir"])

        # If destination directory does not exist, create it.
        if not os.path.isdir(rules_dir):
            os.mkdir(rules_dir)

        filepath = Path(os.path.join(rules_dir, filename + file_ext))

        if isinstance(rules, str):
            # Save YARA source rule to plaintext file using regular Python standard file I/O.
            with open(filepath, 'w') as f:
                f.write(rules)

            self.log.info("Saved YARA rules to file: {}".format(filepath))
            return filepath
        else:
            raise ValueError("save_source: rules must be 'str'.")

    def __str__(self):
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
        identifier_line = "rule {}".format(self.name)
        meta = ""
        strings = ""
    
        # Sanitize every identifier in the condition string before using it.
        if len(self.condition) > 0:
            sanitized_condition = \
                " ".join([part[0] + sanitize_identifier(part[1:])
                          if part[0] == '$' else part for part in self.condition.split(' ')])
        else:
            sanitized_condition = self.condition
    
        condition = "    condition:" \
                    "\n        {}".format(sanitized_condition)
    
        # Append tags to rule line, if provided.
        if self.tags is not None:
            if len(self.tags) > 0:
                identifier_line = identifier_line + (": " + " ".join(self.tags))
    
        # Add the meta info block, if provided.
        if self.meta is not None:
            if bool(self.meta):
                meta = "    meta:"
                for ym in self.meta:
                    meta = meta + "\n        {}".format(str(ym))
    
        # Add the strings (read: variables) block, id provided.
        if self.strings is not None:
            if bool(self.strings):
                # Header
                strings = "    strings:"
                # Content
                for ys in self.get_referenced_strings():
                    # sanitized_identifier = k[0] + sanitize_identifier(k[1:])
                    strings = strings + "\n        {}".format(str(ys))
    
        # Compile the entire rule block string.
        rule_string =           \
            identifier_line     \
            + '\n' + '{'        \
            + '\n' + meta       \
            + '\n'              \
            + '\n' + strings    \
            + '\n'              \
            + '\n' + condition  \
            + '\n' + '}'
    
        return rule_string

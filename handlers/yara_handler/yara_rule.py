import re
from typing import List

from handlers.yara_handler.utils import sanitize_identifier
from handlers.yara_handler.yara_meta import YaraMeta
from handlers.yara_handler.yara_string import YaraString
from handlers.yara_handler.keywords import KEYWORDS

INVALID_IDENTIFIERS = [].extend(KEYWORDS)  # FIXME: Implement validity check against reserved kw.


class YaraRule:
    def __init__(self, name: str, tags: List[str], meta: List[YaraMeta], strings: List[YaraString], condition: str):
        self.name: str = sanitize_identifier(name)
        if tags is not None:
            self.tags: list = [sanitize_identifier(x) for x in tags]
        self.meta = meta
        self.strings = strings
        self.condition = condition
        
        # self.generate_source_string(name, tags, meta, strings, condition)

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

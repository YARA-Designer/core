from typing import Union

from yara_handler.utils import sanitize_identifier, delimiter_wrap_type

VALID_DATA_TYPES = [str, bool, int]


class YaraMeta:
    """
    Besides the string definition and condition sections, rules can also have a metadata section where
    you can put additional information about your rule. The metadata section is defined with the keyword
    meta and contains identifier/value pairs like in the following example:

    rule MetadataExample
    {
        meta:
            my_identifier_1 = "Some string data"
            my_identifier_2 = 24
            my_identifier_3 = true

        strings:
            $my_text_string = "text here"
            $my_hex_string = { E2 34 A1 C8 23 FB }

        condition:
            $my_text_string or $my_hex_string
    }

    As can be seen in the example, metadata identifiers are always followed by an equals sign and the
    value assigned to them. The assigned values can be strings (valid UTF8 only), integers, or one of
    the boolean values true or false.

    Note that identifier/value pairs defined in the metadata section
    can not be used in the condition section, their only purpose is to store additional information about
    the rule.
    """
    def __init__(self, identifier: str, data: Union[str, bool, int]):
        self.identifier = sanitize_identifier(identifier)

        if type(data) in VALID_DATA_TYPES:
            self.data = data
            self.type = type(data).__name__
        else:
            raise ValueError("Invalid data type {} (Valid types: {})!".format(
                str(type(data)), ", ".join([str(x) for x in VALID_DATA_TYPES])))

    def __str__(self):
        return "{} = {}".format(self.identifier, delimiter_wrap_type(self.data, self.type))

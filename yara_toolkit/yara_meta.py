from typing import Union

from yara_toolkit.utils import sanitize_identifier, delimiter_wrap_type

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
    def __init__(self, identifier: str, value: Union[str, bool, int], value_type: str = None):
        self.identifier = sanitize_identifier(identifier)

        # Set value by specified value_type argument.
        if value_type:
            if value_type == 'str' or value_type == str:
                value = str(value)
            elif value_type == 'bool' or value_type == bool:
                value = value.lower() == "true"
            elif value_type == 'int' or value_type == int:
                value = int(value)
            else:
                raise ValueError("value_type set but '{vt}' is not one of [{vdt}]".format(
                    vt=value_type, vdt=", ".join([x.__name__ for x in VALID_DATA_TYPES])))

        if type(value) in VALID_DATA_TYPES:
            self.value = value
            self.type = type(value).__name__
        else:
            raise ValueError("Invalid value type {} (Valid types: {})!".format(
                str(type(value)), ", ".join([x.__name__ for x in VALID_DATA_TYPES])))

    def __str__(self):
        return "{identifier} = {value}".format(
            identifier=self.identifier,
            value=delimiter_wrap_type(self.value, self.type) if isinstance(self.value, str) else str(self.value))

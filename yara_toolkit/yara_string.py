from typing import Union, List

from handlers.log_handler import create_logger
from yara_toolkit.utils import sanitize_identifier, delimiter_wrap_type

YARA_VAR_SYMBOL = "$"

# Modifier (constant) definitions
NO_CASE = "nocase"
WIDE = "wide"
ASCII = "ascii"
XOR = "xor"
BASE64 = "base64"
BASE64_WIDE = "base64wide"
FULL_WORD = "fullword"
PRIVATE = "private"

VALID_MOD_KEYWORDS = [NO_CASE, WIDE, ASCII, XOR, BASE64, BASE64_WIDE, FULL_WORD, PRIVATE]
MODS_WITH_PAYLOAD = [XOR, BASE64, BASE64_WIDE]

MOD_RESTRICTIONS = {
    NO_CASE: [XOR, BASE64, BASE64_WIDE],
    WIDE: [],
    ASCII: [],
    XOR: [NO_CASE, BASE64, BASE64_WIDE],
    BASE64: [NO_CASE, XOR, FULL_WORD],
    BASE64_WIDE: [NO_CASE, XOR, FULL_WORD],
    FULL_WORD: [BASE64, BASE64_WIDE],
    PRIVATE: []
}

VALID_DATA_TYPES = [str, bool, int]

# YARA String types
TEXT_TYPE = "text"
HEX_TYPE = "hex"
REGEX_TYPE = "regex"


class YaraStringModifierRestrictionError(Exception):
    def __init__(self, message: str, modifiers: list = None):
        super().__init__(message)
        self.message = message
        self.modifiers = modifiers

    def __str__(self):
        return self.message


class YaraStringModifierInvalidKeyword(Exception):
    def __init__(self, message: str, keyword: str = None, data: str = None):
        super().__init__(message)
        self.message = message
        self.keyword = keyword
        self.data = data

    def __str__(self):
        return self.message


class YaraStringModifierInvalidModifierType(Exception):
    def __init__(self, message: str, modifier=None):
        super().__init__(message)
        self.message = message
        self.modifier = modifier

    def __str__(self):
        return self.message


class YaraStringModifier:
    def __init__(self, keyword, data=None):
        """
        YARA String modifier.

        Keyword 	String Types    	Summary                                       Restrictions (Cannot use with...)
        nocase 	    Text, Regex     	Ignore case 	                              xor, base64, or base64wide
        wide 	    Text, Regex     	Emulate UTF16 by interleaving null            None
                                        (0x00) characters
        ascii 	    Text, Regex     	Also match ASCII characters, only             None
                                        required if wide is used
        xor 	    Text                XOR text string with single byte keys         nocase, base64, or base64wide
        base64 	    Text                Convert to 3 base64 encoded strings 	      nocase, xor, or fullword
        base64wide 	Text 	            Convert to 3 base64 encoded strings, then
                                        interleaving null characters like wide 	      nocase, xor, or fullword
        fullword 	Text, Regex 	    Match is not preceded or followed by an
                                        alphanumeric character                        base64 or base64wide
        private 	Hex, Text, Regex 	Match never included in output                None

        :param keyword:
        :param data:
        """
        if keyword not in VALID_MOD_KEYWORDS:
            raise YaraStringModifierInvalidKeyword("Invalid keyword: {}!".format(keyword))

        self.keyword = keyword
        self.data = data

    def wrapped_data(self):
        """
        Wraps certain data based on keyword to adhere to YARA syntax.
        :return:
        """
        if self.keyword == BASE64 or self.keyword == BASE64_WIDE:
            return '"{data}"'.format(data=self.data)
        else:
            return self.data

    def __str__(self):
        """
        :return: type or type(data)
        """
        if self.data is not None:
            return "{mod_keyword}({data})".format(mod_keyword=self.keyword, data=self.wrapped_data())
        else:
            return self.keyword

    def __repr__(self):
        return "YaraStringModifier(type={mod_keyword}, data={data})".format(mod_keyword=self.keyword, data=self.data)

    def as_dict(self):
        return {"keyword": self.keyword, "data": self.data}


def validate_modifiers(modifier_objects: list):
    """
    Validates modifiers by checking that keyword restriction are upheld.

    If not valid, raise a YaraModifierRestrictionError exception.

    :param modifier_objects:
    :return:
    """
    restrictions = []

    # Build a list of restricted keywords to compare against every type.
    for modifier_obj in modifier_objects:
        # Update restrictions list
        restrictions.extend(MOD_RESTRICTIONS[modifier_obj.keyword])

    for modifier_obj in modifier_objects:
        if modifier_obj.keyword in restrictions:
            raise YaraStringModifierRestrictionError(
                "Cannot use YARA String modifier {mod_keyword} with modifiers: {items}".format(
                    mod_keyword=modifier_obj.keyword,
                    items=", ".join(MOD_RESTRICTIONS[modifier_obj.keyword])
                ), modifier_objects)


class YaraString:
    modifiers = []

    def __init__(self, identifier: str = None, value: str = None, value_type: str = None, string_type: str = TEXT_TYPE,
                 modifiers: List[Union[str, dict, YaraStringModifier]] = None, from_dict: dict = None):
        """
        YARA String with optional modifiers.

        :param identifier:      Name/identifier.
        :param value:           String/variable data.
        :param string_type:     Valid types: Hexadecimal, text or regular expression.
        :param modifiers:       List of modifiers.
                                Valid modifiers: nocase, wide, ascii, xor, base64, base64wide, fullword or private.
        :param from_dict:       Define YARA String from a dict instead of individual values.
        """
        self.log = create_logger(__name__)
        self.identifier = None

        if from_dict is not None:
            self.create_from_dict(from_dict)
        else:
            self.determine_identifier(identifier)

            self.value_type = value_type
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

            self.value = value

            if modifiers is not None and len(modifiers) > 0:
                # Ensure modifiers are instances of YaraStringModifier
                yara_string_modifier_objects = []
                for modifier in modifiers:
                    if isinstance(modifier, str):
                        self.log.info("Converting YARA String modifier keyword='{keyword}', type='str' "
                                      "to YaraStringModifier object...".format(keyword=modifier))

                        yara_string_modifier_objects.append(YaraStringModifier(modifier))
                    elif isinstance(modifier, dict):
                        self.log.info("Converting YARA String modifier keyword='{keyword}', data={data}, type='dict' "
                                      "to YaraStringModifier object...".format(
                                        keyword=modifier["keyword"], data=modifier["data"]))

                        yara_string_modifier_objects.append(YaraStringModifier(modifier["keyword"], modifier["data"]))
                    elif isinstance(modifier, YaraStringModifier):
                        self.log.debug("Appending YaraStringModifier object to list: '{obj}'".format(obj=modifier))

                        yara_string_modifier_objects.append(modifier)
                    else:
                        raise YaraStringModifierInvalidModifierType(
                            "Got modifier '{modifier}' of invalid type "
                            "(must be either str, dict or YaraStringModifier)!".format(modifier=modifier),
                            modifier
                        )

                # Throws exception if not valid.
                validate_modifiers(yara_string_modifier_objects)

                # If no exception was thrown store the valid modifiers list.
                self.modifiers = yara_string_modifier_objects

        if string_type is None:
            self.determine_type()
        else:
            self.type = string_type

    def modifiers_str(self):
        return " {}".format(" ".join([str(modifier) for modifier in self.modifiers])) if self.modifiers else ""

    def __str__(self):
        # Convert non-str values to strings before wrapping.
        if self.value_type != 'str' or self.value_type != str:
            value = delimiter_wrap_type(str(self.value), self.type)
        else:
            value = delimiter_wrap_type(self.value, self.type)

        return '{var_sym}{identifier} = {value}{modifiers}'.format(var_sym=YARA_VAR_SYMBOL, identifier=self.identifier,
                                                                   value=value, modifiers=self.modifiers_str())

    def __repr__(self):
        return "YaraString(identifier={identifier}, value={value}, modifiers={modifiers})".format(
            identifier=self.identifier, value=self.value, modifiers=self.modifiers)

    def determine_identifier(self, identifier):
        if identifier[0] == YARA_VAR_SYMBOL:
            # Handle being given identifiers without the YARA_VAR_SYMBOL pre-stripped.
            self.identifier = sanitize_identifier(identifier[1:])
        else:
            self.identifier = sanitize_identifier(identifier)

    def create_from_dict(self, from_dict):
        self.determine_identifier(from_dict.keys()[0])
        self.value = from_dict["observable"]

        if "modifiers" in from_dict:
            # Throws exception if not valid.
            validate_modifiers(from_dict["modifiers"])

            for modifier in from_dict["modifiers"]:
                data = modifier["data"] if "data" in modifier else None
                self.modifiers.append(YaraStringModifier(modifier["keyword"], data))

    def as_dict(self):
        d = {
            "identifier": self.identifier,
            "value": self.value,
            "value_type": self.value_type,
            "string_type": self.type,
            "modifiers": [m.as_dict() for m in self.modifiers],
            "modifier_str": self.modifiers_str(),
            "str": self.__str__()
        }

        return d

    def determine_type(self):
        # FIXME: Implement
        pass

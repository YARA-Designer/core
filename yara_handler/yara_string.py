from yara_handler.utils import sanitize_identifier, delimiter_wrap_type

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

    def __str__(self):
        """
        :return: type or type(data)
        """
        if self.data is not None:
            return "{mod_keyword}({data})".format(mod_keyword=self.keyword, data=self.data)
        else:
            return self.keyword

    def __repr__(self):
        return "YaraStringModifier(type={mod_keyword}, data={data})".format(mod_keyword=self.keyword, data=self.data)


def validate_modifiers(modifiers: list):
    """
    Validates modifiers by checking that keyowrd restriction are upheld.

    If not valid, raise a YaraModifierRestrictionError exception.

    :param modifiers:
    :return:
    """
    restrictions = []

    # Build a list of restricted keywords to compare against every type.
    for modifier in modifiers:
        # Update restrictions list
        restrictions.extend(MOD_RESTRICTIONS[modifier["keyword"]])

    for modifier in modifiers:
        if modifier["keyword"] in restrictions:
            raise YaraStringModifierRestrictionError(
                "Cannot use YARA String modifier {mod_keyword} with modifiers: {items}"
                "".format(mod_keyword=modifier["keyword"], items=", ".join(MOD_RESTRICTIONS[modifier["keyword"]])),
                modifiers)


class YaraString:
    modifiers = []

    def __init__(self, identifier: str = None, value: str = None, string_type: str = TEXT_TYPE,
                 modifiers: list = None, from_dict: dict = None):
        """
        YARA String with optional modifiers.

        :param identifier:      Name/identifier.
        :param value:           String/variable data.
        :param string_type:     Valid types: Hexadecimal, text or regular expression.
        :param modifiers:       List of modifiers.
                                Valid modifiers: nocase, wide, ascii, xor, base64, base64wide, fullword or private.
        :param from_dict:       Define YARA String from a dict instead of individual values.
        """
        self.identifier = None

        if from_dict is not None:
            self.create_from_dict(from_dict)
        else:
            self.determine_identifier(identifier)
            self.value = value

            if modifiers is not None and len(modifiers) > 0:
                # Throws exception if not valid.
                validate_modifiers(modifiers)

                for modifier in modifiers:
                    data = modifier["data"] if "data" in modifier else None
                    self.modifiers.append(YaraStringModifier(modifier["keyword"], data))

        if string_type is None:
            self.determine_type()
        else:
            self.type = string_type

    def __str__(self):
        modifiers = " {}".format(" ".join([str(modifier) for modifier in self.modifiers])) if self.modifiers else ""

        value = delimiter_wrap_type(self.value, self.type)

        return '{var_sym}{identifier} = {value}{modifiers}'.format(var_sym=YARA_VAR_SYMBOL, identifier=self.identifier,
                                                                   value=value, modifiers=modifiers)

    def __repr__(self):
        return "YaraString(identifier={identifier}, value={value}, modifiers={modifiers})".format(
            identifier=self.identifier, value=self.value, modifiers=self.modifiers)

    def determine_identifier(self, identifier):
        if identifier[0] == YARA_VAR_SYMBOL:
            # Handle being given identifiers without the YARA_VAR_SYMBOL pre-stripped.
            self.identifier = sanitize_identifier(identifier[1:])
        else:
            self.identifier = sanitize_identifier(identifier)

    def determine_type(self):
        pass

    def create_from_dict(self, from_dict):
        self.determine_identifier(from_dict.keys()[0])
        self.value = from_dict["observable"]

        if "modifiers" in from_dict:
            # Throws exception if not valid.
            validate_modifiers(from_dict["modifiers"])

            for modifier in from_dict["modifiers"]:
                data = modifier["data"] if "data" in modifier else None
                self.modifiers.append(YaraStringModifier(modifier["keyword"], data))

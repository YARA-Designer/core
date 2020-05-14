# Modifier (constant) definitions
NO_CASE = "nocase"
WIDE = "wide"
ASCII = "ascii"
XOR = "xor"
BASE64 = "base64"
BASE64_WIDE = "base64wide"
FULL_WORD = "fullword"
PRIVATE = "private"

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


class YaraModifierRestrictionError(Exception):
    def __init__(self, message: str, modifiers: list = None):
        super().__init__(message)
        self.message = message
        self.modifiers = modifiers

    def __str__(self):
        return self.message


class YaraStringModifier:
    def __init__(self, modifier_dict: dict):
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

        :param modifier_dict:
        """
        self.type = modifier_dict["type"]

        if "data" in modifier_dict:
            self.data = modifier_dict["data"]
        else:
            self.data = None

    def __str__(self):
        """
        :return: type or type(data)
        """
        if self.data is not None:
            return "{mod_type}({data})".format(mod_type=self.type, data=self.data)
        else:
            return self.type

    def __repr__(self):
        return "YaraStringModifier(type={mod_type}, data={data})".format(mod_type=self.type, data=self.data)


class YaraString:
    # FIXME: Support more than basic strings
    # FIXME: Validate modifiers (syntax)
    modifiers = []

    def __init__(self, identifier=None, value=None, string_type=None, modifiers=None, from_dict=None):
        """
        YARA String with optional modifiers.

        :param identifier:      Name/identifier.
        :param value:           String/variable data.
        :param string_type:     Valid types: Hexadecimal, text or regular expression.
        :param modifiers:       List of modifiers.
                                Valid modifiers: nocase, wide, ascii, xor, base64, base64wide, fullword or private.
        :param from_dict:       Define YARA String from a dict instead of individual values.
        """
        if from_dict is not None:
            self.create_from_dict(from_dict)
        else:
            self.identifier = identifier
            self.value = value

            # Throws exception if not valid.
            self.validate_modifiers(modifiers)

            for modifier in modifiers:
                self.modifiers.append(YaraStringModifier(modifier))

        if string_type is None:
            self.determine_type()
        else:
            self.type = string_type

    def __str__(self):
        modifiers = " {}".format(" ".join(self.modifiers)) if self.modifiers else ""

        return '{identifier} = "{value}"{modifiers}'.format(identifier=self.identifier, value=self.value,
                                                            modifiers=modifiers)

    def __repr__(self):
        return "YaraString(identifier={identifier}, value={value}, modifiers={modifiers})".format(
            identifier=self.identifier, value=self.value, modifiers=self.modifiers)

    def determine_type(self):
        pass

    def validate_modifiers(self, modifiers):
        restrictions = []
        # build a list of restricted keywords to compare against every type.
        for modifier in modifiers:
            # Update restrictions list
            restrictions.extend(MOD_RESTRICTIONS[modifier["type"]])

        for modifier in modifiers:
            if modifier["type"] in restrictions:
                raise YaraModifierRestrictionError("Cannot use YARA String modifier {mod_type} with modifiers: "
                                                   "{items}".format(
                                                    mod_type=modifier["type"],
                                                    items=", ".join(MOD_RESTRICTIONS[modifier["type"]])), modifiers)

    def create_from_dict(self, from_dict):
        self.identifier = from_dict.keys()[0]
        self.value = from_dict["observable"]

        if "modifiers" in from_dict:
            # Throws exception if not valid.
            self.validate_modifiers(from_dict["modifiers"])

            self.modifiers = from_dict["modifiers"]


if __name__ == "__main__":
    ys = YaraString("my_string", "potato", string_type="string", modifiers=[
                    {"type": XOR}, {"type": WIDE}, {"type": NO_CASE}])

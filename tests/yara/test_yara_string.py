import unittest

from handlers.yara.yara_string import YaraString, YaraModifierRestrictionError, \
    NO_CASE, WIDE, ASCII, XOR, BASE64, BASE64_WIDE, FULL_WORD, PRIVATE


def create_obj(obj, *args, **kwargs):
    return obj(*args, **kwargs)


def create_ys(*args, **kwargs):
    return YaraString(*args, **kwargs)


class TestYaraString(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def test_valid_modifier_combo(self):
        try:
            YaraString("my_string", "potato", string_type="string",
                       modifiers=[{"type": ASCII}, {"type": WIDE}, {"type": NO_CASE}])
        except YaraModifierRestrictionError as exc:
            self.fail("A VALID combination of YARA String modifiers raised YaraModifierRestrictionError!")
            pass

    def test_invalid_modifier_combo(self):
        try:
            # self.assertRaises(YaraModifierRestrictionError, create_ys, "my_string", "potato", string_type="string",
            #                    modifiers=[{"type": XOR}, {"type": WIDE}, {"type": NO_CASE}]):
            YaraString("my_string", "potato", string_type="string",
                       modifiers=[{"type": XOR}, {"type": WIDE}, {"type": NO_CASE}])

            self.fail("test_invalid_modifier_combo didn't raise YaraModifierRestrictionError! "
                      "Restrictions are likely broken.")
        except YaraModifierRestrictionError as exc:
            pass


if __name__ == '__main__':
    unittest.main()

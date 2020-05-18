import unittest

from yara_handler.yara_string import YaraString, YaraStringModifierRestrictionError, \
    NO_CASE, WIDE, ASCII, XOR, BASE64, TEXT_TYPE


class TestYaraString(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def test_valid_modifier_combo(self):
        try:
            ys = YaraString("my_string", "potato", string_type=TEXT_TYPE,
                            modifiers=[
                                {
                                    "keyword": ASCII},
                                {
                                    "keyword": WIDE},
                                {
                                    "keyword": BASE64,
                                    "data": "!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu"
                                }])
        except YaraStringModifierRestrictionError:
            self.fail("A VALID combination of YARA String modifiers raised YaraModifierRestrictionError!")
            pass

    def test_invalid_modifier_combo(self):
        try:
            YaraString("my_string", "potato", string_type=TEXT_TYPE,
                       modifiers=[{"keyword": XOR}, {"keyword": WIDE}, {"keyword": NO_CASE}])

            self.fail("An INVALID combination of YARA String modifiers DIDN'T RAISE YaraModifierRestrictionError! "
                      "Restrictions are likely broken.")
        except YaraStringModifierRestrictionError:
            pass

    def test_base64_str_representation(self):
        """
        Test that the str(YaraString) returns the expected data in the expected format.
        :return:
        """
        try:
            correct = '$base64_string = "Test __str()__ call on YaraString w/ Base64 modifier." ' \
                      'base64(!@#$%^&*(){}[].,|ABCDEFGHIJ	LMNOPQRSTUVWXYZabcdefghijklmnopqrstu)'

            ys = YaraString("base64_string", "Test __str()__ call on YaraString w/ Base64 modifier.",
                            string_type=TEXT_TYPE,
                            modifiers=[
                                {
                                    "keyword": BASE64,
                                    "data": "!@#$%^&*(){}[].,|ABCDEFGHIJ\x09LMNOPQRSTUVWXYZabcdefghijklmnopqrstu"
                                }])

            self.assertEqual(str(ys), correct)
        except Exception as exc:
            self.fail("{}".format(exc))


if __name__ == '__main__':
    unittest.main()

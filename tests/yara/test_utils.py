import unittest

from yara_toolkit.utils import delimiter_wrap_type, STRING_TYPE_DELIMITERS, \
    TEXT_TYPE, HEX_TYPE, REGEX_TYPE, INT_TYPE, BOOL_TYPE, \
    TEXT_DELIMITER_START, TEXT_DELIMITER_END, HEX_DELIMITER_START, HEX_DELIMITER_END, \
    REGEX_DELIMITER_START, REGEX_DELIMITER_END


class TestYaraUtilsDelimiterWrapType(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def test_text(self):
        """Regular straight-forward string"""
        try:
            test = "This is a test."
            expected = "{sd}This is a test.{ed}".format(sd=TEXT_DELIMITER_START, ed=TEXT_DELIMITER_END)

            self.assertEqual(delimiter_wrap_type(test, TEXT_TYPE), expected)
        except Exception as exc:
            self.fail("{}".format(exc))

    def test_text_quote(self):
        """String with a single quote in it"""
        try:
            test = '"'
            expected = '{sd}"{ed}'.format(sd=TEXT_DELIMITER_START, ed=TEXT_DELIMITER_END)

            self.assertEqual(delimiter_wrap_type(test, TEXT_TYPE), expected)
        except Exception as exc:
            self.fail("{}".format(exc))

    def test_text_escaped_quote(self):
        """String with a single escaped quote in it"""
        try:
            test = '\\"'
            expected = '{sd}\\"{ed}'.format(sd=TEXT_DELIMITER_START, ed=TEXT_DELIMITER_END)

            self.assertEqual(delimiter_wrap_type(test, TEXT_TYPE), expected)
        except Exception as exc:
            self.fail("{}".format(exc))


if __name__ == '__main__':
    unittest.main()

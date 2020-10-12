import json
import re

# YARA String types
from handlers.log_handler import create_logger

TEXT_TYPE = "text"
HEX_TYPE = "hex"
REGEX_TYPE = "regex"
BOOL_TYPE = "bool"
INT_TYPE = "int"

STRING_TYPES = [TEXT_TYPE, HEX_TYPE, REGEX_TYPE]

# YARA String type delimiters
TEXT_DELIMITER_START = '"'
TEXT_DELIMITER_END = '"'
HEX_DELIMITER_START = '{'
HEX_DELIMITER_END = '}'
REGEX_DELIMITER_START = '/'
REGEX_DELIMITER_END = '/'

STRING_TYPE_DELIMITERS = {
    TEXT_TYPE: {
        "start": TEXT_DELIMITER_START,
        "end": TEXT_DELIMITER_END
    },
    HEX_TYPE: {
        "start": HEX_DELIMITER_START,
        "end": HEX_DELIMITER_END
    },
    REGEX_TYPE: {
        "start": REGEX_DELIMITER_START,
        "end": REGEX_DELIMITER_END
    },
    BOOL_TYPE: {
        "start": "",
        "end": ""
    },
    INT_TYPE: {
        "start": "",
        "end": ""
    }
}

SOURCE_FILE_EXTENSION = ".yar"
COMPILED_FILE_EXTENSION = ".bin"

log = create_logger(__name__)


def get_string_type(string_type) -> str:
    string_types = [TEXT_TYPE, str, "str", "string"]
    hex_types = [HEX_TYPE]
    regex_types = [REGEX_TYPE]
    bool_types = [bool, "bool"]
    int_types = [int, "int"]

    if string_type in string_types:
        return TEXT_TYPE
    elif string_type in hex_types:
        return HEX_TYPE
    elif string_type in regex_types:
        return REGEX_TYPE
    elif string_type in bool_types:
        return BOOL_TYPE
    elif string_type in int_types:
        return INT_TYPE
    else:
        raise ValueError("String has invalid type!")


def is_number(s: str) -> bool:
    """
    Checks is a string value is numeric.

    :param s:
    :return:
    """
    try:
        int(s)
        return True
    except ValueError:
        return False


def sanitize_identifier(identifier: str) -> str:
    """
    Identifiers must follow the same lexical conventions of the C programming language,
    they can contain any alphanumeric character and the underscore character, but the
    first character can not be a digit. Rule identifiers are case sensitive and cannot
    exceed 128 characters.

    :param identifier:
    :return:
    """
    if is_number(identifier[0]):
        # If the first character is a digit, prepend an underscore as
        # the first character can not be a digit.
        identifier = '_' + identifier
    elif identifier[0] == ' ':
        # Strip leading whitespace.
        identifier = identifier[1:]

    # Replace all non-word characters and spaces (everything except numbers and letters) with underscore.
    s = re.sub(r"([^\w\s+]|[^\w\S+])", '_', identifier)

    return s


def delimiter_wrap_type(value: str, string_type: str):
    """
    Returns a value wrapped in its corresponding delimiters (if not already present).

    :param value:
    :param string_type:
    :return:
    """
    try:
        # Support a bit more flexible string types using a lookup to determine the likely type match.
        if string_type not in STRING_TYPES:
            string_type = get_string_type(string_type)

        # Hexadecimals have a spacing between value and delimiter for readability.
        indent = " " if string_type == HEX_TYPE else ""
        retv = ""

        if len(value) > 0:
            # If value contains at least two chars.
            if len(value) > 1:
                # If value did not start or end with its string type delimiters, set flag for adding them.
                # Check for both sides in order to handle edge cases like 'example"', where it looks like
                # it ends delimited, but it doesn't really.
                if value[0] == STRING_TYPE_DELIMITERS[string_type]["start"] and \
                        value[-1] == STRING_TYPE_DELIMITERS[string_type]["end"]:
                    delimited = True
                else:
                    delimited = False

                # If value does not start with its delimiter, add it
                if not delimited:
                    retv += STRING_TYPE_DELIMITERS[string_type]["start"] + indent

                # Add the value string.
                retv += value

                # If value does not end with its delimiter, and  add it
                if not delimited:
                    retv += indent + STRING_TYPE_DELIMITERS[string_type]["end"]
            else:
                # Handle single character cases separately due to edge cases with quotes and esc sequences.
                retv = STRING_TYPE_DELIMITERS[string_type]["start"] \
                       + indent + value + indent \
                       + STRING_TYPE_DELIMITERS[string_type]["end"]
        else:
            # If value has no contents.
            retv = STRING_TYPE_DELIMITERS[string_type]["start"] + indent \
                   + indent + STRING_TYPE_DELIMITERS[string_type]["end"]

        return retv
    except Exception as exc:
        log.exception("Got unexpected exception while trying to delimiter wrap the following:\n{}".format(
            json.dumps({"value": value, "string_type": string_type}, indent=4)), exc_info=exc)
        raise


def determine_value_type(v):
    """
    Takes a value v of unknown type and returns which YARA compatible type it is.

    NB: If all else fails, it will assume it's a string.
    :param v:
    :return:
    """
    if is_number(v):
        return int
    elif isinstance(v, str):
        if v.lower() == "false" or v.lower() == "true":
            return bool
        else:
            return str
    else:
        return str


def is_hex_esc_sequence(s):
    """Takes a string 's' and determines if it is a hex escape sequence."""
    p = re.compile(r"^\\x[0-9][0-9]$")
    m = p.match(s)
    if m:
        return True
    else:
        return False
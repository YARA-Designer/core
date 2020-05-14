import re

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

import yara
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


def sanitize_rulename(rule_name: str) -> str:
    """
    Identifiers must follow the same lexical conventions of the C programming language,
    they can contain any alphanumeric character and the underscore character, but the
    first character can not be a digit. Rule identifiers are case sensitive and cannot
    exceed 128 characters.

    :param rule_name:
    :return:
    """
    # If the first character is a digit, prepend an underscore as
    # the first character can not be a digit.
    if is_number(rule_name[0]):
        rule_name = '_' + rule_name

    # Replace all non-word characters (everything except numbers and letters) with underscore.
    s = re.sub(r"[^\w\s+]", '_', rule_name)

    return s


def extract_yara_strings_dict(yara_artifacts: dict) -> dict:
    """
    Takes a yara artifacts dict (varname: {artifact, id, type} and returns a dict with only varname: {artifact}.
    :param yara_artifacts:
    :return: dict
    """
    return {k: yara_artifacts[k]["artifact"] for k in yara_artifacts}


def get_referenced_strings(cond_stmt: str, yara_strings: dict) -> dict:
    """
    In Yara it is a SyntaxError to have unreferenced strings/vars,
    so these need to be rinsed out before rule compilation.

    :param cond_stmt: str
    :param yara_strings: {}
    :return: Returns dict of strings that are referenced in the conditional statement.
    """
    # Find all occurrences of words starting with $ (i.e. variable names)
    r = re.compile(r'\$[\w]*\b')
    possible_matches = r.findall(cond_stmt)

    # Get rid of mismatches by making a list of items that only matches the actual strings/vars list.
    confirmed_items = {}
    for assumed in possible_matches:
        if assumed in yara_strings.keys():
            confirmed_items[assumed] = yara_strings[assumed]

    return confirmed_items


def generate_source_string(src: dict) -> str:
    """
    Generates a yara rule on string form.

    example format:
        rule RuleIdentifier
        {
            meta:
                description = ""

            strings:
                $artifact1 = ""

            condition:
                $artifact1
        }

    :param src: dict on the form of: {tags: [""], rule: "", meta: {}, strings: {}, condition: ""}
    :return:
    """
    identifier_line = "rule {}".format(src["rule"])
    meta = ""
    strings = ""
    condition = "    condition:" \
                "\n        {}".format(src["condition"])

    # Append tags to rule line, if provided.
    if "tags" in src:
        if len(src["tags"]) > 0:
            identifier_line = identifier_line + (": " + " ".join(src["tags"]))

    # Add the meta info block, if provided.
    if "meta" in src:
        if bool(src["meta"]):
            meta = "    meta:"
            for k, v in src["meta"].items():
                meta = meta + "\n        {} = \"{}\"".format(k, v)

    # Add the strings (read: variables) block, id provided.
    if "strings" in src:
        if bool(src["strings"]):
            strings = "    strings:"
            for k, v in get_referenced_strings(src["condition"], src["strings"]).items():
                strings = strings + "\n        {} = \"{}\"".format(k, v)

    # Compile the entire rule block string.
    rule_string =           \
        identifier_line     \
        + '\n' + '{'        \
        + '\n' + meta       \
        + '\n'              \
        + '\n' + strings    \
        + '\n'              \
        + '\n' + condition  \
        + '\n' + '}'

    return rule_string


def generate_yara_rule_from_dict(yara_dict: dict, error_on_warning=True, **kwargs) -> yara.Rules:
    """
    Generates a yara rule based on a given dict on the form of:
     {rule: "", tags: [""], meta: {}, artifacts: [artifact: "", id: "", type: ""], condition: ""}.

    :param error_on_warning: If true warnings are treated as errors, raising an exception.
    :param yara_dict:
    :return:
    """
    source = generate_source_string({"tags": yara_dict["tags"],
                                     "rule": sanitize_rulename(yara_dict["rule"]),
                                     "meta": {k: yara_dict["meta"][k] for k in yara_dict["meta"]},
                                     "strings": extract_yara_strings_dict(yara_dict["artifacts"]),
                                     "condition": yara_dict["condition"]
                                     })

    print("source: \n{}".format(source))    # FIXME: DEBUG

    try:
        yara_rules = yara.compile(source=source,
                                  error_on_warning=error_on_warning,
                                  **kwargs)

        return yara_rules
    except (yara.SyntaxError, yara.Error) as yara_exc:
        print("generate_yara_rule_from_json Exception: {}".format(yara_exc))
        print("generate_yara_rule_from_json incoming dict: {}".format(yara_dict))
        raise yara_exc
    except Exception as exc:
        print("generate_yara_rule_from_json UNEXPECTED Exception: {}".format(exc))
        print("generate_yara_rule_from_json incoming dict: {}".format(yara_dict))
        raise exc


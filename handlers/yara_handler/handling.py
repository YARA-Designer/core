import os
from pathlib import Path

import yara
import re
from typing import overload, Union, List

from handlers import config_handler
from handlers.log_handler import create_logger
from handlers.yara_handler.yara_meta import YaraMeta
from handlers.yara_handler.yara_rule import YaraRule
from handlers.yara_handler.yara_string import YaraString
from handlers.yara_handler.utils import sanitize_identifier

# Get config

config = config_handler.load_config()

log = create_logger(__name__)

SOURCE_FILE_EXTENSION = ".yar"
COMPILED_FILE_EXTENSION = ".bin"
CALLBACK_DICTS: list = []
CONDITION_INDENT_LENGTH = 8


def determine_yara_source_filename(rule_name: str):
    return "{fname}{ext}".format(fname=sanitize_identifier(rule_name), ext=SOURCE_FILE_EXTENSION)


def extract_yara_strings_dict(yara_observables: dict) -> dict:
    """
    Takes a YARA observables dict (varname: {observable, md5sum, modifiers} and returns a dict with only varname: observable modifiers.

    :param yara_observables:
    :return: dict
    """
    return {k: yara_observables[k]["observable"] for k in yara_observables}


def get_referenced_strings(cond_stmt: str, yara_strings: List[YaraString]) -> List[YaraString]:
    """
    In YARA it is a SyntaxError to have unreferenced strings/vars,
    so these need to be rinsed out before rule compilation.

    :param cond_stmt: str
    :param yara_strings: {}
    :return: Returns dict of strings that are referenced in the conditional statement.
    """
    # Find all occurrences of words starting with $ (i.e. variable names)
    r = re.compile(r'\$[\w]*\b\S+')
    matched_condition_strings = r.findall(cond_stmt)

    # Get rid of mismatches by making a list of items that only matches the actual strings/vars list.
    confirmed_items = []
    for matched_condition_identifier, yara_string in zip(matched_condition_strings, yara_strings):
        if sanitize_identifier(matched_condition_identifier[1:]) == yara_string.identifier:
            confirmed_items.append(yara_string)

    return confirmed_items


def newline_condition(condition: str):
    """
    Takes a condition string and returns a string with each condition on a separate line.

    :param condition:
    :return:
    """
    return condition.replace(' ', '\n')


def save_compiled(rules: yara.Rules, filename: str, file_ext=COMPILED_FILE_EXTENSION, rules_dir=None):
    """
    Saves compiled (binary) YARA rules to file.

    :param rules:
    :param filename:
    :param file_ext:
    :param rules_dir:
    :return:
    """
    # If no custom rules dir is given, use TheOracle's.
    if rules_dir is None:
        rules_dir = os.path.join(config["theoracle_local_path"], config["theoracle_repo_rules_dir"])

    # If destination directory does not exist, create it.
    if not os.path.isdir(rules_dir):
        os.mkdir(rules_dir)

    filepath = os.path.join(rules_dir, filename + file_ext)

    if isinstance(rules, yara.Rules):
        # Save compiled YARA rule to binary file using the Yara class' builtin.
        rules.save(filepath)
    else:
        raise ValueError("save_compiled: rules must be 'yara.Rules' object.")


def save_source(rules: str, filename: str, file_ext=SOURCE_FILE_EXTENSION, rules_dir=None):
    """
    Saves source (plaintext) YARA rules to file.

    :param rules:
    :param filename:
    :param file_ext:
    :param rules_dir:
    :return: saved filepath as a Path(PurePath) object.
    """
    # If no custom rules dir is given, use TheOracle's.
    if rules_dir is None:
        rules_dir = os.path.join(config["theoracle_local_path"], config["theoracle_repo_rules_dir"])

    # If destination directory does not exist, create it.
    if not os.path.isdir(rules_dir):
        os.mkdir(rules_dir)

    filepath = Path(os.path.join(rules_dir, filename + file_ext))

    if isinstance(rules, str):
        # Save YARA source rule to plaintext file using regular Python standard file I/O.
        with open(filepath, 'w') as f:
            f.write(rules)

        log.info("Saved YARA rules to file: {}".format(filepath))
        return filepath
    else:
        raise ValueError("save_source: rules must be 'str'.")


def load_file(filename: str, rules_dir=None):
    # If no custom rules dir is given, use TheOracle's.
    if rules_dir is None:
        rules_dir = os.path.join(config["theoracle_local_path"], config["theoracle_repo_rules_dir"])

    rules = None

    # If destination directory does not exist, return.
    if os.path.isdir(rules_dir):
        # Load rules from file.
        rules = yara.load(filepath=os.path.join(rules_dir, filename))

    return rules


def match_to_dict(match: yara.Match, condition: str = None, matches: bool = None) -> dict:
    """
    Copies yara.Match attributes and misc over to a more malleable dict.

    :param match:
    :param condition:
    :param matches:
    :return:
    """
    strings_tuples: List[tuple] = match.strings
    strings_dict: dict = {}

    for some_int, var, value in strings_tuples:
        strings_dict[var] = value

    return {"matches": matches, "rule": match.rule, "namespace": match.namespace, "tags": match.tags,
            "meta": match.meta, "strings": strings_dict, "condition": condition}


def compiled_rules_to_sources_str_callback(d: dict):
    """
    Callback function for when invoking yara.match method.
    The provided function will be called for every rule, no matter if matching or not.

    Function should expect a single parameter of dictionary type, and should return CALLBACK_CONTINUE
    to proceed to the next rule or CALLBACK_ABORT to stop applying rules to your data.
    :param d: Likely a dict.
    :return:
    """
    global CALLBACK_DICTS

    log.info("CALLBACK: {}".format(d))
    CALLBACK_DICTS.append(d)

    # Continue/Step
    # return CALLBACK_CONTINUE to proceed to the next rule or
    # CALLBACK_ABORT to stop applying rules to your data.
    return yara.CALLBACK_CONTINUE


@overload
def compiled_rules_to_source_string(rules: yara.Rules, condition: str) -> str:
    pass


@overload
def compiled_rules_to_source_string(rules: str, condition: str) -> str:
    pass


def compiled_rules_to_source_string(rules: Union[yara.Rules, str], condition: str):
    """
    Converts a compiled yara rule (binary) to a list of source strings (.yar format).

    :param rules:       yara.Rules object or path to a compiled yara rules .bin
    :param condition:   Required parameter as the condition seemingly is not part of the compiled YARA rule.
    :return:            List of source strings
    """
    global CALLBACK_DICTS

    # Use TheOracle's rules dir.
    rules_dir = os.path.join(config["theoracle_local_path"], config["theoracle_repo_rules_dir"])

    if isinstance(rules, yara.Rules):
        complied_rules = rules
    elif isinstance(rules, str):
        complied_rules = load_file(filename=rules + COMPILED_FILE_EXTENSION)
    else:
        raise ValueError("rules must be 'yara.Rules' object or 'str' filepath to a compiled yara rules .bin")

    # The match method returns a list of instances of the class Match.
    # Instances of this class have the same attributes as the dictionary passed to the callback function.
    matches: yara.Match = complied_rules.match(filepath=os.path.join(rules_dir, rules + SOURCE_FILE_EXTENSION),
                                               callback=compiled_rules_to_sources_str_callback)

    # Copy Matches attributes and misc over to a more malleable dict.
    match = match_to_dict(matches[0], condition=condition, matches=CALLBACK_DICTS[0]["matches"])

    # Reset the global callback data list.
    CALLBACK_DICTS = []

    log.info("match: {}".format(match))

    log.debug("compiled_rules_to_source_strings matches: {}".format(match["matches"]))  # FIXME: Debug

    # return generate_source_string(match)


def determine_syntax_error_column(condition_as_lines_str: str, line_number: int, splitline_number: int) -> dict:
    """
    Determines the column (and range) that compilation failed on,
    using whitespace line number and newline line numbers to determine the character offset to the word.

    :param condition_as_lines_str:  Condition string where whitespace is replaced by \n,
    :param line_number:             Line number that failed in the whitespace string.
    :param splitline_number:        Line number that failed in the newline string.
    :return:                        dict: {"column_number", "column_range", "word"}
    """
    global CONDITION_INDENT_LENGTH

    # Create a list version of the conditions newline string, for convenience.
    condition_as_lines_list = condition_as_lines_str.split('\n')

    # Get index of the errored word in the conditions list.
    errored_word_index = splitline_number - line_number

    # Figure out the distance in chars from start of condition to bad word.
    # (Indent + chars-up-to-error + 1 whitespace + 1 human-readable-indexing)
    char_offset = CONDITION_INDENT_LENGTH + len(" ".join(condition_as_lines_list[:errored_word_index])) + 1 + 1

    return {
        "column_number": str(char_offset),
        "column_range": str(char_offset + len(condition_as_lines_list[errored_word_index])),
        "word": condition_as_lines_list[errored_word_index]
        }


def compile_from_source(yara_sources_dict: dict, error_on_warning=True, keep_compiled=False, **kwargs) -> dict:
    """
    Generates a YARA rule based on a given dict on the form of:
     {rule: "", tags: [""], meta: {}, observables: [observable: "", id: "", type: ""], condition: ""}.

    :param keep_compiled: Whether or not to keep compiled binary files.
    :param error_on_warning: If true warnings are treated as errors, raising an exception.
    :param yara_sources_dict:
    :return:
    """
    retv = {
        "source": None,
        "success": False,
        "compilable": False,
        "error": {
            "type": None,
            "message": "",
            "line_number": None,
            "column_number": None,
            "word": None
        },
    }

    # Sanitize inputs (replace spaces with underscore, etc.)
    sanitized_rule_name: str = sanitize_identifier(yara_sources_dict["rule"])
    sanitized_tags: list = [sanitize_identifier(x) for x in yara_sources_dict["tags"]]
    log.info("sanitized_tags: {}".format(sanitized_tags))

    rule = YaraRule(
        yara_sources_dict["rule"], yara_sources_dict["tags"],
        [YaraMeta(identifier, value) for identifier, value in yara_sources_dict["meta"].items()],
        [YaraString(identifier, value["observable"]) for identifier, value in yara_sources_dict["observables"].items()],
        yara_sources_dict["condition"])

    retv["source"] = str(rule)

    log.debug("source: \n{}".format(retv["source"]))    # FIXME: DEBUG

    # Save source rule to text file.
    try:
        retv["generated_yara_source_file"] = str(save_source(rules=retv["source"],
                                                             filename=sanitized_rule_name).resolve(strict=True))
    except Exception as exc:
        log.exception("Handing exception thrown by save_source(rules={rules}, filename={fname})".format(
            rules=retv["source"], fname=sanitized_rule_name), exc_info=exc)
        retv["generated_yara_source_file"] = None
        retv["success"] = False
        retv["compilable"] = False
        retv["error"] = {"type": "Exception", "message": str(exc)}

        return retv

    try:
        compiled_yara_rules: yara.Rules = yara.compile(source=retv["source"],
                                                       error_on_warning=error_on_warning,
                                                       **kwargs)
        retv["compilable"] = True

        # Save compiled rule to binary file.
        save_compiled(rules=compiled_yara_rules, filename=sanitized_rule_name)

        compiled_rules_to_source_string(sanitized_rule_name, condition=yara_sources_dict["condition"])

        if not keep_compiled:
            path = os.path.join(config["theoracle_local_path"], config["theoracle_repo_rules_dir"],
                                sanitized_rule_name + COMPILED_FILE_EXTENSION)
            log.info("Removing compiled YARA binary: {}".format(path))
            os.remove(path)

        retv["success"] = True

    except yara.SyntaxError as e:
        retv["success"] = False
        retv["error"] = {"type": "syntax", "message": str(e)}
        # Get line number (split on colon, then split first element on whitespace then grab the last element.
        retv["error"]["line_number"] = str(e).split(':')[0].split(' ')[-1]

        # Attempt to determine column no:
        condition_as_lines_str = newline_condition(yara_sources_dict["condition"])
        try:
            rule_ = YaraRule(
                yara_sources_dict["rule"], yara_sources_dict["tags"],
                [YaraMeta(identifier, value) for identifier, value in yara_sources_dict["meta"].items()],
                [YaraString(identifier, value["observable"]) for identifier, value in
                 yara_sources_dict["observables"].items()],
                yara_sources_dict["condition"])

            source_ = str(rule_)

            # Attempt a new (failed) compile with condition as newlined strings,
            # in order to detect which word it fails on.
            compiled_yara_rules: yara.Rules = yara.compile(source=source_,
                                                           error_on_warning=error_on_warning,
                                                           **kwargs)
        except yara.SyntaxError as e:
            splitline_number = int(str(e).split(':')[0].split(' ')[-1])

            # Determine the column (and range) that failed, using line and splitline to determine the true word offset.
            res = determine_syntax_error_column(condition_as_lines_str,
                                                int(retv["error"]["line_number"]),
                                                splitline_number)

            retv["error"]["column_number"] = res["column_number"]
            retv["error"]["column_range"] = res["column_range"]
            retv["error"]["word"] = res["word"]

            retv["error"]["message"] += "\n -- column number: {} (columns: {}-{}, word: '{}')".format(
                retv["error"]["column_number"],
                retv["error"]["column_number"],
                retv["error"]["column_range"],
                retv["error"]["word"])
            pass

        pass
    except yara.Error as e:
        retv["success"] = False
        retv["error"] = {"type": "error", "message": str(e)}
        log.exception("yara Error Exception!", exc_info=e)
        pass
    except Exception as e:
        retv["success"] = False
        retv["error"] = {"type": "exception", "message": str(e)}
        log.exception("Unexpected Exception!", exc_info=e)
        pass

    return retv


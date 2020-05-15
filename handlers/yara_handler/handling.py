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

    rule = YaraRule(
        name=yara_sources_dict["rule"],
        tags=yara_sources_dict["tags"],
        meta=[YaraMeta(identifier, value) for identifier, value in yara_sources_dict["meta"].items()],
        strings=
        [YaraString(identifier, value["observable"]) for identifier, value in yara_sources_dict["observables"].items()],
        condition=yara_sources_dict["condition"])

    retv["source"] = str(rule)

    log.debug("source: \n{}".format(retv["source"]))    # FIXME: DEBUG

    # Save source rule to text file.
    try:
        # rule.save_source(rules=retv["source"], filename=rule.name).resolve(strict=True)

        retv["generated_yara_source_file"] = str(rule.save_source(rules=retv["source"],
                                                                  filename=rule.name).resolve(strict=True))
    except Exception as exc:
        log.exception("Handing exception thrown by save_source(rules={rules}, filename={fname})".format(
            rules=retv["source"], fname=rule.name), exc_info=exc)
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
        rule.save_compiled(rules=compiled_yara_rules, filename=rule.name)

        # compiled_rules_to_source_string(rule.name, condition=yara_sources_dict["condition"])
        compiled_rule = YaraRule.from_compiled_file(rule.name)

        if not keep_compiled:
            path = os.path.join(config["theoracle_local_path"], config["theoracle_repo_rules_dir"],
                                rule.name + COMPILED_FILE_EXTENSION)
            log.info("Removing compiled YARA binary: {}".format(path))
            os.remove(path)

        retv["success"] = True

    except yara.SyntaxError as e:
        retv["success"] = False
        retv["error"] = {"type": "syntax", "message": str(e)}
        # Get line number (split on colon, then split first element on whitespace then grab the last element.
        retv["error"]["line_number"] = str(e).split(':')[0].split(' ')[-1]

        # Attempt to determine column no:
        condition_as_lines_str = rule.condition_as_lines()
        try:
            # Attempt a new (failed) compile with condition as newlined strings,
            # in order to detect which word it fails on.
            yara.compile(source=retv["source"], error_on_warning=error_on_warning, **kwargs)
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


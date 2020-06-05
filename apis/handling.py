import datetime
import json
import os

import handlers.git_handler as git
from flask import request, jsonify, make_response
from thehive4py.api import TheHiveApi
from werkzeug.datastructures import ImmutableMultiDict

from database.operations import add_row, has_row
from handlers import config_handler

from database.operations import update_rule, get_rule, get_rules
from handlers.config_handler import CONFIG
from handlers.log_handler import create_logger
from yara_toolkit.yara_rule import YaraRule, YaraRuleSyntaxError, YaraWarningError, YaraTimeoutError

log = create_logger(__name__)


def get_json_returnable_observables_list(observables: json):
    dict_list = {}
    for observable in observables:
        log.info("observable: {}".format(observable))
        dict_list[observable['id']] = observable

    return dict_list


def imd_to_dict(imd: ImmutableMultiDict):
    dct = {}
    for key, value in imd.items():
        log.debug("{}: {}".format(key, value))
        dct[key] = value

    return dct


def add_yara_filename(rule):
    if rule["yara_file"] is not None:
        rule["yara_filename"] = rule["yara_file"].split(os.path.sep)[-1]

    return rule


def add_yara_filenames(rules: list) -> list:
    modified_rules = []

    for rule in rules:
        modified_rules.append(add_yara_filename(rule))

    return modified_rules


def create_yara_file(yara_sources_dict: dict, keep_compiled=False, verify_compiled=True) -> dict:
    """
    Generates a YARA Rule based on a given dict and stores
    the sourcecode (and optionally compiled binary) as a file.

    :param verify_compiled: Verify that the compiled YARA rule is parsable.

                            Saves compiled binary to file, then parses it
                            by loading it into a new YaraRule.
    :param keep_compiled: Whether or not to keep compiled binary files.
    :param yara_sources_dict: dict on the form of:
        {
            name: str,
            tags: List[str],
            meta: {identifier: value},
            strings: [{identifier, value, type, modifiers}]
            condition: str
        }.
    :return retv:
    """
    retv = {
        "source": None,
        "success": False,
        "has_warning": False,
        "compilable": False,
        "error": {
            "type": None,
            "message": "",
            "line_number": None,
            "column_number": None,
            "word": None
        },
        "warning": {    # Singular, due to yara raising an exception on the first one, unable to get any further ones.
            "type": None,
            "message": "",
            "line_number": None,
            "column_number": None,
            "word": None
        }
    }

    # Create YaraRule from given dict.
    rule = YaraRule.from_dict(yara_sources_dict)
    retv["source"] = rule.__str__()
    log.debug("source: \n{}".format(retv["source"]))

    # General catch-all try-block for any unforseen exceptions, in order to not kill backend on-exception.
    try:
        # Save rule source code to text file and store the returned filepath for use in frontend.
        retv["generated_yara_source_file"] = rule.save_source()

        # Compilation try-block to specifically catch syntax errors.
        try:
            # Compile and save file to verify the validity of the YARA code.
            try:
                # Run first with error_on_warning so that warning are raised as exceptions and can be stored.
                rule.compile(save_file=verify_compiled, error_on_warning=True)
                retv["compilable"] = True
            except YaraWarningError as yarawe_exc:
                log.warning("YARA Rule Compilation warning", exc_info=yarawe_exc)

                retv["has_warning"] = True
                retv["warning"]["type"] = "compilation"
                retv["warning"]["message"] = str(yarawe_exc)

                # Add line number info if it is in the string.
                if str(yarawe_exc).startswith("line"):
                    retv["warning"]["line_number"] = str(yarawe_exc).split(':')[0][len('line '):]

                    # If line number is in the string then the offending string should also be in there.
                    try:
                        retv["warning"]["word"] = str(yarawe_exc).split(':')[1].split(' ')[1]
                    except Exception as exc:
                        # If it fails, it shouldn't be critical, we just end up with less available info.
                        log.warning("Failed to determine word from YaraWarningError exception", exc_info=exc)
                        pass
                pass
            finally:
                # Run without warnings raising exceptions, in order to check if it is at all compilable.
                rule.compile(save_file=verify_compiled, error_on_warning=False)
                retv["compilable"] = True
        except YaraRuleSyntaxError as syn_exc:
            # Handle syntax error if raised by YaraRule.
            retv["success"] = False

            retv["error"] = {
                "type": "Syntax",
                "message": str(syn_exc),
                "line_number": syn_exc.line_number,
                "column_number": syn_exc.column_number,
                "column_range": syn_exc.column_range,
                "word": syn_exc.word
            }

            log.exception("YaraRuleSyntaxError Exception!", exc_info=syn_exc)

            return retv

        # Verify that the compiled YARA rule is parsable.
        if verify_compiled is True:
            rule_from_compiled: YaraRule = YaraRule.from_compiled_file(rule.name, condition=rule.condition)

            if keep_compiled is False:
                log.info("Removing compiled YARA binary: {}".format(rule_from_compiled.compiled_path))
                os.remove(rule_from_compiled.compiled_path)

    except Exception as e:
        retv["success"] = False
        retv["error"] = {"type": "exception", "message": str(e)}
        log.exception("Unexpected Exception!", exc_info=e)

        return retv

    retv["success"] = True

    return retv


def reset_invalid_yara_rule(repo, filepath):
    """
    Reset invalid changed file to avoid git-within-git changelist issues.

    Performs a `git checkout` on the generated file using GitPython.

    :param repo:
    :param filepath: Full/absolute path to the file you want reset/checked out.
    :return:
    """
    log.info("Checking out (resetting) file that failed validation: {}".format(filepath))

    # Checkout with force due to local modifications (else CheckoutError Exception is raised).
    repo.index.checkout([filepath], force=True)


def generate_yara_rule(j: json):
    log.debug("Received YARA Rule Dict: {}".format(j))
    retv = {"in": j}

    the_oracle_repo = git.clone_if_not_exist(url=CONFIG["theoracle_repo"], path=CONFIG["theoracle_local_path"])
    # Processing status, return values and so forth.
    try:

        retv["out"] = create_yara_file(j)
        log.debug("Returned YARA Rule Dict: {}".format(retv))

        if not retv["out"]["success"]:
            if not retv["out"]["compilable"]:
                log.info("Resetting invalid changed file to avoid git-within-git changelist issues.")
                reset_invalid_yara_rule(the_oracle_repo, retv["out"]["generated_yara_source_file"])

    except Exception as exc:
        try:
            if "name" in j:
                log.info("Resetting invalid changed file to avoid git-within-git changelist issues.")
                reset_invalid_yara_rule(the_oracle_repo, retv["out"]["generated_yara_source_file"])
            else:
                log.error("Received JSON is missing VITAL key 'name', unable to git unstage!\nj = {}".format(
                    json.dumps(j, indent=4)))

            retv["out"] = {
                "success": False,
                "error": {
                    "message": str(exc),
                    "type": "exception",
                    "level": "error"
                }
            }
            log.error("Exception occurred during YARA compile from source: {}".format(retv), exc_info=exc)
        except Exception as exc2:
            retv["out"] = {
                "success": False,
                "error": {
                    "message": str(exc2),
                    "type": "exception",
                    "level": "error"
                }
            }
            log.error("Exception occurred git checkout: {}".format(retv), exc_info=exc2)

    return retv




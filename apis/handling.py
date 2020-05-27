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
from yara_toolkit.yara_rule import YaraRule, YaraRuleSyntaxError

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


def add_yara_filename(rules: list) -> list:
    modified_rules = []
    for rule in rules:
        if rule["yara_file"] is not None:
            rule["yara_filename"] = rule["yara_file"].split(os.path.sep)[-1]
        modified_rules.append(rule)

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
            rule: str,
            tags: List[str],
            meta: {identifier: value},
            observables: {identifier: value},
            condition: str
        }.
    :return retv:
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
            rule.compile(save_file=verify_compiled)
            retv["compilable"] = True
        except YaraRuleSyntaxError as syn_exc:
            # Handle syntax error if raised by YaraRule.
            retv["success"] = False
            retv["error"] = {"type": "syntax_error", "message": str(syn_exc)}
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
                # Reset invalid changed file to avoid git-within-git changelist issues,
                reset_invalid_yara_rule(the_oracle_repo, retv["generated_yara_source_file"])

    except Exception as exc:
        try:
            if "rule" in j:
                # Reset invalid changed file to avoid git-within-git changelist issues,
                reset_invalid_yara_rule(the_oracle_repo, retv["generated_yara_source_file"])
            else:
                log.error("Received JSON is missing VITAL key 'rule'!\nj = {}".format(json.dumps(j, indent=4)))

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




import datetime
import json
import os

import handlers.git_handler as git
from flask import request, jsonify, make_response

from database.operations import update_rule, get_rule, get_rules
import yara_handler.utils as yara_utils
from handlers.config_handler import load_config
from handlers.log_handler import create_logger
from yara_handler.yara_rule import YaraRule, YaraRuleSyntaxError

the_oracle_repo: git.Repo

log = create_logger(__name__)


def add_yara_filename(rules: list) -> list:
    modified_rules = []
    for rule in rules:
        if rule["yara_file"] is not None:
            rule["yara_filename"] = rule["yara_file"].split(os.path.sep)[-1]
        modified_rules.append(rule)

    return modified_rules


def post_get_rule_request():
    rule = get_rule(request.json["id"])
    rule_modified = add_yara_filename([rule])[0]

    retv = jsonify(rule_modified)
    log.info("GET rule return JSON: {}".format(json.dumps(retv.json, indent=4)))

    return retv


def get_rules_request():
    rules = get_rules()
    rules_modified = add_yara_filename(rules)

    retv = jsonify(rules_modified)
    log.info("GET rules return JSON: {}".format(json.dumps(retv.json, indent=4)))

    return retv


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


def reset_invalid_yara_rule(rule_name):
    """
    Reset invalid changed file to avoid git-within-git changelist issues.

    Performs a `git checkout` on the generated file using GitPython.

    :param rule_name:
    :return:
    """
    config = load_config()
    invalid_file = yara_utils.determine_yara_source_filename(rule_name)
    path = os.path.join(config["theoracle_repo_rules_dir"], invalid_file)

    log.info("Invalid file: {}".format(invalid_file))
    log.info("Checking out (resetting) file that failed validation: {}".format(invalid_file))
    # Checkout with force due to local modifications (else CheckoutError Exception is raised).
    the_oracle_repo.index.checkout([path], force=True)


def generate_yara_rule(j: json):
    log.debug("Received YARA Rule Dict: {}".format(j))
    retv = {"in": j}

    # Processing status, return values and so forth.
    try:
        retv["out"] = create_yara_file(j)
        log.debug("Returned YARA Rule Dict: {}".format(retv))

        if not retv["out"]["success"]:
            if not retv["out"]["compilable"]:
                # Reset invalid changed file to avoid git-within-git changelist issues,
                reset_invalid_yara_rule(j["rule"])

    except Exception as exc:
        try:
            if "rule" in j:
                # Reset invalid changed file to avoid git-within-git changelist issues,
                reset_invalid_yara_rule(j["rule"])
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


def post_rule_json():
    """
    Receives a JSON of the operators which needs to be matched against the original list of observables.
    :return: JSON on the form of:
    {
        "observables:
        [
            {
            "observableN":
            {
                "observable",
                "id",
                "type"
            }
            }
        ]",
        condition: ""
    }
    """
    log.debug("Received HTTP POST Request (application/json): {}".format(json.dumps(request.json, indent=4)))

    return make_response(jsonify(generate_yara_rule(request.json)), 200)


def post_commit_json():
    """
    Receives a JSON of the operators which needs to be matched against the original list of observables.
    :return: JSON on the form of:
    {
        "observables:
        [
            {
            "observableN":
            {
                "observable",
                "id",
                "type"
            }
            }
        ]",
        condition: ""
    }
    """
    log.debug("Received HTTP POST Request (application/json): {}".format(json.dumps(request.json, indent=4)))

    result = {
        "in": request.json,
        "out": {
            "success": False,
            "error": {
                "message": "post_commit_json body (try) never ran",
                "type": "Implementation"
                }
            }
        }

    file_to_add = request.json["filepath"]
    try:
        config = load_config()

        # 1. Git Pull (Make sure we're in sync with remote/origin).
        log.info("Pulling data from remote '{}'...".format(the_oracle_repo.remotes.origin))
        the_oracle_repo.remotes.origin.pull()

        # 2. Git Add the YARA rule file.
        log.info("Git Add file to repo '{repo}': {fn}".format(repo=the_oracle_repo.git_dir, fn=file_to_add))
        the_oracle_repo.index.add(file_to_add)

        # 3. Git Commit
        # Only commit if working tree differs (i.e. there is an actual change).
        tree_differs = False if the_oracle_repo.index.diff('HEAD') == [] else True
        log.debug("Tree differs: {}".format(tree_differs))

        if tree_differs:
            commit_message = config["git_commit_msg_fmt"].format(rulename=request.json["rulename"])
            git_author = git.Actor(config["git_username"], config["git_email"])
            git_committer = git_author  # git.gitpy.Actor(config["git_username"], config["git_email"]

            log.info("Git Commit.")
            log.debug("message={message}, author={author}, committer={committer}".format(
                message=commit_message, author=git_author, committer=git_committer))

            the_oracle_repo.index.commit(message=commit_message, author=git_author, committer=git_committer)

            last_commit = the_oracle_repo.head.commit

            # 4. Git Push
            log.info("Git push commit '{msg}' ({hexsha}) to {origin}".format(msg=last_commit.message,
                                                                             hexsha=last_commit.hexsha,
                                                                             origin=the_oracle_repo.remotes.origin))
            the_oracle_repo.remotes.origin.push()

            result["out"] = {
                "success": True,
                "commit": {
                    "message": last_commit.message,
                    "hexsha": last_commit.hexsha,
                    "author_username": last_commit.author.name,
                    "author_email": last_commit.author.email,
                    "committer_username": last_commit.committer.name,
                    "committer_email": last_commit.committer.email,
                    "committed_date_epoch": last_commit.committed_date,
                    # Include some formatted dates to avoid dealing with it in Frontend/JavaScript.
                    "committed_date_iso": datetime.datetime.isoformat(last_commit.committed_datetime),
                    "committed_date_custom": datetime.datetime.strftime(last_commit.committed_datetime,
                                                                        config["git_datetime_custom_fmt"]),
                    "diff": the_oracle_repo.git.diff('HEAD~1')
                }
            }

            log.info("update_rule(case_id={cid}, "
                     "yara_file={yara_filepath})".format(cid=request.json["case_id"],
                                                         yara_filepath=request.json["filepath"]))
            update_rule(request.json["case_id"], yara_file=request.json["filepath"], pending=False)
        else:
            log.warning("Git Commit ignored, file added to repo does not differ from working tree: '{fn}".format(fn=file_to_add))
            result["out"] = {
                "success": False,
                "commit": None,
                "error": {
                    "message": "Nothing to commit, working tree clean (file added didn't differ).",
                    "type": "Git diff",
                    "level": "warning"
                }
            }
    except Exception as exc:
        log.exception("Unexpected exception!", exc_info=exc)
        result["out"] = {
            "success": False,
            "error": {
                "message": str(exc),
                "type": "Exception"
            }
        }

    # Make response.
    log.debug("Return dict: {}".format(result))
    return make_response(jsonify(result), 200)



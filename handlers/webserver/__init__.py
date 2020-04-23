import datetime
import json
import os

import handlers.git_handler as git
from flask import render_template, request, jsonify, make_response
from sqlalchemy.exc import SQLAlchemyError

from database.models import Rule
from database.operations import db_session, update_rule
import handlers.yara
from handlers.config_handler import load_config
from handlers.log_handler import create_logger

tab_character = "&nbsp;"
tab = tab_character*4
routes = {}
the_oracle_repo: git.Repo

log = create_logger(__name__)


def get_rule(case_id: str) -> dict:
    session = db_session()

    try:
        # Get the first item in the list of queries
        rule_dict: dict = session.query(Rule).filter(Rule.case_id == case_id)[0].as_dict()

        # Commit transaction (NB: makes detached instances expire)
        session.commit()
    except SQLAlchemyError:
        raise
    finally:
        session.close()

    return rule_dict


def get_rules():
    rules = []
    session = db_session()

    try:
        for rule in session.query(Rule).all():
            rules.append(rule.as_dict())
            log.debug("get_rules rule: {}".format(json.dumps(dict_to_json(rule.as_dict()), indent=4)))

        # Commit transaction (NB: makes detached instances expire)
        session.commit()
    except SQLAlchemyError:
        raise
    finally:
        session.close()

    return rules


def get_rules_request():
    return jsonify(get_rules())


def dict_to_json(d: dict):
    # Get rule dict
    rule_dict = d

    # Serialize all items as str
    rule_json_str = json.dumps(rule_dict, default=str)

    # Convert it into a JSON object (avoids TypeErrors with things like datetime)
    return json.loads(rule_json_str)


def list_rules():
    # Get pending rules from database.
    rule_dicts = get_rules()

    rules_json = []
    for rule_dict in rule_dicts:
        if rule_dict["yara_file"]:
            # Strip path down to only filename itself.
            rule_dict["yara_file"] = rule_dict["yara_file"].split(os.path.sep)[-1]
        rules_json.append(dict_to_json(rule_dict))

    return render_template('list_rules.html', rules=rules_json)


def new_rule_raw():
    if 'id' not in request.args:
        return "Please specify a case ID!"

    return render_template('yara_rule_raw.html',
                           case=dict_to_json(get_rule(request.args.get('id'))))


def new_rule_designer():
    if 'id' not in request.args:
        return "Please specify a case ID!"

    case = dict_to_json(get_rule(request.args.get('id')))
    theme = request.args.get('theme')
    log.info("Rendering YARA Rule Designer template for case '{cname}' (ID: {cid})".format(
        cname=case["data"]["title"], cid=request.args.get('id')))
    log.debug("TheHive Case: {}".format(json.dumps(case, indent=4)))

    return render_template('yara_rule_designer.html',
                           case=case,
                           artifacts=case['data']['observables'],
                           theme=theme)


def generate_yara_rule(j: json):
    log.debug("Received YARA Rule Dict: {}".format(j))

    # Processing status, return values and so forth.
    retv = {"in": j, "out": handlers.yara.compile_from_source(j)}
    log.debug("Returned YARA Rule Dict: {}".format(retv))

    return retv


def post_rule_raw_imd():  # FIXME: Should probably be deprecated along with raw CLI (HTML page).
    """
    Receives an ImmutableMultiDict of the operators which needs to be matched against the original list of artifacts.
    :return: JSON on the form of:
    {
        "artifacts:
        [
            {
            "artifactN":
            {
                "artifact",
                "id",
                "type"
            }
            }
        ]",
        condition: ""
    }
    """
    log.debug("keys: " + str([key for key in request.form.keys()]))
    log.debug("request.form: {}".format(request.form))

    artifacts = {}
    for artifact, varname, artifact_type, artifact_id in zip(request.form.getlist('artifact'),
                                                             request.form.getlist('artifact_var'),
                                                             request.form.getlist('artifact_type'),
                                                             request.form.getlist('artifact_id')):
        artifacts[varname] = {"artifact": artifact, "type": artifact_type, "id": artifact_id}

    yara_condition_string = request.form['rawUrlSubmit']
    yara_dict = {"rule": (request.form['rule'] if 'rule' in request.form else 'UNNAMED_RULE'),
                 "meta": ({k: request.form['meta_' + k] for k in request.form['meta_keys'].split(',')}
                          if 'meta_keys' in request.form else {}),
                 "tags": (request.form["tags"] if "tags" in request.form else []),
                 "artifacts": artifacts,
                 "condition": yara_condition_string}

    return generate_yara_rule(yara_dict)


def post_rule_json():
    """
    Receives a JSON of the operators which needs to be matched against the original list of artifacts.
    :return: JSON on the form of:
    {
        "artifacts:
        [
            {
            "artifactN":
            {
                "artifact",
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
    Receives a JSON of the operators which needs to be matched against the original list of artifacts.
    :return: JSON on the form of:
    {
        "artifacts:
        [
            {
            "artifactN":
            {
                "artifact",
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


def home():
    return render_template('index.html', routes=dict_to_json(routes))


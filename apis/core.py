import datetime
import json

from flask import make_response, jsonify, request
from flask_restx import Namespace, Resource, fields, reqparse

# from apis.custom_fields.list_data import ListData
from apis import custom_fields
from .handling import generate_yara_rule, add_yara_filenames, add_yara_filename

import handlers.git_handler as git
from database.operations import update_rule, get_rule, get_rules
from handlers.config_handler import CONFIG
from handlers.log_handler import create_logger

api = Namespace('core', description='Core API')

log = create_logger(__name__)

thehive_case_observables_model = api.model("TheHive-Case-Observables", {
    "_id": fields.String,
    "_parent": fields.String,
    "_routing": fields.String,
    "_type": fields.String,
    "_version": fields.Integer,
    "createdAt": fields.Integer,
    "createdBy": fields.String,
    "data": fields.String,
    "dataType": fields.String,
    "id": fields.String,
    "ioc": fields.Boolean,
    "message": fields.String,
    "reports": fields.Raw(),
    "sighted": fields.Boolean,
    "startDate": fields.Integer,
    "status": fields.String,
    "tags": fields.List(fields.String),
    "tlp": fields.Integer(min=0, max=3),
    "updatedAt": fields.Integer,
    "updatedBy": fields.String
})

thehive_case_model = api.model("TheHive-Case", {
    "_id": fields.String,
    "_parent": fields.String,
    "_routing": fields.String,
    "_type": fields.String,
    "_version": fields.Integer,
    "caseId": fields.Integer,
    "createdAt": fields.Integer,
    "createdBy": fields.String,
    "customFields": fields.Raw(),
    "description": fields.String,
    "flag": fields.Boolean,
    "id": fields.String,
    "metrics": fields.Raw(),
    "observables": fields.List(fields.Nested(thehive_case_observables_model))
})

yara_metadata_model = api.model("YARA-Metadata", {
    "description": fields.String(required=True)
})

yara_string_model = api.model("YARA-String", {
    "identifier": fields.String(required=True),
    "value": fields.String(required=True),
    "type": fields.String(required=True),
    "modifiers": fields.List(fields.String, required=True)
})

db_rule_model = api.model('DB Rule', {
    "added_on": fields.DateTime,
    "case_id": fields.String,
    "data": fields.Nested(thehive_case_model),
    "last_modified": fields.DateTime,
    "pending": fields.Boolean,
    "yara_file": fields.String
})

post_rule_model = api.model('POST Rule', {
    "meta": fields.Nested(yara_metadata_model, required=True),
    "name": fields.String(required=True),
    "tags": fields.List(fields.String, required=True),
    "strings": fields.List(fields.Nested(yara_string_model, required=True), required=True),
    "condition": fields.String(required=True)
})

# post_rule_model = api.schema_model('POST Rule', {
#     # "required": "",
#     "properties": {
#         "meta": {
#             "type": "json",
#         },
#         "name": {
#             "type": "string"
#         },
#         "tags": {
#             "type": "array"
#         },
#         "strings": {
#             "properties": {
#                 "identifier": {
#                     "type": "string"
#                 },
#                 "value": {
#                     "type": "string"
#                 },
#                 "string_type": {
#                     "type": "string"
#                 },
#                 "modifiers": {
#                     "type": "array"
#                 }
#             },
#             "type": "object"
#         },
#         "condition": {
#             "type": "string"
#         }
#     },
#     "type": "object"
# })


@api.route('/commit', methods=['POST'])
class PostCommit(Resource):
    def post(self):
        """

        """
        log.debug("Received HTTP POST Request{mimetype}: {req_json}".format(
            req_json=json.dumps(request.json, indent=4),
            mimetype=" ({})".format(request.headers['Content-Type']) if 'Content-Type' in request.headers else "")
        )

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

        the_oracle_repo = git.clone_if_not_exist(url=CONFIG["theoracle_repo"], path=CONFIG["theoracle_local_path"])

        try:
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
                commit_message = CONFIG["git_commit_msg_fmt"].format(rulename=request.json["rulename"])
                git_author = git.Actor(CONFIG["git_username"], CONFIG["git_email"])
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
                                                                            CONFIG["git_datetime_custom_fmt"]),
                        "diff": the_oracle_repo.git.diff('HEAD~1')
                    }
                }

                log.info("update_rule(case_id={cid}, "
                         "yara_file={yara_filepath})".format(cid=request.json["case_id"],
                                                             yara_filepath=request.json["filepath"]))
                update_rule(request.json["case_id"], yara_file=request.json["filepath"], pending=False)
            else:
                log.warning("Git Commit ignored, file added to repo does not differ from working tree: '{fn}".format(
                    fn=file_to_add))
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


# noinspection PyUnresolvedReferences
@api.route('/rule/<id>', methods=['GET'])
@api.route('/rule', methods=['POST'])
class RuleRequest(Resource):
    @api.param('id', 'Rule/TheHive case ID')
    @api.response(200, "Success", model=db_rule_model)
    def get(self, id):
        """Returns a specific rule."""
        rule = get_rule(case_id=id)
        modified_rule = add_yara_filename(rule)

        retv = jsonify(modified_rule)
        log.info("GET Rule '{id}' return JSON: {retv}".format(id=id, retv=json.dumps(retv.json, indent=4)))

        return retv

    @api.response(200, "Success", model=post_rule_model)
    def post(self):
        """
        Takes a JSON containing the recipe for a YARA Rule, then returns the generated YARA Rule.
        """
        log.debug("Received HTTP POST Request{mimetype}: {req_json}".format(
            req_json=json.dumps(request.json, indent=4),
            mimetype=" ({})".format(request.headers['Content-Type']) if 'Content-Type' in request.headers else "")
        )

        return jsonify(generate_yara_rule(request.json))


@api.route('/rules', methods=['GET'])
class RulesRequest(Resource):
    def get(self):
        """Returns all rules."""
        rules = get_rules()
        rules_modified = add_yara_filenames(rules)

        retv = jsonify(rules_modified)
        log.info("GET rules return JSON: {}".format(json.dumps(retv.json, indent=4)))

        return retv

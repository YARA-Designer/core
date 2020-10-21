import datetime
import json
import os

from flask import make_response, jsonify, request
from flask_restx import Namespace, Resource, fields

from utils import list_keys
from .handling import generate_yara_rule

from handlers import git_handler
from database.operations import update_rule, get_rule, get_rules
from handlers.config_handler import CONFIG
from handlers.log_handler import create_logger

api = Namespace('core', description='Core API')

log = create_logger(__name__)

yara_metadata_model = api.model("YARA-Metadata", {
    "identifier": fields.String(required=True, pattern=r"([a-zA-Z]([a-z0-9])+)"),
    "value": fields.String(required=True, pattern=r'.*'),
    "value_type": fields.String(required=True, pattern=r'str|int|bool'),
})

yara_string_model = api.model("YARA-String", {
    "identifier": fields.String(required=True, pattern=r"([a-zA-Z]([a-z0-9])+)"),
    "value": fields.String(required=True, pattern=r'.*'),
    "value_type": fields.String(required=True, pattern=r'str|int|bool'),
    "string_type": fields.String(required=True, pattern=r'text|hex|regex'),
    "modifiers": fields.List(
        fields.String(
            required=True,
            pattern=r"nocase|wide|ascii|xor|base64(wide)?(?'base64_alphabet'.*)?|fullword|private")
    ),
    "modifier_str": fields.String(
        required=True,
        pattern=r"[nocase|wide|ascii|xor|base64(wide)?(?'base64_alphabet'.*)?|fullword|private]+(\s+)?"),
    "str": fields.String(
            required=True,
            pattern=r"^(?'identifier'(?'prefix'(observable|[a-z]([a-z0-9]+))_)?[a-f0-9]{32})\s+=\s+(?'value'\".*\")$"
    )
})

db_rule_model = api.model('DB Rule', {
    "name": fields.String,
    "title": fields.String,
    "thehive_case_id": fields.String,
    "namespace": fields.String,
    "tags": fields.List(fields.String),
    "meta": fields.Nested(yara_metadata_model),
    "strings": fields.Nested(yara_string_model),
    "condition": fields.String,
    "added_on": fields.DateTime,
    "last_modified": fields.DateTime,
    "pending": fields.Boolean,
    "compilable": fields.Boolean,
    "source_path": fields.String
})

db_rules_model = api.model('DB Rules', {
    "rules": fields.List(fields.Nested(db_rule_model))
})

yara_rule_model = api.model('YARA-Rule', {
    "meta": fields.Nested(yara_metadata_model, required=True),
    "name": fields.String(required=True),
    "namespace": fields.String,
    "tags": fields.List(fields.String, required=True),
    "strings": fields.List(fields.Nested(yara_string_model, required=True), required=True),
    "condition": fields.String(required=True)
})

error_or_warning_feedback_model = api.model('Warning or Error', {
    "column_number": fields.Integer,
    "line_number": fields.Integer,
    "message": fields.String,
    "type": fields.String,
    "word": fields.String
})

post_yara_rule_output_model = api.model('POST YARA Rule Output', {
    "compilable": fields.Boolean,
    "success": fields.Boolean,
    "source_code": fields.String,
    "source_path": fields.String,
    "error": fields.Nested(error_or_warning_feedback_model),
    "has_warning": fields.Boolean,
    "warning": fields.Nested(error_or_warning_feedback_model),
})

post_commit_input_model = api.model('POST Commit Input', {
    "source_path": fields.String(required=True, description="Path to (YARA sourcecode) file to be commited."),
    "name": fields.String(required=True, description="Name of YARA Rule (used in commit msg)."),
    "thehive_case_id": fields.String(
        required=True,
        description="Used for fetching existing YARA Rule data from DB when performing an append operation.")
})

git_commit_model = api.model('Git Commit (Response)', {
    "author_email": fields.String,
    "author_username": fields.String,
    "committed_date_custom": fields.String,
    "committed_date_epoch": fields.Integer,
    "committed_date_iso": fields.String,
    "committer_email": fields.String,
    "committer_username": fields.String,
    "diff": fields.String,
    "hexsha": fields.String,
    "message": fields.String
})

post_commit_output_model = api.model('POST Commit Output', {
    "commit": fields.Nested(git_commit_model, required=True),
    "success": fields.Boolean(required=True)
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
    @api.expect(post_commit_input_model)
    @api.response(200, 'Success', model=post_commit_output_model)
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

        file_to_add = request.json["source_path"]
        yara_rulename = request.json["name"]
        thehive_case_id = request.json["thehive_case_id"]

        the_oracle_repo = git_handler.clone_if_not_exist(url=CONFIG["theoracle_repo"], path=CONFIG["theoracle_local_path"])

        try:
            # 1. Git Pull (Make sure we're in sync with remote/origin).
            log.info("Pulling data from remote '{}'...".format(the_oracle_repo.remotes.origin))
            the_oracle_repo.remotes.origin.pull()

            # 2. Git Add the YARA rule file.
            log.info("Git Add file to repo '{repo}': {fn}".format(repo=the_oracle_repo.git_dir, fn=file_to_add))
            the_oracle_repo.index.add(file_to_add, force=CONFIG["git_add_forcibly"])

            # 3. Git Commit
            # Only commit if working tree differs (i.e. there is an actual change).
            tree_differs = False if the_oracle_repo.index.diff('HEAD') == [] else True
            log.debug("Tree differs: {}".format(tree_differs))

            if tree_differs:
                commit_message = CONFIG["git_commit_msg_fmt"].format(rulename=yara_rulename)
                git_author = git_handler.Actor(CONFIG["git_username"], CONFIG["git_email"])
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

                # Update rule in database:
                # Get existing tags, meta and strings, in order to append instead of replace.
                # existing_rule = get_rule()
                existing_tags = None
                existing_meta = None
                existing_strings = None

                # update_rule()

                log.info("update_rule(case_id={cid}, "
                         "yara_file={yara_filepath})".format(cid=thehive_case_id,
                                                             yara_filepath=file_to_add))
                # update_rule(request.json["case_id"], yara_file=request.json["filepath"], pending=False)
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
        retv = jsonify(get_rule(thehive_case_id=id))
        log.info("GET '{route}/{id}' return JSON: {retv}".format(
            route='/rule', id=id, retv=json.dumps(retv.json, indent=4)))

        return retv

    @api.expect(yara_rule_model)
    @api.response(200, "Success", model=post_yara_rule_output_model)
    def post(self):
        """
        Takes a JSON containing the recipe for a YARA Rule, then returns the generated YARA Rule.
        """
        log.debug("Received HTTP POST '{route}' Request{mimetype}: {req_json}".format(
            route='/rule',
            req_json=json.dumps(request.json, indent=4),
            mimetype=" ({})".format(request.headers['Content-Type']) if 'Content-Type' in request.headers else "")
        )

        retv = {
            "in": request.json,
            "out": {}
        }
        try:
            retv = generate_yara_rule(request.json)
        except Exception as exc:
            retv["out"] = {
                "source": None,
                "success": False,
                "has_warning": False,
                "compilable": False,
                "error": {
                    "type": "Exception",
                    "message": str(exc),
                    "line_number": None,
                    "column_number": None,
                    "word": None
                }
            }

        return jsonify(retv)


@api.route('/rules', methods=['GET'])
class RulesRequest(Resource):
    @api.response(200, "Success", model=db_rules_model)
    def get(self):
        """Returns all rules."""
        rules = get_rules()
        retv = jsonify({"rules": rules})
        log.info("HTTP GET '{route}' returning {num}x JSON{keys_list}:\n{js}".format(
            route='/rules',
            num=len(rules), keys_list=str(list_keys(rules)), js=json.dumps(retv.json, indent=4)))

        return retv


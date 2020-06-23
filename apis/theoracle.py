import json
import os
import time
from datetime import datetime

from flask import request, jsonify
from flask_restx import Namespace, Resource, fields

from hashlib import sha256

from handlers.log_handler import create_logger
from handlers.config_handler import CONFIG
from handlers import git_handler as git
from yara_toolkit.yara_meta import YaraMeta
from yara_toolkit.yara_rule import YaraRule
from yara_toolkit.yara_string import YaraString

api = Namespace('theoracle', description='TheOracle YARA Rule Git repository.')

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

rule_model = api.model('TheOracle Rule', {
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

rules_model = api.model('TheOracle Rules', {
    "rules": fields.List(fields.Nested(rule_model))
})


@api.route('/rule_files', methods=['GET'])
class RulesOracleRequest(Resource):
    @api.response(200, "Success", model=rules_model)
    def get(self):
        """Returns all rules."""
        theoracle_rules_dir = os.path.join(CONFIG["theoracle_local_path"], CONFIG["theoracle_repo_rules_dir"])
        yara_files = os.listdir(theoracle_rules_dir)
        retv = jsonify({"files": yara_files})
        # log.info("HTTP GET '{route}' returning {num}x JSON{keys_list}:\n{js}".format(
        #     route='/rules',
        #     num=len(rules), keys_list=str((list(rules[0].keys()))), js=json.dumps(retv.json, indent=4)))

        return retv


def get_rule(filepath):
    start_time = time.time_ns()
    rule: YaraRule = YaraRule.from_source_file(filepath)
    elapsed_time = time.time_ns() - start_time
    log.debug(rule)

    title = rule.name
    thehive_case_id = None
    added_on = None

    if rule.meta:
        for meta in rule.meta:
            if meta.identifier == "title":
                title = meta.value
            if meta.identifier == "thehive_case_id":
                thehive_case_id = meta.value
            if meta.identifier == "added_on":
                added_on = meta.value

    rule_json_retv = {
        "name": rule.name,
        "title": title,
        "thehive_case_id": thehive_case_id,
        "namespace": rule.namespace,
        "tags": rule.tags if rule.tags else [],
        "meta": [meta.as_dict() for meta in rule.meta] if rule.meta else [],
        "strings": [ys.as_dict() for ys in rule.strings] if rule.strings else [],
        "condition": rule.condition.values,
        "condition_str": str(rule.condition),
        "added_on": added_on,
        "last_modified": datetime.isoformat(datetime.fromtimestamp(os.stat(filepath).st_mtime)),
        "pending": False,
        "compilable": None,
        "source_path": filepath.split(os.sep)[-1],
        "source_filename": os.path.basename(filepath),
        "source_path_sha256sum": sha256(filepath.encode('utf-8')).hexdigest(),
        "processing_time": elapsed_time
    }

    return rule_json_retv


# noinspection PyUnresolvedReferences
@api.route('/rule/<filename>', methods=['GET'])
class RuleRequest(Resource):
    @api.param('filename', 'YARA filename in TheOracle repo rules dir.')
    @api.response(200, "Success", model=rule_model)
    def get(self, filename):
        """Returns a specific rule."""
        theoracle_rules_dir = os.path.join(CONFIG["theoracle_local_path"], CONFIG["theoracle_repo_rules_dir"])
        filepath = os.path.join(theoracle_rules_dir, filename)

        retv = jsonify(get_rule(filepath))
        log.info("GET '{route}/{id}' return JSON: {retv}".format(
            route='/rule', id=id, retv=json.dumps(retv.json, indent=4)))

        return retv


@api.route('/rules', methods=['GET'])
class RulesOracleRequest(Resource):
    @api.response(200, "Success", model=rules_model)
    def get(self):
        """Returns all rules."""
        theoracle_rules_dir = os.path.join(CONFIG["theoracle_local_path"], CONFIG["theoracle_repo_rules_dir"])

        # Do a git pull to get latest revision
        try:
            log.info("Git pull theoracle repo.")
            git.clone_if_not_exist(url=CONFIG["theoracle_repo"], path=CONFIG["theoracle_local_path"])
        except Exception as exc:
            log.exception("Caught exception when trying to git.clone_if_not_exist!\nurl={url}\npath={path}".format(
                url=CONFIG["theoracle_repo"], path=CONFIG["theoracle_local_path"]), exc_info=exc)
            return {
                "rules": [],
                "success": False,
                "error": {
                    "message": str(exc),
                    "type": "exception",
                    "level": "error"
                }
            }

        # Get listing of YARA files in rules dir.
        yara_files = os.listdir(theoracle_rules_dir)
        yara_files_path = [os.path.join(theoracle_rules_dir, f) for f in yara_files]

        rules = []
        for yara_file in yara_files_path:
            rule = get_rule(yara_file)

            # Append the JSON/Model
            rules.append(rule)

        # Track stats
        time_stats = "Processing Time\tRule name\n"
        time_total = 0
        for r in rules:
            t = r["processing_time"]
            time_total += t
            time_stats += "{time}s:\t{name}\n".format(name=r["name"], time=t/1000000000)

        log.info("TheOracle Rule processing times:\n{}\n\nTotal: {}s".format(time_stats, time_total/1000000000))

        retv = jsonify({"rules": rules, "success": True, "error": {"message": None, "type": None, "level": None}})
        log.info("HTTP GET '{route}' returning {num}x JSON{keys_list}:\n{js}".format(
            route='/rules',
            num=len(rules), keys_list=str((list(rules[0].keys()))), js=json.dumps(retv.json, indent=4)))

        return retv

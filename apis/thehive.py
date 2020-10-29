import json

from flask import request, jsonify
from flask_restx import Namespace, Resource, fields
from thehive4py.api import TheHiveApi

from database.operations import has_row, update_rule, add_row
from handlers.log_handler import create_logger
from handlers.config_handler import CONFIG
from database.models import YaraRuleDB
from yara_toolkit.yara_meta import YaraMeta
from yara_toolkit.yara_string import YaraString

from hashlib import md5

api = Namespace('thehive', description='TheHive and Cortex endpoint.')

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
    "metrics": fields.Raw()
})

thehive_case_with_observables_model = api.model("TheHive-Case (Modified to contain observables)", {
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


def sanitize_case_property(s):
    """Removes problematic characters from a string"""
    return repr(s)[1:-1]


@api.route('/cortex-responder')
class CortexResponder(Resource):
    @api.expect(thehive_case_model)
    @api.response(400, 'Request data type mismatch')
    @api.response(200, "JSON response", model=thehive_case_with_observables_model)
    def post(self):
        """Receives a thehive:case from a Cortex Responder in JSON format."""
        if request.form is None:
            log.error("Received data was NoneType!")
            api.abort(400, "Received data was NoneType")
        elif not request.is_json:
            log.error("Received data was NOT JSON!\n{}".format(request.form))
            api.abort(400, "Received data was NOT JSON!")
        try:
            case = request.json
            case_id = case['id']
            log.info("thehive_case: {}".format(json.dumps(case, indent=4)))

            # Instantiate TheHive4py API
            hive_api = TheHiveApi(
                '{proto}://{host}:{port}'.format(
                    proto=("https" if CONFIG["hive_server_use_ssl"] else "http"),
                    host=CONFIG["hive_server"],
                    port=CONFIG["hive_port"]
                ), CONFIG["hive_api_key"])

            # Retrieve Observables in a separate API call (as they're not included in responder)
            observables_response = hive_api.get_case_observables(case_id)

            # Add observables to thehive:case as its own sub-dict
            case['observables'] = observables_response.json()

            strings = []
            for o in case["observables"]:
                # FIXME: Implement backend str type determination.
                strings.append(YaraString("observable_{md5sum}".format(
                    md5sum=md5(o["data"].encode("utf-8")).hexdigest()), o["data"]))

            # Append additional strings if specified in config.
            strings.extend(
                [
                    YaraString(
                        "observable_{md5sum}".format(
                            md5sum=md5(field.encode("utf-8")).hexdigest()),
                        case[field]) for field in CONFIG["hive_case_string_fields"]
                ]
            )

            all_tags = case["tags"]
            observables_tags = [t for li in [o["tags"] for o in case["observables"]] for t in li]
            all_tags.extend(observables_tags)
            all_unique_tags = list(set(all_tags))

            rule = YaraRuleDB(
                title=sanitize_case_property(case["title"]),
                description=sanitize_case_property(case["description"]),
                thehive_case_id=case_id,
                tags=all_unique_tags,
                meta=[YaraMeta(field, case[field]) for field in CONFIG["hive_case_meta_fields"]],
                strings=strings,
                pending=True
                )

            # Store the modified thehive:case JSON to database.
            if has_row(YaraRuleDB, thehive_case_id=case_id):
                log.warning("Row/Object identified by {filter_by} already exists in DB! Overwriting existing entry.")
                update_rule(case_id, update_attrs=rule.as_dict())
            else:
                add_row(rule)

            return jsonify(case)
        except Exception as exc:
            log.exception("An unexpected Exception occurred!", exc_info=exc)
            api.abort(500, str(exc))

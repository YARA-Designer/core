import json

from flask import request, jsonify
from flask_restx import Namespace, Resource
from thehive4py.api import TheHiveApi

from database.operations import has_row, update_rule, add_row
from handlers.log_handler import create_logger
from handlers.config_handler import CONFIG
from database.models import YaraRuleDB
from yara_toolkit.yara_meta import YaraMeta
from yara_toolkit.yara_string import YaraString

api = Namespace('thehive', description='TheHive and Cortex endpoint.')

log = create_logger(__name__)


@api.route('/cortex-responder')
class CortexResponder(Resource):
    @api.response(400, 'Request data type mismatch')
    @api.response(200, "JSON response")
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
            hive_api = TheHiveApi('http://{}:{}'.format(CONFIG["hive_server"], CONFIG["hive_port"]), CONFIG["hive_api_key"])

            # Retrieve Observables in a separate API call (as they're not included in responder)
            observables_response = hive_api.get_case_observables(case_id)

            # Add observables to thehive:case as its own sub-dict
            case['observables'] = observables_response.json()

            all_tags = case["tags"]
            observables_tags = [t for li in [o["tags"] for o in case["observables"]] for t in li]
            all_tags.extend(observables_tags)
            all_unique_tags = list(set(all_tags))

            rule = YaraRuleDB(
                title=case["title"],
                description=case["description"],
                thehive_case_id=case_id,
                tags=all_unique_tags,
                meta=[YaraMeta(field, case[field]) for field in CONFIG["hive_case_meta_fields"]],
                strings=[YaraString(field, case[field]) for field in CONFIG["hive_case_string_fields"]],
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

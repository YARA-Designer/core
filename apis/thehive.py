import json

from flask import request, jsonify, make_response
from flask_restx import Namespace, Resource, fields
from thehive4py.api import TheHiveApi

from database.operations import has_row, update_rule, add_row
from handlers.log_handler import create_logger
from handlers.config_handler import CONFIG
from database.models import Rule

api = Namespace('thehive', description='TheHive and Cortex endpoint.')

log = create_logger(__name__)


@api.route('/cortex-responder')
class CortexResponder(Resource):
    def post(self):
        """Receives a thehive:case from a Cortex Responder in JSON format."""
        if request.method != 'POST':
            log.error("Received request with wrong method!\n{}".format(request.method))
            return make_response("ERROR: Only POST method is allowed!", 405)

        if request.form is None:
            log.error("Received data was NoneType!")
            return make_response("ERROR: Received data was NoneType!", 400)
        elif not request.is_json:
            log.error("Received data was NOT JSON!\n{}".format(request.form))
            return make_response("ERROR: Received data was NOT JSON!", 400)
        try:
            thehive_case = request.json
            case_id = thehive_case['id']
            log.info("thehive_case: {}".format(json.dumps(thehive_case, indent=4)))

            # rule = YaraWhitelistAlertRule(request.form['title'], description=request.form['description'])
            # js = json.loads(json.dumps(rule.get_dict()))

            # Instantiate TheHive4py API
            hive_api = TheHiveApi('http://{}:{}'.format(CONFIG["hive_server"], CONFIG["hive_port"]), CONFIG["hive_api_key"])

            # Retrieve Observables in a separate API call (as they're not included in responder)
            observables_response = hive_api.get_case_observables(case_id)

            # Add observables to thehive:case as its own sub-dict
            thehive_case['observables'] = observables_response.json()
            # log.debugs("Case with observables:\n{}".format(json.dumps(thehive_case, indent=4)))

            rule = Rule(data=thehive_case)

            # Store the modified thehive:case JSON to database.
            if has_row(Rule, case_id=case_id):
                log.warning("Row/Object identified by {filter_by} already exists in DB! Overwriting existing entry.")
                update_rule(case_id, update_attrs=rule.as_dict())
            else:
                add_row(rule)

            return jsonify(thehive_case)
        except Exception as exc:
            log.exception("An unexpected Exception occurred!", exc_info=exc)

            return make_response(str(exc), 500)

import json

from flask import request, jsonify, make_response
from thehive4py.api import TheHiveApi
from werkzeug.datastructures import ImmutableMultiDict

from database.operations import add_row, has_row, update_rule
from handlers import config_handler

from database.models import Rule
from handlers.log_handler import create_logger

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


def create_yara_whitelist_rule():
    if request.method == 'POST':
        if request.form is None:
            log.error("ERROR: Received data was NoneType!")
            return "ERROR: Received data was NoneType!"
        elif not request.is_json:
            log.error("ERROR: Received data was NOT JSON!\n{}".format(request.form))
            return "ERROR: Received data was NOT JSON!\n{}".format(request.form)
        try:
            thehive_case = request.json
            case_id = thehive_case['id']
            log.info("thehive_case: {}".format(json.dumps(thehive_case, indent=4)))

            # rule = YaraWhitelistAlertRule(request.form['title'], description=request.form['description'])
            # js = json.loads(json.dumps(rule.get_dict()))

            # Get config
            config = config_handler.load_config()

            # Instantiate TheHive4py API
            hive_api = TheHiveApi('http://{}:{}'.format(config["hive_server"], config["hive_port"]), config["hive_api_key"])

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




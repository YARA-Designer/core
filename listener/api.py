import json

from flask import request, jsonify
from thehive4py.api import TheHiveApi
from handlers import config_handler

from yara.rules import YaraWhitelistAlertRule


def create_yara_whitelist_rule():
    if request.method == 'POST':
        if request.form is None:
            return "ERROR: Received data was NoneType!"

        rule = YaraWhitelistAlertRule(request.form['title'], description=request.form['description'])
        js = json.loads(json.dumps(rule.get_dict()))

        # FIXME: Make separate function
        # Get config
        config = config_handler.load_config()

        # Instantiate TheHive4py API
        hive_api = TheHiveApi('http://{}:{}'.format(config["hive_server"], config["hive_port"]), config["hive_api_key"])

        # Retrieve Observables in a separate API call (as they're not included in responder)
        observables_response = hive_api.get_case_observables(request.form['id'])
        print(observables_response)
        observables = observables_response.json()
        print(observables)

        dict_list = {}
        for observable in observables:
            print(observable)
            dict_list[observable['id']] = observable




        return jsonify(dict_list)
        # return js



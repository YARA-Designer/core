import json

from flask import request, jsonify
from sqlalchemy.orm import sessionmaker
from thehive4py.api import TheHiveApi
from werkzeug.datastructures import ImmutableMultiDict

from database.operations import add_row
from handlers import config_handler

from yara.rules import YaraWhitelistAlertRule
import webserver
from database import engine
from database.tables.pending_rule import PendingRule


def get_json_returnable_observables_list(observables: json):
    dict_list = {}
    for observable in observables:
        print(observable)
        dict_list[observable['id']] = observable

    return dict_list


def imd_to_dict(imd: ImmutableMultiDict):
    dct = {}
    for key, value in imd.items():
        print("{}: {}".format(key, value))
        dct[key] = value

    return dct


def create_yara_whitelist_rule():
    if request.method == 'POST':
        if request.form is None:
            return "ERROR: Received data was NoneType!"
        elif not request.is_json:
            return "ERROR: Received data was NOT JSON!\n{}".format(request.form)

        thehive_case = request.json
        print(json.dumps(thehive_case, indent=4))

        # rule = YaraWhitelistAlertRule(request.form['title'], description=request.form['description'])
        # js = json.loads(json.dumps(rule.get_dict()))

        # FIXME: Make separate function
        # Get config
        config = config_handler.load_config()

        # Instantiate TheHive4py API
        hive_api = TheHiveApi('http://{}:{}'.format(config["hive_server"], config["hive_port"]), config["hive_api_key"])

        # Retrieve Observables in a separate API call (as they're not included in responder)
        observables_response = hive_api.get_case_observables(thehive_case['id'])

        # Add observables to thehive:case as its own sub-dict
        thehive_case['observables'] = observables_response.json()
        # print("Case with observables:\n{}".format(json.dumps(thehive_case, indent=4)))

        # Send the modified thehive:case to the webserver
        # webserver.update_content(thehive_case)

        # Store the modified thehive:case JSON to database.
        rule = PendingRule(data=thehive_case)

        add_row(rule)

        return jsonify(thehive_case)



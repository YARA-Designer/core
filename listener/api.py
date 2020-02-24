import json

from flask import request
from yara.rules import YaraWhitelistAlertRule


def create_yara_whitelist_rule():
    if request.method == 'POST':
        if request.form is None:
            return "ERROR: Received data was NoneType!"

        rule = YaraWhitelistAlertRule(request.form['title'], description=request.form['description'])
        js = json.loads(json.dumps(rule.get_dict()))
        return js



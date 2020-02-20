import json

from flask import Flask, jsonify, request
from yara.rules import YaraWhitelistAlertRule

app = Flask(__name__)
app.config["DEBUG"] = True


@app.route('/YaraWhitelistRuleCreator', methods=['POST'])
def create_yara_whitelist_rule():
    if request.method == 'POST':
        if request.form is None:
            return "ERROR: Received data was NoneType!"

        rule = YaraWhitelistAlertRule(request.form['title'], description=request.form['description'])
        js = json.loads(json.dumps(rule.get_dict()))
        return js


app.run(host="0.0.0.0", port=5001)


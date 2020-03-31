import json
import pprint

import yara
from flask import render_template, request, jsonify, make_response
from sqlalchemy.exc import SQLAlchemyError

from database.models import PendingRule
from database.operations import db_session
import yara_handling

tab_character = "&nbsp;"
tab = tab_character*4
routes = {}


def get_pending_rule_db_by_case_id(case_id: str):
    rule = None
    session = db_session()

    try:
        # Get the first item in the list of queries
        query = session.query(PendingRule).filter(PendingRule.case_id == case_id)[0]
        rule = {'added_on': query.added_on, 'data': query.data, 'case_id': query.case_id, 'id': query.id}

        # Commit transaction (NB: makes detached instances expire)
        session.commit()
    except SQLAlchemyError:
        raise
    finally:
        session.close()

    return rule


def get_pending_rules_db():
    pending_rules = []
    session = db_session()

    try:
        for row in session.query(PendingRule).all():
            pending_rules.append({'added_on': row.added_on, 'data': row.data, 'case_id': row.case_id, 'id': row.id})

        # Commit transaction (NB: makes detached instances expire)
        session.commit()
    except SQLAlchemyError:
        raise
    finally:
        session.close()

    return pending_rules


def list_pending_rules_rawhtml():
    # Get pending rules from database.
    pending_rules = get_pending_rules_db()

    line = ""
    for rule in pending_rules:
        line += "{}{} Case '{}': {}".format(rule['added_on'], tab, rule['data']['id'], rule['data']['title'])

        for observable in rule['data']['observables']:
            line += ("<br/>{}Observable: {} ({})".format(tab, observable['data'], observable['dataType']))

        line += "<br/>"

    return line


def dict_to_json(d: dict):
    # Get rule dict
    rule_dict = d

    # Serialize all items as str
    rule_json_str = json.dumps(rule_dict, default=str)

    # Convert it into a JSON object (avoids TypeErrors with things like datetime)
    return json.loads(rule_json_str)


def list_pending_rules():
    # Get pending rules from database.
    pending_rules_dict = get_pending_rules_db()

    pending_rules_json = []
    for rule_dict in pending_rules_dict:
        pending_rules_json.append(dict_to_json(rule_dict))

    return render_template('list_pending_rules.html', cases=pending_rules_json)


def new_rule():
    """
    Renders a web page containing both raw rule cli and the designer.
    :return:
    """
    if 'id' not in request.args:
        return "Please specify a case ID!"

    return render_template('new_yara_rule.html',
                           case=dict_to_json(get_pending_rule_db_by_case_id(request.args.get('id'))))


def new_rule_raw():
    if 'id' not in request.args:
        return "Please specify a case ID!"

    return render_template('yara_rule_raw.html',
                           case=dict_to_json(get_pending_rule_db_by_case_id(request.args.get('id'))))


def new_rule_designer_drag_and_drop():
    if 'id' not in request.args:
        return "Please specify a case ID!"

    case = dict_to_json(get_pending_rule_db_by_case_id(request.args.get('id')))
    theme = request.args.get('theme')

    return render_template('yara_rule_designer_drag_and_drop.html',
                           case=case,
                           artifacts=case['data']['observables'],
                           theme=theme)


def new_rule_designer_click():
    if 'id' not in request.args:
        return "Please specify a case ID!"

    case = dict_to_json(get_pending_rule_db_by_case_id(request.args.get('id')))
    print(json.dumps(case, indent=4))
    theme = request.args.get('theme')

    return render_template('yara_rule_designer_click.html',
                           case=case,
                           artifacts=case['data']['observables'],
                           theme=theme)


def generate_yara_rule(j: json):
    print("========== DEBUG: Yara Dict ==========")
    pp = pprint.PrettyPrinter(indent=4)
    print(pp.pprint(j))
    print("========== DEBUG: Yara Dict ==========")

    # Processing status, return values and so forth.
    retv = {"in": j, "out": yara_handling.compile_from_source(j)}

    # FIXME: Send proper feedback to be handled by webpage instead of navigating to a JSON dump.
    return retv


def post_rule_raw_imd():
    """
    Receives an ImmutableMultiDict of the operators which needs to be matched against the original list of artifacts.
    :return: JSON on the form of:
    {
        "artifacts:
        [
            {
            "artifactN":
            {
                "artifact",
                "id",
                "type"
            }
            }
        ]",
        condition: ""
    }
    """
    print("keys: " + str([key for key in request.form.keys()]))
    print("request.form: {}".format(request.form))

    artifacts = {}
    for artifact, varname, artifact_type, artifact_id in zip(request.form.getlist('artifact'),
                                                             request.form.getlist('artifact_var'),
                                                             request.form.getlist('artifact_type'),
                                                             request.form.getlist('artifact_id')):
        artifacts[varname] = {"artifact": artifact, "type": artifact_type, "id": artifact_id}

    yara_condition_string = request.form['rawUrlSubmit']
    yara_dict = {"rule": (request.form['rule'] if 'rule' in request.form else 'UNNAMED_RULE'),
                 "meta": ({k: request.form['meta_' + k] for k in request.form['meta_keys'].split(',')}
                          if 'meta_keys' in request.form else {}),
                 "tags": (request.form["tags"] if "tags" in request.form else []),
                 "artifacts": artifacts,
                 "condition": yara_condition_string}

    return generate_yara_rule(yara_dict)


def post_rule_json():
    """
    Receives a JSON of the operators which needs to be matched against the original list of artifacts.
    :return: JSON on the form of:
    {
        "artifacts:
        [
            {
            "artifactN":
            {
                "artifact",
                "id",
                "type"
            }
            }
        ]",
        condition: ""
    }
    """
    print("request.json: {}".format(json.dumps(request.json, indent=4)))

    # Workaround: JSON.Stringify() returns lists wrapped in string, so let's convert it to a proper list:
    #   1. Split on the human readable delimiter and transform it into a list (NB: items will still be quoted).
    #   2. Strip head and tail string wrappers from each individual item using list comprehension.
    request.json["tags"]: list = [x[1:-1] for x in list(request.json["tags"][1:-1].split(", "))]

    return make_response(jsonify(generate_yara_rule(request.json)), 200)


def home():
    return render_template('index.html', routes=dict_to_json(routes))


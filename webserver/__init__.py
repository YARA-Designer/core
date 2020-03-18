import json
import os

from flask import render_template, request, jsonify
from sqlalchemy.exc import SQLAlchemyError

from database.models import PendingRule
from database.operations import db_session

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


def new_rule_designer():
    if 'id' not in request.args:
        return "Please specify a case ID!"

    case = dict_to_json(get_pending_rule_db_by_case_id(request.args.get('id')))
    theme = request.args.get('theme')

    return render_template('yara_rule_designer.html',
                           case=case,
                           artifacts=case['data']['observables'],
                           theme=theme)


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

    artifacts = {}
    for artifact, varname, artifact_type, artifact_id in zip(request.form.getlist('artifact'),
                                                             request.form.getlist('artifact_var'),
                                                             request.form.getlist('artifact_type'),
                                                             request.form.getlist('artifact_id')):
        artifacts[varname] = {"artifact": artifact, "type": artifact_type, "id": artifact_id}

    yara_condition_string = request.form['rawUrlSubmit']
    combined = {"artifacts": artifacts, "condition": yara_condition_string}

    return combined
    # return render_template('post_yara_rule.html',
    #                        case=dict_to_json(get_pending_rule_db_by_case_id(request.args.get('id'))))


def home():
    return render_template('index.html', routes=dict_to_json(routes))


import json
import os

from flask import render_template, request, jsonify
from sqlalchemy.exc import SQLAlchemyError

from database.models import PendingRule
from database.operations import db_session

tab_character = "&nbsp;"
tab = tab_character*4


def get_pending_rule_db_by_case_id(case_id: str):
    rule = None
    session = db_session()

    try:
        # Get the first item in the list of queries
        query = session.query(PendingRule).filter(PendingRule.case_id == case_id)[0]
        print("dfdff")
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
    return render_template('new_yara_rule.html',
                           case=dict_to_json(get_pending_rule_db_by_case_id(request.args.get('id'))))


def post_rule():
    """
    Receives an ImmutableMultiDict of the operators which needs to be matched against the original list of artifacts.
    :return:
    """
    print(request.form)
    # operator = request.form['operator']
    # artifact = request.form['artifact']
    # artifact_type = request.form['artifactType']
    # artifact_id = request.form['artifactId']
    # print("operator = {}\n"
    #       "artifact = {}\n"
    #       "artifact_type = {}\n"
    #       "artifact_id = {}\n".format(operator, artifact, artifact_type, artifact_id))

    return dict_to_json(request.form)
    # return render_template('post_yara_rule.html',
    #                        case=dict_to_json(get_pending_rule_db_by_case_id(request.args.get('id'))))


def home():
    return new_rule()


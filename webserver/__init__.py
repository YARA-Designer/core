import json
import os

from flask import render_template

from database.models import PendingRule
from database.operations import db_session

tab_character = "&nbsp;"
tab = tab_character*4


def get_pending_rules_db():
    pending_rules = []
    session = db_session()

    try:
        for row in session.query(PendingRule).all():
            pending_rules.append({'added_on': row.added_on, 'data': row.data, 'id': row.id})

        # Commit transaction (NB: makes detached instances expire)
        session.commit()
    except:
        raise
    finally:
        session.close()

    return pending_rules


def list_pending_rules():
    # Get pending rules from database.
    pending_rules = get_pending_rules_db()

    line = ""
    for rule in pending_rules:
        line += "{}{} Case '{}': {}".format(rule['added_on'], tab, rule['data']['id'], rule['data']['title'])

        for observable in rule['data']['observables']:
            line += ("<br/>{}Observable: {} ({})".format(tab, observable['data'], observable['dataType']))

        line += "<br/>"

    return line


def new_rule():
    # return render_template('new_yara_rule.html', **locals())
    return render_template('new_yara_rule.html', thehive_cases=get_pending_rules_db())


def home():
    return new_rule()


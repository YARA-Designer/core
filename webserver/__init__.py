import json
import os

from flask import render_template
from globals import pending_yara_rules

tab_character = "&nbsp;"
tab = tab_character*4


def update_content(hive_case: json):
    pending_yara_rules.append(hive_case)


def list_pending_rules():
    line = ""
    for case in pending_yara_rules:
        line += "Case '{}': {}".format(case['id'], case['title'])

        for observable in case['observables']:
            line += ("<br/>{}Observable: {}".format(tab, str(observable)))

        line += "<br/>"

    return line


def new_rule():
    # return render_template('new_yara_rule.html', **locals())
    return render_template('new_yara_rule.html', thehive_cases=pending_yara_rules)


def home():
    return new_rule()


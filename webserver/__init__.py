import json
import os

from flask import render_template

content = []
tab_character = "&nbsp;"
tab = tab_character*4


def update_content(hive_case: json):
    global content
    content.append(hive_case)


def list_content():
    global content

    line = "UNSET"
    for case in content:
        line = "Case '{}': {}".format(case['id'], case['title'])

        for observable in case['observables']:
            line += ("<br/>{}Observable: {}".format(tab, str(observable)))

    return line


def new_yara_rule():
    # return render_template('new_yara_rule.html', **locals())
    return render_template('new_yara_rule.html', thehive_cases=content)


def home():
    return new_yara_rule()


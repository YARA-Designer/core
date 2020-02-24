import json

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


def home():
    return list_content()

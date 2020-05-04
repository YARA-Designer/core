import json


def strip_trailing_comment(s):
    """
    Strips out a trailing comment

    :param s:
    :return:
    """
    return s[:s.find('/*')]


if __name__ == "__main__":
    styleLines = []
    rootVars = []
    with open('../styles/yara_rule_designer.css', 'r') as f:
        root_var_segment = False
        for line in f:
            styleLines.append(line)

            if ':root {' in line:
                root_var_segment = True
                continue

            if root_var_segment:
                if '}' in line:
                    root_var_segment = False
                else:
                    # Strip any trailing comments.
                    # (coding support for leading and depth is too
                    # time consuming for this simple utility script.)
                    line = strip_trailing_comment(line)
                    if '/*' not in line and '*/' not in line:
                        # Trim leading indent.
                        rootVars.append(line[4:].strip('\n'))
                    else:
                        print("Ignore commented line: {}".format(repr(line)))

    themeJson = {}
    for var in rootVars:
        if var != '':
            key, value = var.split(':')
            # Strip trailing semicolon and leading whitespace.
            value = value.strip(' ').strip(';')
            themeJson[key] = value

    print(json.dumps(themeJson, indent=4))

    with open('default.json', 'w') as f:
        json.dump(themeJson, f, indent=4)
    with open('light.json', 'w') as f:
        json.dump(themeJson, f, indent=4)


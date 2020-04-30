import json

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
                    if '/*' not in line and '*/' not in line:
                        # Trim leading indent.
                        rootVars.append(line[4:].strip('\n'))

    themeJson = {}
    for var in rootVars:
        if var != '':
            key, value = var.split(':')
            # Strip trailing semicolon and leading whitespace.
            value = value[1:-1]
            themeJson[key] = value

    print(json.dumps(themeJson, indent=4))

    with open('default.json', 'w') as f:
        json.dump(themeJson, f, indent=4)
    with open('light.json', 'w') as f:
        json.dump(themeJson, f, indent=4)


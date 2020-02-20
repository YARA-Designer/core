import json


class YaraWhitelistAlertRule:
    def __init__(self, name, description=""):
        self.rulename = "Whitelist_{}".format(name)
        self.alertname = name
        self.remove_me = "String to enable empty whitelistingrules - DELETE when adding whitelisting rules"
        self.alert_type = "email"
        self.description = description
        self.condition = "{} and ({})".format(self.alertname, self.remove_me)

        self.dict = {
            "name": "Whitelist_{}".format(name), "type": "email",
            "meta": {
                "description ": "Whitelist rules for the alert: {}".format(name)
            },
            "strings": {
                "alertname": name, "remove_me": "String to enable empty whitelistingrules - DELETE when adding "
                                                "whitelisting rules"
            },
            "condition": "$alertname and ($remove_me)"
        }

    # def __str__(self):
    #     return "rule {} : {}" \
    #            "{" \
    #            "    meta:" \
    #            "        description = \"{}\"" \
    #            "" \
    #            "    strings:" \
    #            "        $alertname = \"{}\"" \
    #            "" \
    #            "    condition:" \
    #            "        {}" \
    #            "}".format(self.rulename, self.alert_type, self.description, self.alertname, self.condition)

    def get_dict(self):
        return self.dict

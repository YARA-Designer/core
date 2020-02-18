class YaraWhitelistAlertRule:
    def __init__(self, name, description=""):
        self.rulename = "Whitelist_{}".format(name)
        self.alertname = name
        self.remove_me = "String to enable empty whitelistingrules - DELETE when adding whitelisting rules"
        self.alert_type = "email"
        self.description = description
        self.condition = "{} and ({})".format(self.alertname, self.remove_me)

    def __str__(self):
        return "rule {} : {}" \
               "{" \
               "    meta:" \
               "        description = \"{}\"" \
               "" \
               "    strings:" \
               "        $alertname = \"{}\"" \
               "" \
               "    condition:" \
               "        {}" \
               "}".format(self.rulename, self.alert_type, self.description, self.alertname, self.condition)

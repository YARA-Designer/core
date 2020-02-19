#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder

TH_DATATYPE_ALERT = "thehive:alert"


class YaraWhitelistAlertRule:
    def __init__(self, name):
        self.json_data = {
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

    def get_json(self):
        return self.json_data


class YaraWhitelistRuleCreator(Responder):
    def __init__(self):
        Responder.__init__(self)

    def run(self):
        Responder.run(self)

        if self.data_type != TH_DATATYPE_ALERT:
            self.error("Invalid dataType!")

        alertname = self.get_param("details_title", None, "Missing alert title/name!")

        rule = YaraWhitelistAlertRule(alertname)
        print(rule)

        self.report("test message", "FIXME")

    def operations(self, raw):
        return [self.build_operation('AddTagToCase', tag='FIXME')]  # FIXME: Apply a proper relevant operation


if __name__ == "__main__":
    YaraWhitelistRuleCreator().run()

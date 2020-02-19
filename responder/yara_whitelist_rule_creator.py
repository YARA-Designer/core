#!/usr/bin/env python3
# encoding: utf-8
import json

from cortexutils.responder import Responder

TH_DATATYPE_ALERT = "thehive:alert"
TH_DATATYPE_CASE = "thehive:case"


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
        # self.report({"message": "DEBUG: Self ran"})
        # Responder.run(self)
        self.report({"message": "DEBUG: Responder ran"})

        if self.data_type != TH_DATATYPE_CASE:
            self.error({"message": "Invalid dataType: got '{}', expected '{}'!".format(self.data_type,
                                                                                       TH_DATATYPE_CASE)})

        # alertname = self.get_param("title", None, "Missing title/name!")
        #
        # rule = YaraWhitelistAlertRule(alertname)
        # # FIXME: Log debug into syslog (dumping to file seems to fail)debug to a file.
        # print(json.dumps(rule.get_json(), indent=4))
        # with open("/opt/debug/YaraWhitelistRuleCreator.json", "w") as f:
        #     json.dump(rule.get_json(), f, indent=4)

        self.report({"message": "FIXME"})

    def operations(self, raw):
        return [self.build_operation('AddTagToCase', tag='FIXME')]  # FIXME: Apply a proper relevant operation


if __name__ == "__main__":
    YaraWhitelistRuleCreator().run()

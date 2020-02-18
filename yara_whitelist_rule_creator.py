#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
from yara.rules import YaraWhitelistAlertRule

TH_DATATYPE_ALERT = "thehive:alert"


class YaraWhitelistRuleCreator(Responder):
    def __init__(self):
        Responder.__init__(self)

    def run(self):
        Responder.run(self)

        if self.data_type != TH_DATATYPE_ALERT:
            self.error("Invalid dataType!")

        alertname = self.get_param("details_title", None, "Missing alert title/name!")
        meta_desc = "Whitelist rules for the alert: {}".format(alertname)

        rule = YaraWhitelistAlertRule(alertname, meta_desc)
        print(rule)

        self.report("test message", "FIXME")

    def operations(self, raw):
        return [self.build_operation('AddTagToCase', tag='FIXME')]  # FIXME: Apply a proper relevant operation


if __name__ == "__main__":
    YaraWhitelistRuleCreator().run()

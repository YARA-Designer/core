#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder

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


if __name__ == "__main__":
    YaraWhitelistRuleCreator().run()

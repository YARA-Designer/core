#!/usr/bin/env python3
# encoding: utf-8
import json
import requests

from cortexutils.responder import Responder

TH_DATATYPE_ALERT = "thehive:alert"
TH_DATATYPE_CASE = "thehive:case"


class YaraWhitelistRuleCreator(Responder):
    def __init__(self):
        Responder.__init__(self)

    def run(self):
        if self.data_type != TH_DATATYPE_CASE:
            self.error("Invalid dataType: got '{}', expected '{}'!".format(self.data_type, TH_DATATYPE_CASE))

        server = "192.168.136.1"
        port = 5001
        route = "YaraWhitelistRuleCreator"
        endpoint = "http://{}:{}/{}".format(server, port, route)
        r = requests.post(endpoint, data=self.get_data())
        if r.status_code != 200:
            self.error("POST Request to {} failed with status: {} {}!".format(endpoint, r.status_code,
                                                                              r.reason))

        # dct = {"name": js["name"],
        #        "type": js["type"],
        #        "meta": js["meta"],
        #        "strings": js["strings"],
        #        "condition": js["condition"]
        #        }
        # self.report(dct)

        js = json.loads(r.text)
        self.report(js)

    def operations(self, raw):
        # FIXME: Apply a proper relevant operation (like mark read)
        return [self.build_operation('AddTagToCase', tag='FIXME')]


if __name__ == "__main__":
    YaraWhitelistRuleCreator().run()

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

    # def get_data_as_json(self):
    #     """
    #     Convert get_data()'s python dict to JSON object.
    #
    #     First convert the dict to a JSON-compatible string, then load it as JSON input,
    #     resulting in a JSON object.
    #     :return:
    #     """
    #     # return json.loads(json.dumps(self.get_data()))
    #     return json.JSONEncoder.encode(json.dumps(self.get_data()))

    def run(self):
        if self.data_type != TH_DATATYPE_CASE:
            self.error("Invalid dataType: got '{}', expected '{}'!".format(self.data_type, TH_DATATYPE_CASE))

        server = "192.168.136.1"
        port = 5001
        route = "YaraWhitelistRuleCreator"
        endpoint = "http://{}:{}/{}".format(server, port, route)
        print(type(self.get_data()))
        print(self.get_data())
        r = requests.post(endpoint, json=self.get_data(), headers={'Content-type': 'application/json'})
        if r.status_code != 200:
            self.error("POST Request to {} failed with status: {} {}!".format(endpoint, r.status_code,
                                                                              r.reason))

        js = json.loads(r.text)
        self.report(js)

    def operations(self, raw):
        # FIXME: Apply a proper relevant operation (like mark alert read and delete case?)
        return [self.build_operation('AddTagToCase', tag='FIXME 1')]


if __name__ == "__main__":
    YaraWhitelistRuleCreator().run()

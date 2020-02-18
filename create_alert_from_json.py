import sys
import json
from datetime import datetime

from thehive4py.api import TheHiveApi
from thehive4py.models import Alert

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Error: Requires one single JSON file as argument!")
        exit(1)

    api_key = "YaMWlH5cr25AegAhTjntDkXNLFNlO1Yx"
    hive_api = TheHiveApi('http://{}:{}'.format("192.168.136.129", 9000), api_key)

    with open(sys.argv[1], "r") as f:
        alert_json = json.load(f)
        print(json.dumps(f, indent=4))
        exit(3)

    response = hive_api.create_alert(Alert(title="Test @ {}".format(datetime.utcnow()),
                                           severity=3,
                                           tlp=3,
                                           source="splunk @ {}".format(datetime.utcnow()),
                                           sourceRef="splunkRef",
                                           type='external',
                                           description="Something",
                                           tags=[]))
    # response = hive_api.create_alert(Alert())
    if response.status_code == 201:
        print(json.dumps(response.json(), indent=4, sort_keys=True))
        print('')
        id = response.json()['id']
    else:
        print('ko: {}/{}'.format(response.status_code, response.text))

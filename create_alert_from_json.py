import sys
import json

from thehive4py.api import TheHiveApi
from thehive4py.models import Alert

if __name__ == "__main__":
    print(sys.argv)
    if len(sys.argv) != 2:
        print("Error: Requires one single JSON file as argument!")
        exit(1)

    api_key = "YaMWlH5cr25AegAhTjntDkXNLFNlO1Yx"
    hive_api = TheHiveApi('http://{}:{}'.format("192.168.136.129", 9000), api_key)

    with open(sys.argv[1]) as f:
        alert_json = json.load(f)
        # print(json.dumps(alert_json, indent=4))

    response = hive_api.create_alert(Alert(**alert_json))
    if response.status_code == 201:
        print(json.dumps(response.json(), indent=4, sort_keys=True))
        print('')
        id = response.json()['id']
    else:
        print('ko: {}/{}'.format(response.status_code, response.text))

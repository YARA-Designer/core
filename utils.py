import json


def dict_to_json(d: dict):
    # Get rule dict
    rule_dict = d

    # Serialize all items as str
    rule_json_str = json.dumps(rule_dict, default=str)

    # Convert it into a JSON object (avoids TypeErrors with things like datetime)
    return json.loads(rule_json_str)


def list_keys(li: list):
    """
    Takes a list of JSON objects and returns a list of keys.
    """
    if len(li) == 0:
        return li
    else:
        return list(li[0].keys())

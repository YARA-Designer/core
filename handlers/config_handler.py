import json
import os

CONFIG_FILE = "config.json"
SAMPLE_CONFIG_FILE = "config.json.sample"
DEFAULT_CONFIG = {
    "debug": "False",
    "hive_server": "192.168.136.129",
    "hive_port": 9000,
    "hive_listener_endpoint": "/YaraWhitelistRuleCreator",
    "hive_api_key": "SuGd5Aj4NNudH8unh5CpWLm4U/MYDeVc",
    "listener_bind_host": "0.0.0.0",
    "listener_bind_port": 5001,
    "datetime_format": "%Y-%m-%d %H:%M:%SZ"
}


def has_option(cfg: json, cfg_key: str):
    if cfg_key in cfg:
        return True

    return False


def load_default_config():
    # Create a sample config file.
    with open(SAMPLE_CONFIG_FILE, 'w') as f:
        json.dump(DEFAULT_CONFIG, f, indent=4)

    return DEFAULT_CONFIG


def load_config():
    # If config file doesn't exist
    if not os.path.isfile(CONFIG_FILE):
        cfg = load_default_config()
    else:
        try:
            with open(CONFIG_FILE) as f:
                cfg = json.load(f)
        except Exception as exc:
            print("Error: Exception occurred while opening config file: {}! "
                  "Falling back to default config.".format(exc, CONFIG_FILE))
            cfg = load_default_config()
            pass

    return cfg

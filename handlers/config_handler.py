import json
import os

CONFIG_FILE = "config.json"
SAMPLE_CONFIG_FILE = "config.json.sample"
DEFAULT_CONFIG = {
    "debug": False,
    "log_to_file": False,
    "log_level": 1,
    "logging_port": 19995,
    "logging_dir": "logs/",
    "hive_server": "127.0.0.1",
    "hive_port": 9000,
    "hive_listener_endpoint": "/YaraWhitelistRuleCreator",
    "hive_api_key": "SuGd5Aj4NNudH8unh5CpWLm4U/MYDeVc",
    "listener_bind_host": "0.0.0.0",
    "listener_bind_port": 5001,
    "datetime_format": "%Y-%m-%d %H:%M:%SZ",
    "theoracle_server": "127.0.0.1",
    "theoracle_port": 22,
    "theoracle_user": "git",
    "theoracle_remote_repo": "",
    "theoracle_local_path": "the-oracle",
    "theoracle_repo_rules_dir": "rules"
}


def has_option(cfg: json, cfg_key: str):
    if cfg_key in cfg:
        return True

    return False


def has_custom_config():
    if os.path.isfile(CONFIG_FILE):
        return True
    else:
        return False


def update_sample_config():
    with open(SAMPLE_CONFIG_FILE, 'w') as f:
        json.dump(DEFAULT_CONFIG, f, indent=4)


def load_config():
    # Create a sample config file.
    update_sample_config()

    # If config file doesn't exist
    if has_custom_config() is False:
        cfg = DEFAULT_CONFIG
    else:
        try:
            with open(CONFIG_FILE) as f:
                cfg = json.load(f)
        except Exception as exc:
            print("Error: Exception occurred while opening config file: {}! "
                  "Falling back to default config.".format(exc, CONFIG_FILE))
            cfg = DEFAULT_CONFIG
            pass

    return cfg

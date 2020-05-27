import copy
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
    "hive_api_key": "SuGd5Aj4NNudH8unh5CpWLm4U/MYDeVc",
    "listener_bind_host": "0.0.0.0",
    "listener_bind_port": 5001,
    "datetime_format": "%Y-%m-%d %H:%M:%SZ",
    "git_username": "",
    "git_email": "",
    "git_commit_msg_fmt": "Update YARA Rule: {rulename}",
    "git_datetime_custom_fmt": "%a %b %d %H:%M:%S %Y %z",
    "theoracle_server": "127.0.0.1",
    "theoracle_port": 22,
    "theoracle_user": "git",
    "theoracle_remote_repo": "",
    "theoracle_local_path": "the-oracle",
    "theoracle_repo_rules_dir": "rules"
}

# Let's make sure we copy default config by value, not reference. So that it remains unmodified.
CONFIG = copy.deepcopy(DEFAULT_CONFIG)


def has_option(cfg: json, cfg_key: str):
    if cfg_key in cfg:
        return True

    return False


def get_option(key, default=None):
    if key in CONFIG:
        return CONFIG[key]
    else:
        return default


def has_custom_config(config_file=CONFIG_FILE):
    if os.path.isfile(config_file):
        return True
    else:
        return False


def update_sample_config(sample_config=SAMPLE_CONFIG_FILE):
    with open(sample_config, 'w') as f:
        json.dump(DEFAULT_CONFIG, f, indent=4)


def set_custom_config_options(cfg: json):
    global CONFIG

    for key, value in cfg.items():
        CONFIG[key] = value


def load_config(config_file=CONFIG_FILE):
    global CONFIG

    # Create a sample config file.
    update_sample_config()

    # If config file doesn't exist
    if has_custom_config():
        try:
            with open(config_file) as f:
                # Override config options with those defined in the custom config file.
                set_custom_config_options(json.load(f))
        except Exception as exc:
            print("Error: Exception occurred while opening config file: {}! "
                  "Falling back to default config.".format(exc, config_file))
            pass

    return CONFIG

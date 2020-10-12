import copy
import json
import os

CONFIG_FILE = "config.json"
SAMPLE_CONFIG_FILE = "config.json.sample"
DEFAULT_CONFIG = {
    # Debug
    "debug": False,
    # Logging
    "log_to_file": False,
    "log_level": 1,
    "logging_port": 19995,
    "logging_dir": "logs/",
    # YARA
    "yara_ignore_compiler_errors": False,
    # TheHive
    "hive_server": "127.0.0.1",
    "hive_port": 9000,
    "hive_api_key": "SuGd5Aj4NNudH8unh5CpWLm4U/MYDeVc",
    "hive_case_meta_fields": ["createdBy", "owner", "description", "id", "title", "pap", "tlp"],
    "hive_case_string_fields": [],
    # Own Flask server
    "listener_bind_host": "0.0.0.0",
    "listener_server_name": "localhost:5001",
    "listener_application_root": "/",
    "listener_bind_port": 5001,
    # Utils
    "datetime_format": "%Y-%m-%d %H:%M:%SZ",
    # Git (wrapped GitPy)
    "git_username": "",
    "git_email": "",
    "git_commit_msg_fmt": "Update YARA Rule: {rulename}",
    "git_datetime_custom_fmt": "%a %b %d %H:%M:%S %Y %z",
    "git_add_forcibly": True,
    "git_checkout_forcibly": True,
    "git_push_forcibly": False,
    "git_pull_forcibly": False,
    # TheOracle Git repository
    "theoracle_server": "127.0.0.1",
    "theoracle_port": 22,
    "theoracle_user": "git",
    "theoracle_repo": "",
    "theoracle_local_path": "the-oracle",
    "theoracle_repo_rules_dir": "rules"
}

# Let's make sure we copy default config by value, not reference. So that it remains unmodified.
CONFIG = copy.deepcopy(DEFAULT_CONFIG)

CONFIG_OVERRIDES = {}


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
    global CONFIG, CONFIG_OVERRIDES

    for key, value in cfg.items():
        CONFIG[key] = value

        # Update record of what overrides have been applied.
        CONFIG_OVERRIDES[key] = value


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

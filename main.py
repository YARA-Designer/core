from flask import Flask

from handlers import config_handler
from listener import api

if __name__ == "__main__":
    # Get config
    config = config_handler.load_config()

    app = Flask(__name__)
    app.config["DEBUG"] = True

    app.add_url_rule(config["hive_listener_endpoint"], methods=['POST'], view_func=api.create_yara_whitelist_rule)

    app.run(host=config["listener_bind_host"], port=config["listener_bind_port"])

from flask import Flask

from handlers import config_handler
from listener import api
import webserver
from database import init_db

if __name__ == "__main__":
    # Get config
    config = config_handler.load_config()

    # Initialize database
    init_db()

    # Set up Flask
    app = Flask(__name__)
    app.config["DEBUG"] = True

    # Add TheHive listener endpoint
    app.add_url_rule(config["hive_listener_endpoint"], methods=['POST'], view_func=api.create_yara_whitelist_rule)

    # Add root endpoint for frontend Web GUI
    app.add_url_rule('/', view_func=webserver.home)

    # Add other useful routes
    # -- Listing of all pending rules.
    app.add_url_rule('/list', view_func=webserver.list_pending_rules)
    # -- Page to create yara rules on.
    app.add_url_rule('/new_yara_rule', view_func=webserver.new_rule)
    # -- Page to receive POST request from new_yara_rule so it can be processed by the codebase.
    app.add_url_rule('/post_yara_rule', view_func=webserver.post_rule, methods=['POST'])

    # Run the Flask Webserver.
    app.run(host=config["listener_bind_host"], port=config["listener_bind_port"])

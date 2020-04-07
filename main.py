from flask import Flask

from handlers import config_handler
from listener import api
import webserver
from database import init_db


def utility_functions():
    def print_in_console(message):
        print(str(message))

    return dict(mdebug=print_in_console)


def filter_suppress_none(val):
    """
    A filter that prevents Jinja2 from printing "None" when executing code with no return value.

    This filter will return/print an empty string instead of None,
    so no actual extra (garbage) text gets added to the HTML.

    :param val:
    :return:
    """
    if val is not None:
        return val
    else:
        return ''


if __name__ == "__main__":
    # Get config
    config = config_handler.load_config()

    # Initialize database
    init_db()

    # Set up Flask
    app = Flask(__name__)
    app.config["DEBUG"] = True

    # Add utility functions like print_in_console ('mdebug' in Jinja2 code)
    app.context_processor(utility_functions)

    # Add filters
    app.jinja_env.filters['ignore_none'] = filter_suppress_none

    # Add TheHive listener endpoint
    app.add_url_rule(config["hive_listener_endpoint"], methods=['POST'], view_func=api.create_yara_whitelist_rule)

    # Add other useful routes
    # -- Listing of all pending rules.
    app.add_url_rule('/list', view_func=webserver.list_pending_rules)
    webserver.routes['/list'] = "List all rules pending creation."

    # -- Page containing both raw rule cli and the designer.
    app.add_url_rule('/yara_rule', view_func=webserver.new_rule)
    webserver.routes['/yara_rule'] = "Create Yara rule"

    # -- Page to create raw yara rules on.
    app.add_url_rule('/yara_rule_raw', view_func=webserver.new_rule_raw, methods=['GET', 'POST'])
    webserver.routes['/yara_rule_raw'] = "Create Yara rule using only raw CLI"

    # -- Page to design yara rules on.
    app.add_url_rule('/yara_rule_designer', view_func=webserver.new_rule_designer, methods=['GET', 'POST'])
    webserver.routes['/yara_rule_designer'] = "Create Yara rule using only the designer"

    # -- Page to receive POST request from new_yara_rule so it can be processed by the codebase.
    app.add_url_rule('/post_yara_rule_imd', view_func=webserver.post_rule_raw_imd, methods=['POST'])
    app.add_url_rule('/post_yara_rule_json', view_func=webserver.post_rule_json, methods=['POST'])

    # Add root endpoint for frontend Web GUI (last to account for polulating of route list)
    app.add_url_rule('/', view_func=webserver.home)

    # Run the Flask Webserver.
    app.run(host=config["listener_bind_host"], port=config["listener_bind_port"])

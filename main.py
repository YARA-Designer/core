from datetime import date

from flask import Flask
from flask.json import JSONEncoder
from flask_cors import CORS

from handlers import config_handler, webserver
from handlers.log_handler import create_logger
import handlers.git_handler as git
from listener import api
from database import init_db

log = create_logger(__name__)
log_utility_functions = create_logger("{}.utility_functions".format(__name__))


class MyJSONEncoder(JSONEncoder):
    def default(self, o):
        # Override Flask JSONEncoder's date serializer (RFC 1123) to use ISO8601..
        if isinstance(o, date):
            return o.isoformat()

        return super().default(o)


class MyFlask(Flask):
    json_encoder = MyJSONEncoder


def utility_functions():
    def print_in_console(message):
        print(str(message))

    def print_in_log(message):
        log_utility_functions.debug(str(message))

    return dict(mdebug=print_in_console, log=print_in_log)


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


def get_flask_rule_by_name(name: str):
    for r in app.url_map.iter_rules():
        if r.rule == name:
            return r


def log_added_route(name: str, include_obj=True):
    rule = get_flask_rule_by_name(name)
    log.info("Added TheHive listener Flask App route '{rule}': "
             "view_func: {endpoint}, methods: {methods}".format(**rule.__dict__))

    if include_obj is True:
        log.debug2(rule.__dict__)


def add_app_route(flask_app: Flask, route: str, **kwargs):
    """
    Expand route adding to also update webserver routes dict and log action.

    :param flask_app:   A Flask app handle.
    :param route:       Route pathname.
    :param kwargs:      Additional Flask app kwargs.
    :return:
    """
    flask_app.add_url_rule(route, **kwargs)
    log_added_route(route)


if __name__ == "__main__":
    # Get config.
    config = config_handler.load_config()
    log.info("Loaded configuration: '{}'.".format(
        config_handler.CONFIG_FILE if config_handler.has_custom_config() else 'default'))

    # Initialize database.
    init_db()
    log.info("Initialized database.")

    # Set up TheOracle Git.
    webserver.the_oracle_repo = git.clone_if_not_exist(url=config["theoracle_repo"], path=config["theoracle_local_path"])

    # Set up Flask.
    app = MyFlask(__name__)
    log.info("Configured Flask app.")
    CORS(app)

    # Add utility functions like print_in_console ('mdebug' in Jinja2 code)
    app.context_processor(utility_functions)
    log.info("Added Flask app context processor utility functions: {}.".format(
        [str(func) for func in utility_functions.__call__()]))

    # Add filters.
    app.jinja_env.filters['ignore_none'] = filter_suppress_none
    log.info("Added Flask app Jinja2 filters: ['ignore_none'].")

    # Add TheHive listener endpoint.
    app.add_url_rule(config["hive_listener_endpoint"], methods=['POST'], view_func=api.create_yara_whitelist_rule)
    log_added_route(config["hive_listener_endpoint"])

    # -- Page to design yara rules on (root endpoint for frontend Web GUI).
    # add_app_route(app, '/', view_func=webserver.new_rule_designer, methods=['GET', 'POST'])

    # -- Pages to receive POST request from new_yara_rule so it can be processed by the codebase.
    add_app_route(app, '/post_yara_rule_json', view_func=webserver.post_rule_json, methods=['POST'])
    add_app_route(app, '/post_yara_commit_json', view_func=webserver.post_commit_json, methods=['POST'])
    add_app_route(app, '/post_get_rule_request', view_func=webserver.post_get_rule_request, methods=['POST'])

    # -- Pages to receive GET requests on.
    add_app_route(app, '/get_rules_request', view_func=webserver.get_rules_request, methods=['GET'])

    # Run the Flask Webserver.
    log.info("Starting Flask App Webserver, listening on: {host}:{port}".format(
        host=config["listener_bind_host"], port=config["listener_bind_port"]))
    app.run(host=config["listener_bind_host"], port=config["listener_bind_port"], debug=True)

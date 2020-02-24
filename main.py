from flask import Flask
from listener import api

if __name__ == "__main__":
    app = Flask(__name__)
    app.config["DEBUG"] = True

    app.add_url_rule('/YaraWhitelistRuleCreator', methods=['POST'], view_func=api.create_yara_whitelist_rule)

    app.run(host="0.0.0.0", port=5001)

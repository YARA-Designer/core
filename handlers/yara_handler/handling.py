import os

import yara

from handlers import config_handler
from handlers.log_handler import create_logger
from handlers.yara_handler.yara_rule import YaraRule, YaraRuleSyntaxError
from handlers.yara_handler.utils import sanitize_identifier

# Get config

config = config_handler.load_config()

log = create_logger(__name__)
SOURCE_FILE_EXTENSION = ".yar"
COMPILED_FILE_EXTENSION = ".bin"
CALLBACK_DICTS: list = []
CONDITION_INDENT_LENGTH = 8

RETV_BASE_STRUCTURE = {
    "source": None,
    "success": False,
    "compilable": False,
    "error": {
        "type": None,
        "message": "",
        "line_number": None,
        "column_number": None,
        "word": None
    },
}


def compile_from_source(yara_sources_dict: dict, error_on_warning=True, keep_compiled=False, **kwargs) -> dict:
    """
    Generates a YARA rule based on a given dict on the form of:
    {
        rule: str,
        tags: List[str],
        meta: {identifier: value},
        observables: {identifier: value},
        condition: str
    }.

    :param keep_compiled: Whether or not to keep compiled binary files.
    :param error_on_warning: If true warnings are treated as errors, raising an exception.
    :param yara_sources_dict:
    :return:
    """
    retv = RETV_BASE_STRUCTURE

    rule = YaraRule.from_dict(yara_sources_dict)

    try:
        retv["source"] = rule.__str__()
        log.debug("source: \n{}".format(retv["source"]))    # FIXME: DEBUG

        # Save rule source code to text file and store the returned filepath for use in frontend.
        retv["generated_yara_source_file"] = rule.save_source()

        try:
            rule.compile(save_file=True)
            retv["compilable"] = True
        except YaraRuleSyntaxError as syn_exc:
            retv["success"] = False
            retv["error"] = {"type": "syntax_error", "message": str(syn_exc)}
            log.exception("YaraRuleSyntaxError Exception!", exc_info=syn_exc)

            return retv

        # Create YaraRule from the compiled file in order to run it against yara.Match.
        rule_from_binary: YaraRule = YaraRule.from_compiled_file(rule.name)

        if not keep_compiled:
            path = os.path.join(config["theoracle_local_path"], config["theoracle_repo_rules_dir"],
                                rule.name + COMPILED_FILE_EXTENSION)
            log.info("Removing compiled YARA binary: {}".format(path))
            os.remove(path)
            rule_from_binary.compiled_blob = None

        retv["success"] = True

    except yara.Error as e:
        retv["success"] = False
        retv["error"] = {"type": "error", "message": str(e)}
        log.exception("YARA Error Exception!", exc_info=e)
        pass
    except Exception as e:
        retv["success"] = False
        retv["error"] = {"type": "exception", "message": str(e)}
        log.exception("Unexpected Exception!", exc_info=e)
        pass

    return retv


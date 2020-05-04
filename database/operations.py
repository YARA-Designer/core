import json

from sqlalchemy.exc import SQLAlchemyError

from database import db_session
from database.models import Rule
from handlers.log_handler import create_logger
from utils import dict_to_json

log = create_logger(__name__)


def add_row(db_row):
    # Create a Session
    session = db_session()
    try:
        session.add(db_row)
        session.commit()
    except SQLAlchemyError:
        session.rollback()
        raise
    finally:
        session.close()


def update_rule(case_id: str, **kwargs):
    # Create a Session
    session = db_session()
    try:
        rule = session.query(Rule).filter(Rule.case_id == case_id).one()

        rule.update_last_modified()

        for attr, value in kwargs.items():
            if hasattr(rule, attr):
                log.debug("rule (cid={cid}) has attr: '{attr}'".format(cid=case_id, attr=attr))
                if getattr(rule, attr) != value:
                    log.debug("rule (cid={cid}) attr: '{attr}' != value={value}".format(cid=case_id, attr=attr,
                                                                                        value=value))

                    log.info("Rule({cid}).{attr} = {value}".format(cid=case_id, attr=attr, value=value))
                    setattr(rule, attr, value)
                else:
                    log.debug("rule (cid={cid}) attr: '{attr}' == value={value}".format(cid=case_id, attr=attr,
                                                                                        value=value))

        session.commit()
    except SQLAlchemyError:
        session.rollback()
        raise
    finally:
        session.close()


def get_rule(case_id: str) -> dict:
    session = db_session()

    try:
        # Get the first item in the list of queries
        rule_dict: dict = session.query(Rule).filter(Rule.case_id == case_id)[0].as_dict()

        # Commit transaction (NB: makes detached instances expire)
        session.commit()
    except SQLAlchemyError:
        raise
    finally:
        session.close()

    return rule_dict


def get_rules() -> list:
    rules = []
    session = db_session()

    try:
        for rule in session.query(Rule).all():
            rules.append(rule.as_dict())
            log.debug("get_rules rule: {}".format(json.dumps(dict_to_json(rule.as_dict()), indent=4)))

        # Commit transaction (NB: makes detached instances expire)
        session.commit()
    except SQLAlchemyError:
        raise
    finally:
        session.close()

    return rules

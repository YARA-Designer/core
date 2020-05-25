import json

from sqlalchemy.exc import SQLAlchemyError

from database import db_session
from database.models import Rule
from handlers.log_handler import create_logger
from utils import dict_to_json

log = create_logger(__name__)


def add_row(db_row):
    """
    Add a new database row.

    :param db_row:
    :return:
    """
    # Create a Session
    session = db_session()
    try:
        log.info("Add DB row: {db_row}.".format(db_row=db_row))
        session.add(db_row)

        session.commit()
    except SQLAlchemyError:
        log.exception("An unexpected SQLAlchemyError Exception occurred!", exc_info=SQLAlchemyError)

        session.rollback()

        raise
    finally:
        session.close()


def has_row(db_obj, **filter_by) -> bool:
    """
    Checks if a row already exists in the DB.

    :param filter_by: kwarg on the form: key='val'
    :param db_obj: A database object.
    :return:
    """
    # Create a Session
    session = db_session()
    try:
        exists = session.query(db_obj).filter_by(**filter_by).scalar() is not None
        log.debug("Row exists for {db_obj}?: {result}".format(db_obj=db_obj, result=exists))

        return exists
    except SQLAlchemyError:
        log.exception("An unexpected SQLAlchemyError Exception occurred!", exc_info=SQLAlchemyError)

        session.rollback()

        raise
    finally:
        session.close()


def update_rule(case_id: str, update_attrs: dict = None, **kwargs):
    """
    Update given attributes in an existing Rule row.

    Attributes can be given by kwargs or an update_attrs dict
    (useful when sending kwargs on the form of a dict).

    :param case_id:         Case ID (used to identify row)
    :param update_attrs:    A dict of attributes to update (if None, use kwargs)
    :param kwargs:          A list of keyword arguments with attributes to update
                            (only used if update_attrs is None)
    :return:
    """
    log.info("Updating Rule with case ID: {case_id}...".format(case_id=case_id))

    if update_attrs:
        attrs = update_attrs
        log.debug("Got update_attrs: {update_attrs}".format(update_attrs=update_attrs))
    else:
        attrs = kwargs
        log.debug("Got kwargs: {kwargs}".format(kwargs=kwargs))

    # Create a Session
    session = db_session()

    try:
        rule = session.query(Rule).filter(Rule.case_id == case_id).one()

        rule.update_last_modified()

        for attr, value in attrs.items():
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
        log.exception("An unexpected SQLAlchemyError Exception occurred!", exc_info=SQLAlchemyError)

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
        log.exception("An unexpected SQLAlchemyError Exception occurred!", exc_info=SQLAlchemyError)

        session.rollback()

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
        log.exception("An unexpected SQLAlchemyError Exception occurred!", exc_info=SQLAlchemyError)

        session.rollback()

        raise
    finally:
        session.close()

    return rules

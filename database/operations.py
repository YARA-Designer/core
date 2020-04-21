from sqlalchemy.exc import SQLAlchemyError

from database import db_session
from database.models import Rule
from handlers.log_handler import create_logger

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

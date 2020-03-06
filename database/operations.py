from database import db_session


def add_row(db_row):
    # Create a Session
    session = db_session()
    try:
        session.add(db_row)
        session.commit()
    except:
        session.rollback()
        raise
    finally:
        session.close()

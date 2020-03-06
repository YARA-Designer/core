import datetime

from sqlalchemy import Column, Integer, JSON, DateTime, VARCHAR
from database import Base


class PendingRule(Base):
    __tablename__ = 'pending_rules'
    id = Column(Integer, primary_key=True)
    case_id = Column(VARCHAR)
    added_on = Column(DateTime)
    data = Column(JSON)

    def __init__(self, data):
        self.data = data
        self.case_id = data['id']
        self.added_on = datetime.datetime.utcnow()

    def __repr__(self):
        return "<PendingRule(id='{}', data='{}')>".format(self.id, self.data)

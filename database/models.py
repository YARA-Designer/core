import datetime

from sqlalchemy import Column, Integer, JSON, DateTime, VARCHAR, Boolean
from database import Base


class Rule(Base):
    __tablename__ = 'rules'
    id = Column(Integer, primary_key=True)
    case_id = Column(VARCHAR)
    added_on = Column(DateTime)
    last_modified = Column(DateTime)
    data = Column(JSON)
    pending = Column(Boolean)
    yara_file = Column(VARCHAR)

    def __init__(self, data, yara_file=None):
        self.data = data
        self.case_id = data['id']
        self.added_on = datetime.datetime.utcnow()
        self.last_modified = datetime.datetime.utcnow()
        self.yara_file = yara_file

    def __repr__(self):
        return "<Rule(id='{my_id}', yara_file='{yara_file}, data='{data}')>".format(my_id=self.id, data=self.data,
                                                                                    yara_file=self.yara_file)

    def update_last_modified(self):
        self.last_modified = datetime.datetime.utcnow()

    def as_dict(self):
        return {"data": self.data, "case_id": self.case_id, "added_on": self.added_on,
                "last_modified": self.last_modified, "yara_file": self.yara_file, "pending": bool(self.pending)}

import datetime
from typing import List, Union

from sqlalchemy import Column, Integer, DateTime, VARCHAR, Boolean, Table, ForeignKey
from sqlalchemy.orm import relationship, backref, Query

from database import Base
from handlers.log_handler import create_logger

from yara_toolkit.yara_meta import YaraMeta
from yara_toolkit.yara_string import YaraString, YaraStringModifier
from yara_toolkit.utils import delimiter_wrap_type

# YARA:
YARA_VAR_SYMBOL = "$"

# String types
TEXT_TYPE = "text"
HEX_TYPE = "hex"
REGEX_TYPE = "regex"

# Value types
VALUE_TYPES = ["str", "int", "bool"]
STRING_TYPES = [TEXT_TYPE, HEX_TYPE, REGEX_TYPE]

# Modifier (constant) definitions
NO_CASE = "nocase"
WIDE = "wide"
ASCII = "ascii"
XOR = "xor"
BASE64 = "base64"
BASE64_WIDE = "base64wide"
FULL_WORD = "fullword"
PRIVATE = "private"

YARA_RULE_DB_RELATION_COLUMNS = ["tags", "meta", "strings"]

log = create_logger(__name__)

# Association tables that are used for many-to-many relationships.
yara_tag_association_table: Table = Table(
    'tag_association', Base.metadata,
    Column('tag_id', Integer, ForeignKey('tag.id'), primary_key=True),
    Column('rule_id', Integer, ForeignKey('rule.id'), primary_key=True)
)

yara_meta_association_table: Table = Table(
    'meta_association', Base.metadata,
    Column('meta_id', Integer, ForeignKey('meta.id'), primary_key=True),
    Column('rule_id', Integer, ForeignKey('rule.id'), primary_key=True)
)

yara_string_association_table: Table = Table(
    'string_association', Base.metadata,
    Column('string_id', Integer, ForeignKey('string.id'), primary_key=True),
    Column('rule_id', Integer, ForeignKey('rule.id'), primary_key=True)
)

yara_string_modifier_association_table: Table = Table(
    'string_modifier_association', Base.metadata,
    Column('string_modifier_id', Integer, ForeignKey('string_modifier.id'), primary_key=True),
    Column('string_id', Integer, ForeignKey('string.id'), primary_key=True)
)


class YaraTagDB(Base):
    __tablename__ = 'tag'
    id = Column(Integer, primary_key=True)
    name = Column(VARCHAR)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return "<YaraTag(id='{my_id}', name='{name}')>".format(name=self.name, my_id=self.id)

    def as_dict(self):
        return {"name": self.name}


class YaraMetaDB(Base):
    __tablename__ = 'meta'
    id = Column(Integer, primary_key=True)
    identifier = Column(VARCHAR)
    value = Column(VARCHAR)
    value_type = Column(VARCHAR)  # bool, string or int

    def __init__(self, identifier, value, value_type):
        self.identifier = identifier
        self.value = value
        self.value_type = value_type

    def __repr__(self):
        return "<YaraMeta(id='{my_id}', identifier='{identifier}, value='{value}', value_type='{value_type}')>".format(
            my_id=self.id, identifier=self.identifier, value=self.value, value_type=self.value_type)

    def __str__(self):
        return "{identifier} = {value}".format(
            identifier=self.identifier, value=delimiter_wrap_type(self.value, self.value_type))

    def as_dict(self):
        return {"identifier": self.identifier, "value": self.value, "value_type": self.value_type}


class YaraStringModifierDB(Base):
    __tablename__ = 'string_modifier'
    id = Column(Integer, primary_key=True)
    keyword = Column(VARCHAR)
    value = Column(VARCHAR)

    def __init__(self, keyword, value: str = None):
        self.keyword = keyword
        self.value = value

    def __repr__(self):
        return "<YaraStringModifierDB(id='{my_id}', keyword='{keyword}, value='{value}'')>".format(
            my_id=self.id, keyword=self.keyword, value=self.value)

    def __str__(self):
        return "{keyword}{value}".format(
            keyword=self.keyword, value="({})".format(self.value) if self.value else "")

    def as_dict(self):
        return {"keyword": self.keyword, "value": self.value}


class YaraStringDB(Base):
    __tablename__ = 'string'
    id = Column(Integer, primary_key=True)
    identifier = Column(VARCHAR)
    value = Column(VARCHAR)
    value_type = Column(VARCHAR)  # bool, string or int
    string_type = Column(VARCHAR)  # text, hex or regex
    modifiers = relationship(
        'YaraStringModifierDB', secondary=yara_string_modifier_association_table, lazy='subquery',
        backref=backref('yara_strings', lazy=True))

    def __init__(self, identifier: str, value: str,
                 value_type: str = "str", string_type: str = TEXT_TYPE,
                 modifiers: List[Union[YaraStringModifier, dict]] = None):

        self.identifier = identifier
        self.value = value
        if value_type not in VALUE_TYPES:
            raise ValueError("Error {this}.value_type needs to be one of [{types}]".format(
                this=self.__class__.__name__, types=','.join(VALUE_TYPES)))
        self.value_type = value_type
        if value_type not in VALUE_TYPES:
            raise ValueError("Error {this}.string_type needs to be one of [{types}]".format(
                this=self.__class__.__name__, types=','.join(STRING_TYPES)))
        self.string_type = string_type

        # Modifiers
        for m in modifiers:
            if isinstance(m, YaraStringModifier):
                self.modifiers.append(YaraStringModifierDB(m.keyword, m.data))
            elif isinstance(m, dict):
                self.modifiers.append(YaraStringModifierDB(**m))
            else:
                raise ValueError(
                    "YARA-String-Modifier object is neither YaraStringModifier nor dict: {obj}".format(obj=m))

    def modifier_str(self):
        """ Return whitespace-delimited string of all True modifiers. """
        return ' '.join([str(m) for m in self.modifiers])

    def __repr__(self):
        return "<YaraStringDB(id='{my_id}', identifier='{identifier}, value='{value}', value_type='{value_type}')>".format(
            my_id=self.id, identifier=self.identifier, value=self.value, value_type=self.value_type)

    def __str__(self):
        return '{var_sym}{identifier} = {value}{modifiers}'.format(
            var_sym=YARA_VAR_SYMBOL, identifier=self.identifier,
            value=delimiter_wrap_type(self.value, self.value_type),
            modifiers=" {}".format(self.modifier_str()))

    def as_dict(self):
        return {
            "identifier": self.identifier,
            "value": self.value,
            "value_type": self.value_type,
            "string_type": self.string_type,
            "modifiers": self.modifiers,
            "modifier_str": self.modifier_str(),
            "str": self.__str__()
        }


class YaraRuleDB(Base):
    __tablename__ = 'rule'
    id = Column(Integer, primary_key=True)
    thehive_case_id = Column(VARCHAR)
    added_on = Column(DateTime)
    last_modified = Column(DateTime)
    name = Column(VARCHAR)
    title = Column(VARCHAR)
    description = Column(VARCHAR)
    tags = relationship(
        'YaraTagDB', secondary=yara_tag_association_table, lazy='subquery', backref=backref('yara_rules', lazy=True))
    meta = relationship(
        'YaraMetaDB', secondary=yara_meta_association_table, lazy='subquery', backref=backref('yara_rules', lazy=True))
    strings = relationship(
        'YaraStringDB', secondary=yara_string_association_table, lazy='subquery', backref=backref('yara_rules', lazy=True))
    condition = Column(VARCHAR)
    namespace = Column(VARCHAR)
    pending = Column(Boolean)
    source_path = Column(VARCHAR)
    compilable = Column(Boolean)

    def __init__(self,
                 name: str = None,
                 title: str = None,
                 description: str = None,
                 thehive_case_id: str = None,
                 tags: list = None,
                 meta: List[Union[YaraMeta, dict]] = None,
                 strings: list = None,
                 condition: str = None,
                 namespace: str = None,
                 source_path: str = None,
                 compilable: bool = False,
                 pending: bool = True):

        self.added_on = datetime.datetime.utcnow()
        self.last_modified = datetime.datetime.utcnow()
        self.thehive_case_id = thehive_case_id

        self.name = name
        self.title = title
        self.description = description
        self.set_tags(tags)
        self.set_meta(meta)
        self.set_strings(strings)

        self.condition = condition
        self.namespace = namespace
        self.source_path = source_path
        self.compilable = compilable
        self.pending = pending

    def set_tags(self, tags: List[str], session=None):
        """
        Replaces tags in the association table with the ones given.

        :param tags:        List of tags.
        :param session:     If provided, check if row(s) already exist, to avoid dupe entries.
        :return:
        """
        new_tags = []

        if session:
            # Check if the attr row already exists in DB (avoid dupes)
            for tag in tags:
                # Get DB row.
                db_query = session.query(YaraTagDB).filter_by(name=tag)

                # Append existing if exist else append a new DB row.
                new_tags.append(db_query.one()) if db_query.scalar() else new_tags.append(YaraTagDB(tag))
        else:
            # If no session is given, no existence checks can be performed; Append new DB rows.
            new_tags = [YaraTagDB(t) for t in tags]

        self.tags = new_tags

    def set_meta(self, meta: List[Union[YaraMeta, dict]], session=None):
        """
        Replaces tags in the association table with the ones given.

        :param meta:        List of string objects (YaraMetaDB or dict (see: YaraMetaDB.as_dict)).
        :param session:     If provided, check if row(s) already exist, to avoid dupe entries.
        :return:
        """
        # Clear old rows.
        self.meta = []

        if session:
            for m in meta:
                if isinstance(m, YaraMeta):
                    identifier = m.identifier
                    value = m.value
                    value_type = m.type
                elif isinstance(m, dict):
                    identifier = m["identifier"]
                    value = m["value"]
                    value_type = m["value_type"]
                else:
                    raise ValueError("YARA-Meta object is neither YaraMeta nor dict: {obj}".format(obj=m))

                # Get row matching meta obj (if any).
                associated_row_query: Query = session.query(
                    YaraMetaDB).join(
                    yara_meta_association_table).filter(
                    (yara_meta_association_table.c.meta_id) &
                    (yara_meta_association_table.c.rule_id == self.id) &
                    (YaraMetaDB.identifier == identifier)
                )

                # Append existing if exist else append a new DB row.
                if associated_row_query.scalar():
                    self.meta.append(associated_row_query.one())
                else:
                    self.meta.append(YaraMetaDB(identifier, value, value_type))
        else:
            # If no session is given, no existence checks can be performed; Append new DB rows.
            for m in meta:
                if isinstance(m, YaraMeta):
                    self.meta.append(YaraMetaDB(m.identifier, m.value, m.type))
                elif isinstance(m, dict):
                    self.meta.append(YaraMetaDB(**m))
                else:
                    raise ValueError("YARA-Meta object is neither YaraMeta nor dict: {obj}".format(obj=m))

    def set_strings(self, strings: List[Union[YaraString, dict]], session=None):
        """
        Replaces tags in the association table with the ones given.

        :param strings:     List of string objects (YaraString or dict (see: YaraStringDB.as_dict)).
        :param session:     If provided, check if row(s) already exist, to avoid dupe entries.
        :return:
        """
        # Clear old rows.
        self.strings = []

        if session:
            for s in strings:
                if isinstance(s, YaraString):
                    identifier = s.identifier
                    value = s.value
                    value_type = type(s.value).__name__
                    string_type = s.type
                    modifiers = s.modifiers
                elif isinstance(s, dict):
                    identifier = s["identifier"]
                    value = s["value"]
                    value_type = s["value_type"]
                    string_type = s["string_type"]
                    modifiers = s["modifiers"]
                else:
                    raise ValueError("YARA-String object is neither YaraString nor dict: {obj}".format(obj=s))

                # Get row matching meta obj (if any).
                associated_row_query: Query = session.query(
                    YaraStringDB).join(
                    yara_string_association_table).filter(
                    (yara_string_association_table.c.string_id) &
                    (yara_string_association_table.c.rule_id == self.id) &
                    (YaraStringDB.identifier == identifier)
                )

                # Append existing if exist else append a new DB row.
                if associated_row_query.scalar():
                    self.strings.append(associated_row_query.one())
                else:
                    self.strings.append(YaraStringDB(identifier, value, value_type, string_type, modifiers))
        else:
            # If no session is given, no existence checks can be performed; Append new DB rows.
            for s in strings:
                if isinstance(s, YaraString):
                    self.strings.append(YaraStringDB(s.identifier, s.value, type(s.value).__name__, s.type, s.modifiers))
                elif isinstance(s, dict):
                    self.strings.append(YaraStringDB(**s))
                else:
                    raise ValueError("YARA-String object is neither YaraString nor dict: {obj}".format(obj=s))

    def update_last_modified(self):
        self.last_modified = datetime.datetime.utcnow()

    def as_dict(self):
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "thehive_case_id": self.thehive_case_id,
            "namespace": self.namespace,
            "tags": [t.name for t in self.tags],
            "meta": [m.as_dict() for m in self.meta],
            "strings": [s.as_dict() for s in self.strings],
            "condition": self.condition,
            "added_on": self.added_on,
            "last_modified": self.last_modified,
            "source_path": self.source_path,
            "compilable": self.compilable,
            "pending": bool(self.pending)
        }

    def set_relation_attr(self, attr, value, session):
        """setattr helper for complex SQLAlchemy attributes that don't accept simple assignment."""
        if attr == "tags":
            self.set_tags(value, session=session)
        elif attr == "meta":
            self.set_meta(value, session=session)
        elif attr == "strings":
            self.set_strings(value, session=session)
        else:
            msg = "set_relation_attr got unexpected attr: {}".format(attr)
            log.error(msg)
            raise ValueError(msg)

    def __repr__(self):
        return "<{class_name}(id='{id}', " \
               "name='{name}', " \
               "thehive_case_id='{thehive_case_id}', " \
               "namespace='{namespace}, " \
               "tags='{tags}, " \
               "meta='{meta}, " \
               "strings='{strings}, " \
               "condition='{condition}, " \
               "added_on='{added_on}, " \
               "last_modified='{last_modified}, " \
               "source_path='{source_path}, " \
               "compilable='{compilable}, " \
               "pending='{pending})>".format(
                class_name=self.__class__.__name__, id=self.id, **self.as_dict())

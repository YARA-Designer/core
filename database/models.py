import datetime
from typing import List, Union

from sqlalchemy import Column, Integer, DateTime, VARCHAR, Boolean, Table, ForeignKey
from sqlalchemy.orm import relationship, backref

from database import Base

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

# Association tables that are used for many-to-many relationships.
yara_tag_association_table = Table(
    'tag_association', Base.metadata,
    Column('tag_id', Integer, ForeignKey('tag.id'), primary_key=True),
    Column('rule_id', Integer, ForeignKey('rule.id'), primary_key=True)
)

yara_meta_association_table = Table(
    'meta_association', Base.metadata,
    Column('meta_id', Integer, ForeignKey('meta.id'), primary_key=True),
    Column('rule_id', Integer, ForeignKey('rule.id'), primary_key=True)
)

yara_string_association_table = Table(
    'string_association', Base.metadata,
    Column('string_id', Integer, ForeignKey('string.id'), primary_key=True),
    Column('rule_id', Integer, ForeignKey('rule.id'), primary_key=True)
)

yara_string_modifier_association_table = Table(
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
    thehive_case_creator = Column(VARCHAR)
    added_on = Column(DateTime)
    last_modified = Column(DateTime)
    name = Column(VARCHAR)
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

    def __init__(self,
                 name: str,
                 thehive_case_id: str = None,
                 thehive_case_creator: str = None,
                 tags: list = None,
                 meta: List[Union[YaraMeta, dict]] = None,
                 strings: list = None,
                 condition: str = None,
                 namespace: str = None,
                 source_path: str = None):

        self.added_on = datetime.datetime.utcnow()
        self.last_modified = datetime.datetime.utcnow()
        self.thehive_case_id = thehive_case_id
        self.thehive_case_creator = thehive_case_creator

        self.name = name
        self.tags = [YaraTagDB(t) for t in tags]

        for m in meta:
            if isinstance(m, YaraMeta):
                self.meta.append(YaraMetaDB(m.identifier, m.data, m.type))
            elif isinstance(m, dict):
                self.meta.append(YaraMetaDB(**m))
            else:
                raise ValueError("YARA-Meta object is neither YaraMeta nor dict: {obj}".format(obj=m))

        for s in strings:
            if isinstance(s, YaraString):
                self.strings.append(YaraStringDB(s.identifier, s.value, type(s.value).__name__, s.type, s.modifiers))
            elif isinstance(s, dict):
                self.strings.append(YaraStringDB(**s))
            else:
                raise ValueError("YARA-String object is neither YaraString nor dict: {obj}".format(obj=s))

        self.condition = condition
        self.namespace = namespace
        self.source_path = source_path

    def __repr__(self):
        return "<YaraRule(id='{my_id}', yara_file='{yara_file}, data='{data}')>".format(  # FIXME: insert actual attrs
            my_id=self.id, data=self.as_dict(), yara_file=self.source_path)

    def update_last_modified(self):
        self.last_modified = datetime.datetime.utcnow()

    def as_dict(self):
        return {
            "name": self.name,
            "thehive_case_id": self.thehive_case_id,
            "thehive_case_creator": self.thehive_case_creator,
            "namespace": self.namespace,
            "tags": [t.name for t in self.tags],
            "meta": [m.as_dict() for m in self.meta],
            "strings": [s.as_dict() for s in self.strings],
            "condition": self.condition,
            "added_on": self.added_on,
            "last_modified": self.last_modified,
            "source_path": self.source_path,
            "pending": bool(self.pending)
        }

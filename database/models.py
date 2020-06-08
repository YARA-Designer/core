import datetime
from typing import List

from sqlalchemy import Column, Integer, JSON, DateTime, VARCHAR, Boolean
from database import Base


# YARA:
YARA_VAR_SYMBOL = "$"

# String types
from yara_toolkit.utils import delimiter_wrap_type

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


class YaraTagDB(Base):
    __tablename__ = 'yara_tags'
    id = Column(Integer, primary_key=True)
    name = Column(VARCHAR)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return "<YaraTag(id='{my_id}', name='{name}')>".format(name=self.name, my_id=self.id)

    def as_dict(self):
        return {"name": self.name}


class YaraMetaDB(Base):
    __tablename__ = 'yara_meta'
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


class YaraStringDB(Base):
    __tablename__ = 'yara_strings'
    id = Column(Integer, primary_key=True)
    identifier = Column(VARCHAR)
    value = Column(VARCHAR)
    value_type = Column(VARCHAR)  # bool, string or int
    string_type = Column(VARCHAR)  # text, hex or regex

    # Modifiers
    m_no_case = Column(Boolean)
    m_wide = Column(Boolean)
    m_ascii = Column(Boolean)
    m_xor = Column(Boolean)
    m_base64 = Column(Boolean)
    m_base64_wide = Column(Boolean)
    m_full_word = Column(Boolean)
    m_private = Column(Boolean)

    def __init__(self, identifier: str, value: str,
                 value_type: str = "str", string_type: str = TEXT_TYPE,
                 m_no_case: bool = False, m_wide: bool = False, m_ascii: bool = False, m_xor: bool = False,
                 m_base64: bool = False, m_base64_wide: bool = False, m_full_word: bool = False,
                 m_private: bool = False):

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
        self.m_no_case = m_no_case
        self.m_wide = m_wide
        self.m_ascii = m_ascii
        self.m_xor = m_xor
        self.m_base64 = m_base64
        self.m_base64_wide = m_base64_wide
        self.m_full_word = m_full_word
        self.m_private = m_private

    def modifiers(self):
        return {
            NO_CASE: self.m_no_case,
            WIDE: self.m_wide,
            ASCII: self.m_ascii,
            XOR: self.m_xor,
            BASE64: self.m_base64,
            BASE64_WIDE: self.m_base64_wide,
            FULL_WORD: self.m_full_word,
            PRIVATE: self.m_private
        }

    def modifier_str(self):
        """ Return whitespace-delimited string of all True modifiers. """
        return ' '.join([k for k, v in self.modifiers().items() if v])

    def __repr__(self):
        return "<YaraMeta(id='{my_id}', identifier='{identifier}, value='{value}', value_type='{value_type}')>".format(
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
            "modifiers": self.modifiers(),
            "modifier_str": self.modifier_str(),
            "str": self.__str__()
        }


class YaraRuleDB(Base):
    __tablename__ = 'yara_rules'
    id = Column(Integer, primary_key=True)
    thehive_case_id = Column(VARCHAR)
    added_on = Column(DateTime)
    last_modified = Column(DateTime)
    name = Column(VARCHAR)
    description = Column(VARCHAR)
    tags = Column()
    meta = Column(JSON)
    strings = Column(JSON)
    condition = Column(VARCHAR)
    pending = Column(Boolean)
    yara_file = Column(VARCHAR)

    def __init__(self, name: str, tags: List[str] = None, meta: List[YaraMeta] = None,
                 strings: List[YaraString] = None, condition: str = None, namespace: str = None,
                 compiled_blob: yara.Rules = None, compiled_path: str = None,
                 compiled_match_source: bool = None, yara_file=None):
        self.thehive_case_id = data['id']
        self.added_on = datetime.datetime.utcnow()
        self.last_modified = datetime.datetime.utcnow()
        self.yara_file = yara_file

    def __repr__(self):
        return "<YaraRule(id='{my_id}', yara_file='{yara_file}, data='{data}')>".format(
            my_id=self.id, data=self.data, yara_file=self.yara_file)

    def update_last_modified(self):
        self.last_modified = datetime.datetime.utcnow()

    def as_dict(self):
        return {"data": self.data, "case_id": self.thehive_case_id, "added_on": self.added_on,
                "last_modified": self.last_modified, "yara_file": self.yara_file, "pending": bool(self.pending)}

"""DNS record class definitions and utilities.

Defines the standard DNS resource record classes (IN, CH, HS, etc.)
with conversion between numeric values and text mnemonics.
"""

from enum import IntEnum


class RecordClass(IntEnum):
    """DNS resource record classes."""
    RESERVED = 0
    IN = 1
    CH = 3
    HS = 4
    NONE = 254
    ANY = 255


_ALIASES = {
    "INTERNET": RecordClass.IN,
    "CHAOS": RecordClass.CH,
    "HESIOD": RecordClass.HS,
}

_META_CLASSES = frozenset({RecordClass.NONE, RecordClass.ANY})

_text_to_class = {}
_class_to_text = {}

for _member in RecordClass:
    _mname = _member.name
    _text_to_class[_mname.upper()] = _member
    _class_to_text[_member] = _mname

for _alias, _val in _ALIASES.items():
    _text_to_class[_alias] = _val


def class_from_text(text):
    """Convert a text mnemonic or CLASSNN string to a record class value.

    Returns an int (RecordClass enum member if known).
    """
    upper = text.upper()
    result = _text_to_class.get(upper)
    if result is not None:
        return result
    if upper.startswith("CLASS"):
        try:
            val = int(upper[5:])
            if 0 <= val <= 65535:
                try:
                    return RecordClass(val)
                except ValueError:
                    return val
        except ValueError:
            pass
    raise ValueError(f"unknown record class: {text!r}")


def class_to_text(value):
    """Convert a record class value to its text mnemonic.

    Returns the mnemonic like "IN" or "CLASSNN" for unknown classes.
    """
    result = _class_to_text.get(value)
    if result is not None:
        return result
    if isinstance(value, int) and 0 <= value <= 65535:
        return f"CLASS{value}"
    raise ValueError(f"invalid record class value: {value!r}")


def is_meta_class(rclass):
    """Return True if the record class is a meta-class (ANY or NONE)."""
    return rclass in _META_CLASSES

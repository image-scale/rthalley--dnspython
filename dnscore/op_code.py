"""DNS operation codes.

Defines DNS opcodes (QUERY, STATUS, NOTIFY, UPDATE) with conversion
between numeric values, text mnemonics, and DNS message flag fields.
"""

from enum import IntEnum


class OpCode(IntEnum):
    """DNS operation codes."""
    QUERY = 0
    IQUERY = 1
    STATUS = 2
    NOTIFY = 4
    UPDATE = 5


_text_to_opcode = {}
_opcode_to_text = {}

for _member in OpCode:
    _text_to_opcode[_member.name] = _member
    _opcode_to_text[_member] = _member.name


def opcode_from_text(text):
    """Convert a text mnemonic to an opcode value."""
    upper = text.upper()
    result = _text_to_opcode.get(upper)
    if result is not None:
        return result
    raise ValueError(f"unknown opcode: {text!r}")


def opcode_to_text(value):
    """Convert an opcode value to its text mnemonic."""
    result = _opcode_to_text.get(value)
    if result is not None:
        return result
    if isinstance(value, int) and 0 <= value <= 15:
        return str(value)
    raise ValueError(f"invalid opcode value: {value!r}")


def opcode_from_flags(flags):
    """Extract the opcode from the DNS message flags field.

    The opcode occupies bits 11-14 of the 16-bit flags field.
    """
    return (flags & 0x7800) >> 11


def opcode_to_flags(opcode):
    """Encode an opcode into the DNS message flags field position.

    Returns the flags value with the opcode in bits 11-14.
    """
    return (opcode & 0x0F) << 11


def is_update(flags):
    """Return True if the flags indicate an UPDATE opcode."""
    return opcode_from_flags(flags) == OpCode.UPDATE

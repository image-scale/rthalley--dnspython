"""DNS domain name representation and manipulation.

Provides the DomainName class for creating, parsing, comparing, and
manipulating DNS domain names, along with text and wire format conversion.
"""

import struct
from enum import IntEnum

from dnscore.exceptions import SyntaxError as DNSSyntaxError, FormError


class EmptyLabelError(DNSSyntaxError):
    """A DNS label is empty where it shouldn't be."""
    pass


class BadEscapeError(DNSSyntaxError):
    """An escape sequence in DNS name text is invalid."""
    pass


class LabelTooLongError(DNSSyntaxError):
    """A DNS label exceeds the 63-octet limit."""
    pass


class NameTooLongError(FormError):
    """A DNS name exceeds the 255-octet wire length limit."""
    pass


class BadPointerError(FormError):
    """A compression pointer points forward (invalid)."""
    pass


class BadLabelTypeError(FormError):
    """An unknown label type was found in wire format."""
    pass


class AbsoluteConcatError(Exception):
    """Cannot append labels to an absolute name."""
    pass


class NoParentError(Exception):
    """The root or empty name has no parent."""
    pass


class NeedAbsoluteError(Exception):
    """An absolute name or origin is required but not provided."""
    pass


class Relation(IntEnum):
    """Describes the relationship between two DNS names."""
    NONE = 0
    SUPERDOMAIN = 1
    SUBDOMAIN = 2
    EQUAL = 3
    COMMON_ANCESTOR = 4


_SPECIAL_CHARS = b'"().;\\@$'
_SPECIAL_CHARS_STR = '"().;\\@$'


def _escape_label(label):
    """Convert a binary label to escaped text representation."""
    if isinstance(label, bytes):
        result = ""
        for byte_val in label:
            if byte_val in _SPECIAL_CHARS:
                result += "\\" + chr(byte_val)
            elif 0x21 <= byte_val <= 0x7E:
                result += chr(byte_val)
            else:
                result += f"\\{byte_val:03d}"
        return result
    result = ""
    for ch in label:
        if ch in _SPECIAL_CHARS_STR:
            result += "\\" + ch
        elif ord(ch) <= 0x20:
            result += f"\\{ord(ch):03d}"
        else:
            result += ch
    return result


def _check_labels(labels):
    """Validate a tuple of labels for correctness."""
    total_wire_len = 0
    found_empty_at = -1
    for idx, lbl in enumerate(labels):
        lbl_len = len(lbl)
        if lbl_len > 63:
            raise LabelTooLongError(f"label is {lbl_len} octets, max is 63")
        total_wire_len += lbl_len + 1
        if found_empty_at < 0 and lbl == b"":
            found_empty_at = idx
    if total_wire_len > 255:
        raise NameTooLongError(f"name is {total_wire_len} octets, max is 255")
    if found_empty_at >= 0 and found_empty_at != len(labels) - 1:
        raise EmptyLabelError("empty label in the middle of a name")


def _to_binary(label):
    """Ensure a label is bytes."""
    if isinstance(label, bytes):
        return label
    return label.encode()


class DomainName:
    """Immutable representation of a DNS domain name.

    A DNS name is stored as a tuple of binary labels. The root label
    is the empty byte string b"". An absolute name ends with the root label.
    """

    __slots__ = ("_labels", "_hash")

    def __init__(self, labels):
        """Create a DomainName from an iterable of labels (bytes or str)."""
        converted = tuple(_to_binary(lbl) for lbl in labels)
        _check_labels(converted)
        object.__setattr__(self, "_labels", converted)
        object.__setattr__(self, "_hash", None)

    def __setattr__(self, name, value):
        raise AttributeError("DomainName objects are immutable")

    def __delattr__(self, name):
        raise AttributeError("DomainName objects are immutable")

    @property
    def labels(self):
        """The tuple of binary labels making up this name."""
        return self._labels

    def is_absolute(self):
        """Return True if this is an absolute name (ends with root label)."""
        return len(self._labels) > 0 and self._labels[-1] == b""

    def is_wild(self):
        """Return True if this is a wildcard name (first label is '*')."""
        return len(self._labels) > 0 and self._labels[0] == b"*"

    def label_count(self):
        """Return the number of labels in this name."""
        return len(self._labels)

    def __len__(self):
        return len(self._labels)

    def __getitem__(self, index):
        return self._labels[index]

    def __hash__(self):
        cached = object.__getattribute__(self, "_hash")
        if cached is not None:
            return cached
        h = 0
        for lbl in self._labels:
            for byte_val in lbl.lower():
                h += (h << 3) + byte_val
        object.__setattr__(self, "_hash", h)
        return h

    def full_compare(self, other):
        """Compare two names returning (relation, order, common_labels).

        relation: a Relation enum value
        order: negative if self < other, positive if self > other, 0 if equal
        common_labels: number of labels in common from the right
        """
        if not isinstance(other, DomainName):
            raise TypeError(f"cannot compare DomainName with {type(other)}")

        self_abs = self.is_absolute()
        other_abs = other.is_absolute()
        if self_abs != other_abs:
            if self_abs:
                return (Relation.NONE, 1, 0)
            else:
                return (Relation.NONE, -1, 0)

        len1 = len(self._labels)
        len2 = len(other._labels)
        diff = len1 - len2
        min_len = min(len1, len2)

        common = 0
        i1 = len1
        i2 = len2
        for _ in range(min_len):
            i1 -= 1
            i2 -= 1
            lbl1 = self._labels[i1].lower()
            lbl2 = other._labels[i2].lower()
            if lbl1 < lbl2:
                rel = Relation.COMMON_ANCESTOR if common > 0 else Relation.NONE
                return (rel, -1, common)
            elif lbl1 > lbl2:
                rel = Relation.COMMON_ANCESTOR if common > 0 else Relation.NONE
                return (rel, 1, common)
            common += 1

        if diff < 0:
            return (Relation.SUPERDOMAIN, diff, common)
        elif diff > 0:
            return (Relation.SUBDOMAIN, diff, common)
        else:
            return (Relation.EQUAL, 0, common)

    def is_subdomain(self, other):
        """Return True if self is a subdomain of other (includes equality)."""
        rel, _, _ = self.full_compare(other)
        return rel in (Relation.SUBDOMAIN, Relation.EQUAL)

    def is_superdomain(self, other):
        """Return True if self is a superdomain of other (includes equality)."""
        rel, _, _ = self.full_compare(other)
        return rel in (Relation.SUPERDOMAIN, Relation.EQUAL)

    def canonicalize(self):
        """Return a lowercased copy in DNSSEC canonical form."""
        return DomainName([lbl.lower() for lbl in self._labels])

    def __eq__(self, other):
        if isinstance(other, DomainName):
            return self.full_compare(other)[1] == 0
        return False

    def __ne__(self, other):
        if isinstance(other, DomainName):
            return self.full_compare(other)[1] != 0
        return True

    def __lt__(self, other):
        if isinstance(other, DomainName):
            return self.full_compare(other)[1] < 0
        return NotImplemented

    def __le__(self, other):
        if isinstance(other, DomainName):
            return self.full_compare(other)[1] <= 0
        return NotImplemented

    def __gt__(self, other):
        if isinstance(other, DomainName):
            return self.full_compare(other)[1] > 0
        return NotImplemented

    def __ge__(self, other):
        if isinstance(other, DomainName):
            return self.full_compare(other)[1] >= 0
        return NotImplemented

    def __add__(self, other):
        return self.concatenate(other)

    def __sub__(self, other):
        return self.relativize(other)

    def __repr__(self):
        return f"<DomainName {self.to_text()}>"

    def __str__(self):
        return self.to_text()

    def to_text(self, omit_final_dot=False):
        """Convert name to text representation.

        If omit_final_dot is True, the trailing dot for absolute names
        is omitted.
        """
        if len(self._labels) == 0:
            return "@"
        if len(self._labels) == 1 and self._labels[0] == b"":
            return "."
        if omit_final_dot and self.is_absolute():
            parts = self._labels[:-1]
        else:
            parts = self._labels
        return ".".join(_escape_label(lbl) for lbl in parts)

    def to_wire(self, origin=None, compress=None, canonicalize=False):
        """Convert name to DNS wire format.

        If compress is a dict, it is used as a compression table (name -> offset).
        If origin is provided and this name is relative, origin is appended.
        If canonicalize is True, labels are lowercased.

        Returns bytes if compress is None (no file output), otherwise
        this method is designed for simple usage returning bytes.
        """
        labels = list(self._labels)
        if not self.is_absolute():
            if origin is None or not origin.is_absolute():
                raise NeedAbsoluteError(
                    "relative name requires an absolute origin"
                )
            labels.extend(origin._labels)

        out = bytearray()
        for lbl in labels:
            out.append(len(lbl))
            if canonicalize:
                out += lbl.lower()
            else:
                out += lbl
        return bytes(out)

    def concatenate(self, other):
        """Create a new name by appending other's labels to this name.

        Raises AbsoluteConcatError if this name is absolute and other
        is non-empty.
        """
        if not isinstance(other, DomainName):
            raise TypeError(f"cannot concatenate with {type(other)}")
        if self.is_absolute() and len(other) > 0:
            raise AbsoluteConcatError(
                "cannot append to an absolute name"
            )
        return DomainName(list(self._labels) + list(other._labels))

    def relativize(self, origin):
        """If self is a subdomain of origin, return self relative to origin."""
        if not isinstance(origin, DomainName):
            raise TypeError(f"origin must be a DomainName, not {type(origin)}")
        if self.is_subdomain(origin):
            cut = len(origin)
            return DomainName(self._labels[:-cut])
        return self

    def derelativize(self, origin):
        """If self is relative, append origin to make it absolute."""
        if not self.is_absolute():
            return self.concatenate(origin)
        return self

    def parent(self):
        """Return the parent domain name.

        Raises NoParentError for root or empty names.
        """
        if self == ROOT or self == EMPTY:
            raise NoParentError("root and empty names have no parent")
        return DomainName(self._labels[1:])

    def choose_relativity(self, origin=None, relativize=True):
        """Adjust relativity based on origin and relativize flag."""
        if origin is not None:
            if relativize:
                return self.relativize(origin)
            else:
                return self.derelativize(origin)
        return self


ROOT = DomainName([b""])
EMPTY = DomainName([])


def from_text(text, origin=ROOT):
    """Parse a text string into a DomainName.

    text: str or bytes, the DNS name in text form
    origin: DomainName to append to relative names (default: root)

    The "@" symbol represents the empty/origin name.
    Backslash escapes are supported: \\DDD for decimal byte values,
    \\X for literal character X.
    """
    if isinstance(text, bytes):
        text = text.decode("ascii")

    if text == "@":
        text = ""

    if not text:
        if origin is not None:
            return DomainName(list(origin._labels))
        return EMPTY

    if text == ".":
        return DomainName([b""])

    labels = []
    current_label = bytearray()
    escaping = False
    escape_digits = 0
    escape_value = 0

    for ch in text:
        if escaping:
            if escape_digits == 0:
                if ch.isdigit():
                    escape_value = int(ch)
                    escape_digits = 1
                else:
                    current_label.append(ord(ch))
                    escaping = False
            else:
                if not ch.isdigit():
                    raise BadEscapeError("incomplete decimal escape")
                escape_value = escape_value * 10 + int(ch)
                escape_digits += 1
                if escape_digits == 3:
                    if escape_value > 255:
                        raise BadEscapeError(
                            f"decimal escape {escape_value} out of range"
                        )
                    current_label.append(escape_value)
                    escaping = False
        elif ch == ".":
            if len(current_label) == 0:
                raise EmptyLabelError("empty label in name")
            labels.append(bytes(current_label))
            current_label = bytearray()
        elif ch == "\\":
            escaping = True
            escape_digits = 0
            escape_value = 0
        else:
            current_label.append(ord(ch))

    if escaping:
        raise BadEscapeError("incomplete escape at end of name")

    if len(current_label) > 0:
        labels.append(bytes(current_label))
    else:
        labels.append(b"")

    if (len(labels) == 0 or labels[-1] != b"") and origin is not None:
        labels.extend(list(origin._labels))

    return DomainName(labels)


def from_wire(data, offset=0):
    """Parse a DNS name from wire format data.

    Handles compression pointers. Returns (DomainName, bytes_consumed).

    data: bytes containing the DNS message
    offset: starting position in data
    """
    labels = []
    pos = offset
    biggest_pointer = pos
    bytes_consumed = None

    while True:
        if pos >= len(data):
            raise FormError("name extends past end of data")
        length = data[pos]
        pos += 1

        if length == 0:
            labels.append(b"")
            if bytes_consumed is None:
                bytes_consumed = pos - offset
            break
        elif length < 64:
            end = pos + length
            if end > len(data):
                raise FormError("label extends past end of data")
            labels.append(data[pos:end])
            pos = end
        elif length >= 192:
            if pos >= len(data):
                raise FormError("compression pointer incomplete")
            pointer = ((length & 0x3F) << 8) | data[pos]
            pos += 1
            if bytes_consumed is None:
                bytes_consumed = pos - offset
            if pointer >= biggest_pointer:
                raise BadPointerError("compression pointer points forward")
            biggest_pointer = pointer
            pos = pointer
        else:
            raise BadLabelTypeError(f"unknown label type: {length}")

    return DomainName(labels), bytes_consumed

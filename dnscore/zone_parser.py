"""DNS zone file parser.

Parses DNS master file (zone file) text format into structured data:
domain names mapped to record data sets. Supports $ORIGIN, $TTL directives,
and standard resource record syntax.
"""

from dnscore.tokenizer import Tokenizer, TokenKind
from dnscore.domain_name import DomainName, from_text as name_from_text, ROOT
from dnscore.record_type import RecordType, type_from_text
from dnscore.record_class import RecordClass, class_from_text
from dnscore.record_data import create_from_text
from dnscore.record_sets import RRDataSet
from dnscore.ttl import ttl_from_text

_CLASS_NAMES = {"IN", "CH", "HS", "NONE", "ANY", "INTERNET", "CHAOS", "HESIOD"}


def _is_class_token(text):
    """Check if a token looks like a record class."""
    return text.upper() in _CLASS_NAMES or text.upper().startswith("CLASS")


def _is_type_token(text):
    """Check if a token looks like a record type."""
    try:
        type_from_text(text)
        return True
    except ValueError:
        return False


def _is_ttl_token(text):
    """Check if a token looks like a TTL value."""
    if not text:
        return False
    if text[0].isdigit():
        try:
            ttl_from_text(text)
            return True
        except Exception:
            pass
    return False


class ZoneFileEntry:
    """A single parsed zone file entry: name + rdataset."""

    def __init__(self, name, ttl, rdclass, rdtype, rdata):
        self.name = name
        self.ttl = ttl
        self.rdclass = rdclass
        self.rdtype = rdtype
        self.rdata = rdata


def parse_zone_text(text, origin=None, default_ttl=0, rdclass=RecordClass.IN):
    """Parse zone file text into a list of ZoneFileEntry objects.

    text: the zone file content
    origin: the zone origin (DomainName), default is root
    default_ttl: default TTL for records without explicit TTL
    rdclass: default record class

    Returns a list of ZoneFileEntry objects.
    """
    if origin is None:
        origin = ROOT
    if isinstance(origin, str):
        origin = name_from_text(origin)

    tokenizer = Tokenizer(text)
    entries = []
    current_name = origin
    current_ttl = default_ttl

    while True:
        tok = tokenizer.get(want_leading_whitespace=True)

        if tok.is_eof():
            break

        if tok.is_eol():
            continue

        if tok.is_whitespace():
            tok = tokenizer.get()
            if tok.is_eol_or_eof():
                continue
            name = current_name
        else:
            if not tok.is_identifier():
                continue

            value = tok.value

            if value.upper() == "$ORIGIN":
                origin_text = tokenizer.get_identifier()
                origin = name_from_text(origin_text, origin=origin)
                _skip_to_eol(tokenizer)
                continue

            if value.upper() == "$TTL":
                ttl_text = tokenizer.get_identifier()
                current_ttl = ttl_from_text(ttl_text)
                _skip_to_eol(tokenizer)
                continue

            if value == "@":
                name = origin
            else:
                name = name_from_text(value, origin=origin)

            current_name = name
            tok = tokenizer.get()

        if tok.is_eol_or_eof():
            continue

        entry_ttl = current_ttl
        entry_class = rdclass

        token_text = tok.value if tok.is_identifier() else None

        if token_text and _is_ttl_token(token_text):
            entry_ttl = ttl_from_text(token_text)
            tok = tokenizer.get()
            token_text = tok.value if tok.is_identifier() else None

        if token_text and _is_class_token(token_text):
            entry_class = class_from_text(token_text)
            tok = tokenizer.get()
            token_text = tok.value if tok.is_identifier() else None

        if token_text and _is_ttl_token(token_text) and entry_ttl == current_ttl:
            entry_ttl = ttl_from_text(token_text)
            tok = tokenizer.get()
            token_text = tok.value if tok.is_identifier() else None

        if not token_text or not _is_type_token(token_text):
            _skip_to_eol(tokenizer)
            continue

        rdtype = type_from_text(token_text)

        remaining = tokenizer.get_remaining()
        parts = []
        for t in remaining:
            if t.is_quoted_string():
                parts.append(f'"{t.value}"')
            else:
                parts.append(t.value)
        rdata_text = " ".join(parts)

        try:
            rdata = create_from_text(rdtype, rdata_text, origin=origin, rdclass=entry_class)
        except (ValueError, Exception):
            continue

        entries.append(ZoneFileEntry(name, entry_ttl, entry_class, rdtype, rdata))

    return entries


def _skip_to_eol(tokenizer):
    """Skip all tokens until end of line or end of file."""
    while True:
        tok = tokenizer.get()
        if tok.is_eol_or_eof():
            break

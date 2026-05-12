"""Tests for DNS tokenizer and zone file parsing."""

import pytest
from dnscore.tokenizer import Tokenizer, Token, TokenKind
from dnscore.zone_parser import parse_zone_text, ZoneFileEntry
from dnscore.domain_name import from_text as name_from_text
from dnscore.record_type import RecordType
from dnscore.record_class import RecordClass
from dnscore.record_data import ARecord, MXRecord, NSRecord, SOARecord, TXTRecord


class TestTokenizer:
    def test_simple_identifier(self):
        t = Tokenizer("hello")
        tok = t.get()
        assert tok.is_identifier()
        assert tok.value == "hello"

    def test_multiple_identifiers(self):
        t = Tokenizer("hello world")
        tok1 = t.get()
        tok2 = t.get()
        assert tok1.value == "hello"
        assert tok2.value == "world"

    def test_eol(self):
        t = Tokenizer("hello\nworld")
        t.get()
        tok = t.get()
        assert tok.is_eol()
        tok = t.get()
        assert tok.value == "world"

    def test_eof(self):
        t = Tokenizer("")
        tok = t.get()
        assert tok.is_eof()

    def test_quoted_string(self):
        t = Tokenizer('"hello world"')
        tok = t.get()
        assert tok.is_quoted_string()
        assert tok.value == "hello world"

    def test_quoted_with_spaces(self):
        t = Tokenizer('"  spaces  "')
        tok = t.get()
        assert tok.value == "  spaces  "

    def test_semicolon_comment(self):
        t = Tokenizer("hello ; this is a comment\nworld")
        tok1 = t.get()
        assert tok1.value == "hello"
        tok2 = t.get()
        assert tok2.is_eol()
        tok3 = t.get()
        assert tok3.value == "world"

    def test_parentheses_multiline(self):
        t = Tokenizer("( hello\nworld )")
        tok1 = t.get()
        assert tok1.value == "hello"
        tok2 = t.get()
        assert tok2.value == "world"

    def test_nested_parens(self):
        t = Tokenizer("( a\n( b\nc ) d )")
        tokens = []
        while True:
            tok = t.get()
            if tok.is_eof():
                break
            if tok.is_identifier():
                tokens.append(tok.value)
        assert tokens == ["a", "b", "c", "d"]

    def test_escape_literal(self):
        t = Tokenizer("he\\llo")
        tok = t.get()
        assert tok.value == "hello"

    def test_escape_decimal(self):
        t = Tokenizer("\\065xample")
        tok = t.get()
        assert tok.value == "Axample"

    def test_leading_whitespace(self):
        t = Tokenizer("  hello")
        tok = t.get(want_leading_whitespace=True)
        assert tok.is_whitespace()
        tok = t.get()
        assert tok.value == "hello"

    def test_get_identifier(self):
        t = Tokenizer("example.com.")
        val = t.get_identifier()
        assert val == "example.com."

    def test_get_string_quoted(self):
        t = Tokenizer('"hello"')
        val = t.get_string()
        assert val == "hello"

    def test_get_int(self):
        t = Tokenizer("300")
        val = t.get_int()
        assert val == 300

    def test_get_uint16(self):
        t = Tokenizer("1234")
        val = t.get_uint16()
        assert val == 1234

    def test_get_uint32(self):
        t = Tokenizer("4000000000")
        val = t.get_uint32()
        assert val == 4000000000

    def test_get_remaining(self):
        t = Tokenizer("a b c\nd")
        tokens = t.get_remaining()
        values = [tok.value for tok in tokens]
        assert values == ["a", "b", "c"]

    def test_tab_is_whitespace(self):
        t = Tokenizer("a\tb")
        tok1 = t.get()
        tok2 = t.get()
        assert tok1.value == "a"
        assert tok2.value == "b"

    def test_cr_lf(self):
        t = Tokenizer("hello\r\nworld")
        t.get()
        tok = t.get()
        assert tok.is_eol()

    def test_quoted_escape(self):
        t = Tokenizer('"hello\\065"')
        tok = t.get()
        assert tok.value == "helloA"


class TestZoneParser:
    def test_simple_a_record(self):
        text = "example.com. 300 IN A 1.2.3.4\n"
        entries = parse_zone_text(text)
        assert len(entries) == 1
        e = entries[0]
        assert e.name == name_from_text("example.com.")
        assert e.ttl == 300
        assert e.rdtype == RecordType.A
        assert isinstance(e.rdata, ARecord)
        assert e.rdata.address == "1.2.3.4"

    def test_origin_directive(self):
        text = "$ORIGIN example.com.\nwww 300 IN A 1.2.3.4\n"
        entries = parse_zone_text(text)
        assert len(entries) == 1
        assert entries[0].name == name_from_text("www.example.com.")

    def test_ttl_directive(self):
        text = "$TTL 600\nexample.com. IN A 1.2.3.4\n"
        entries = parse_zone_text(text)
        assert len(entries) == 1
        assert entries[0].ttl == 600

    def test_at_sign_origin(self):
        text = "@ 300 IN A 1.2.3.4\n"
        origin = name_from_text("example.com.")
        entries = parse_zone_text(text, origin=origin)
        assert len(entries) == 1
        assert entries[0].name == origin

    def test_blank_owner_continuation(self):
        text = (
            "example.com. 300 IN A 1.2.3.4\n"
            "             300 IN A 5.6.7.8\n"
        )
        entries = parse_zone_text(text)
        assert len(entries) == 2
        assert entries[0].name == entries[1].name

    def test_multiple_types(self):
        text = (
            "$ORIGIN example.com.\n"
            "@ 3600 IN SOA ns1.example.com. admin.example.com. 1 3600 900 604800 86400\n"
            "@ 3600 IN NS ns1.example.com.\n"
            "@ 300 IN A 93.184.216.34\n"
            "@ 300 IN MX 10 mail.example.com.\n"
        )
        entries = parse_zone_text(text)
        assert len(entries) == 4
        types = [e.rdtype for e in entries]
        assert RecordType.SOA in types
        assert RecordType.NS in types
        assert RecordType.A in types
        assert RecordType.MX in types

    def test_mx_record(self):
        text = "example.com. 300 IN MX 10 mail.example.com.\n"
        entries = parse_zone_text(text)
        assert len(entries) == 1
        e = entries[0]
        assert isinstance(e.rdata, MXRecord)
        assert e.rdata.preference == 10

    def test_soa_record(self):
        text = "example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400\n"
        entries = parse_zone_text(text)
        assert len(entries) == 1
        soa = entries[0].rdata
        assert isinstance(soa, SOARecord)
        assert soa.serial == 2024010101

    def test_ns_record(self):
        text = "example.com. 3600 IN NS ns1.example.com.\n"
        entries = parse_zone_text(text)
        assert len(entries) == 1
        assert isinstance(entries[0].rdata, NSRecord)

    def test_txt_record(self):
        text = 'example.com. 300 IN TXT "v=spf1 include:example.com ~all"\n'
        entries = parse_zone_text(text)
        assert len(entries) == 1
        assert isinstance(entries[0].rdata, TXTRecord)
        assert entries[0].rdata.strings[0] == b"v=spf1 include:example.com ~all"

    def test_comments_ignored(self):
        text = (
            "; This is a zone file\n"
            "example.com. 300 IN A 1.2.3.4 ; inline comment\n"
        )
        entries = parse_zone_text(text)
        assert len(entries) == 1

    def test_class_before_ttl(self):
        text = "example.com. IN 300 A 1.2.3.4\n"
        entries = parse_zone_text(text)
        assert len(entries) == 1
        assert entries[0].ttl == 300

    def test_origin_with_string(self):
        entries = parse_zone_text(
            "www 300 IN A 1.2.3.4\n",
            origin="example.com."
        )
        assert len(entries) == 1
        assert entries[0].name == name_from_text("www.example.com.")

    def test_multiline_soa(self):
        text = (
            "$ORIGIN example.com.\n"
            "@ 3600 IN SOA ns1 admin (\n"
            "  2024010101 ; serial\n"
            "  3600       ; refresh\n"
            "  900        ; retry\n"
            "  604800     ; expire\n"
            "  86400      ; minimum\n"
            ")\n"
        )
        entries = parse_zone_text(text)
        assert len(entries) == 1
        soa = entries[0].rdata
        assert isinstance(soa, SOARecord)
        assert soa.serial == 2024010101

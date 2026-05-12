"""Tests for DNS type system and protocol constants."""

import pytest
from dnscore.record_type import (
    RecordType,
    type_from_text,
    type_to_text,
    is_meta_type,
    is_singleton_type,
)
from dnscore.record_class import (
    RecordClass,
    class_from_text,
    class_to_text,
    is_meta_class,
)
from dnscore.msg_flags import (
    MessageFlag,
    EDNSFlag,
    flags_from_text,
    flags_to_text,
    edns_flags_from_text,
    edns_flags_to_text,
)
from dnscore.op_code import (
    OpCode,
    opcode_from_text,
    opcode_to_text,
    opcode_from_flags,
    opcode_to_flags,
    is_update,
)
from dnscore.resp_code import (
    ResponseCode,
    rcode_from_text,
    rcode_to_text,
    rcode_from_flags,
    rcode_to_flags,
)
from dnscore.ttl import ttl_from_text, ttl_to_text, MAX_TTL
from dnscore.exceptions import SyntaxError as DNSSyntaxError


class TestRecordTypeFromText:
    def test_standard_types(self):
        assert type_from_text("A") == 1
        assert type_from_text("AAAA") == 28
        assert type_from_text("CNAME") == 5
        assert type_from_text("MX") == 15
        assert type_from_text("NS") == 2
        assert type_from_text("PTR") == 12
        assert type_from_text("SOA") == 6
        assert type_from_text("TXT") == 16
        assert type_from_text("SRV") == 33

    def test_case_insensitive(self):
        assert type_from_text("a") == 1
        assert type_from_text("Aaaa") == 28
        assert type_from_text("mx") == 15

    def test_type_nn(self):
        assert type_from_text("TYPE1") == 1
        assert type_from_text("TYPE999") == 999

    def test_unknown_raises(self):
        with pytest.raises(ValueError):
            type_from_text("BOGUS")

    def test_meta_types(self):
        assert type_from_text("ANY") == 255
        assert type_from_text("AXFR") == 252
        assert type_from_text("OPT") == 41


class TestRecordTypeToText:
    def test_known_type(self):
        assert type_to_text(RecordType.A) == "A"
        assert type_to_text(RecordType.AAAA) == "AAAA"
        assert type_to_text(RecordType.MX) == "MX"

    def test_unknown_type(self):
        assert type_to_text(999) == "TYPE999"

    def test_from_int(self):
        assert type_to_text(1) == "A"


class TestMetaAndSingleton:
    def test_meta_types(self):
        assert is_meta_type(RecordType.ANY)
        assert is_meta_type(RecordType.AXFR)
        assert is_meta_type(RecordType.OPT)
        assert not is_meta_type(RecordType.A)
        assert not is_meta_type(RecordType.MX)

    def test_singleton_types(self):
        assert is_singleton_type(RecordType.SOA)
        assert is_singleton_type(RecordType.CNAME)
        assert not is_singleton_type(RecordType.A)
        assert not is_singleton_type(RecordType.MX)


class TestRecordClassFromText:
    def test_standard_classes(self):
        assert class_from_text("IN") == 1
        assert class_from_text("CH") == 3
        assert class_from_text("HS") == 4
        assert class_from_text("NONE") == 254
        assert class_from_text("ANY") == 255

    def test_aliases(self):
        assert class_from_text("INTERNET") == 1
        assert class_from_text("CHAOS") == 3
        assert class_from_text("HESIOD") == 4

    def test_case_insensitive(self):
        assert class_from_text("in") == 1
        assert class_from_text("In") == 1

    def test_class_nn(self):
        assert class_from_text("CLASS1") == 1
        assert class_from_text("CLASS999") == 999

    def test_unknown_raises(self):
        with pytest.raises(ValueError):
            class_from_text("BOGUS")


class TestRecordClassToText:
    def test_known_class(self):
        assert class_to_text(RecordClass.IN) == "IN"
        assert class_to_text(RecordClass.CH) == "CH"

    def test_unknown_class(self):
        assert class_to_text(999) == "CLASS999"


class TestMetaClass:
    def test_meta_classes(self):
        assert is_meta_class(RecordClass.ANY)
        assert is_meta_class(RecordClass.NONE)
        assert not is_meta_class(RecordClass.IN)
        assert not is_meta_class(RecordClass.CH)


class TestMessageFlags:
    def test_flag_values(self):
        assert MessageFlag.QR == 0x8000
        assert MessageFlag.AA == 0x0400
        assert MessageFlag.TC == 0x0200
        assert MessageFlag.RD == 0x0100
        assert MessageFlag.RA == 0x0080
        assert MessageFlag.AD == 0x0020
        assert MessageFlag.CD == 0x0010

    def test_flags_from_text(self):
        result = flags_from_text("QR AA RD")
        assert result & MessageFlag.QR
        assert result & MessageFlag.AA
        assert result & MessageFlag.RD
        assert not (result & MessageFlag.TC)

    def test_flags_to_text(self):
        flags = MessageFlag.QR | MessageFlag.RD | MessageFlag.RA
        text = flags_to_text(flags)
        assert "QR" in text
        assert "RD" in text
        assert "RA" in text

    def test_flags_from_text_empty(self):
        assert flags_from_text("") == 0

    def test_flags_from_text_unknown(self):
        with pytest.raises(ValueError):
            flags_from_text("BOGUS")


class TestEDNSFlags:
    def test_do_flag(self):
        assert EDNSFlag.DO == 0x8000

    def test_edns_from_text(self):
        result = edns_flags_from_text("DO")
        assert result & EDNSFlag.DO

    def test_edns_to_text(self):
        text = edns_flags_to_text(EDNSFlag.DO)
        assert text == "DO"


class TestOpCode:
    def test_values(self):
        assert OpCode.QUERY == 0
        assert OpCode.STATUS == 2
        assert OpCode.NOTIFY == 4
        assert OpCode.UPDATE == 5

    def test_from_text(self):
        assert opcode_from_text("QUERY") == 0
        assert opcode_from_text("UPDATE") == 5

    def test_from_text_case_insensitive(self):
        assert opcode_from_text("query") == 0

    def test_from_text_unknown(self):
        with pytest.raises(ValueError):
            opcode_from_text("BOGUS")

    def test_to_text(self):
        assert opcode_to_text(OpCode.QUERY) == "QUERY"
        assert opcode_to_text(OpCode.UPDATE) == "UPDATE"

    def test_from_flags(self):
        flags = opcode_to_flags(OpCode.QUERY)
        assert opcode_from_flags(flags) == OpCode.QUERY

    def test_update_flags(self):
        flags = opcode_to_flags(OpCode.UPDATE)
        assert opcode_from_flags(flags) == OpCode.UPDATE
        assert is_update(flags)

    def test_query_not_update(self):
        flags = opcode_to_flags(OpCode.QUERY)
        assert not is_update(flags)

    def test_opcode_bits_position(self):
        flags = opcode_to_flags(OpCode.UPDATE)
        assert flags == (5 << 11)


class TestResponseCode:
    def test_values(self):
        assert ResponseCode.NOERROR == 0
        assert ResponseCode.FORMERR == 1
        assert ResponseCode.SERVFAIL == 2
        assert ResponseCode.NXDOMAIN == 3
        assert ResponseCode.REFUSED == 5

    def test_from_text(self):
        assert rcode_from_text("NOERROR") == 0
        assert rcode_from_text("NXDOMAIN") == 3
        assert rcode_from_text("SERVFAIL") == 2
        assert rcode_from_text("REFUSED") == 5

    def test_from_text_unknown(self):
        with pytest.raises(ValueError):
            rcode_from_text("BOGUS")

    def test_to_text(self):
        assert rcode_to_text(0) == "NOERROR"
        assert rcode_to_text(3) == "NXDOMAIN"
        assert rcode_to_text(5) == "REFUSED"

    def test_to_text_unknown(self):
        assert rcode_to_text(100) == "100"

    def test_badvers_badsig_alias(self):
        assert ResponseCode.BADVERS == 16
        assert ResponseCode.BADSIG == 16

    def test_from_flags_simple(self):
        rcode = rcode_from_flags(3)
        assert rcode == 3

    def test_to_flags_simple(self):
        low, high = rcode_to_flags(3)
        assert low == 3
        assert high == 0

    def test_extended_rcode_roundtrip(self):
        for rcode in [0, 3, 16, 255, 4095]:
            low, high = rcode_to_flags(rcode)
            result = rcode_from_flags(low, high)
            assert result == rcode, f"roundtrip failed for rcode={rcode}"


class TestTTL:
    def test_integer(self):
        assert ttl_from_text("300") == 300
        assert ttl_from_text("0") == 0

    def test_int_input(self):
        assert ttl_from_text(300) == 300

    def test_bind_style_hours(self):
        assert ttl_from_text("1h") == 3600

    def test_bind_style_minutes(self):
        assert ttl_from_text("30m") == 1800

    def test_bind_style_combined(self):
        assert ttl_from_text("1h30m") == 5400

    def test_bind_style_week_day(self):
        assert ttl_from_text("1w2d") == 604800 + 172800

    def test_bind_style_all_units(self):
        assert ttl_from_text("1w1d1h1m1s") == 604800 + 86400 + 3600 + 60 + 1

    def test_bind_style_seconds(self):
        assert ttl_from_text("45s") == 45

    def test_trailing_number_is_seconds(self):
        assert ttl_from_text("1h30") == 3600 + 30

    def test_max_ttl(self):
        assert ttl_from_text(str(MAX_TTL)) == MAX_TTL

    def test_zero_ttl(self):
        assert ttl_from_text("0") == 0

    def test_empty_raises(self):
        with pytest.raises(DNSSyntaxError):
            ttl_from_text("")

    def test_invalid_char_raises(self):
        with pytest.raises(DNSSyntaxError):
            ttl_from_text("abc")

    def test_too_large_raises(self):
        with pytest.raises(DNSSyntaxError):
            ttl_from_text(MAX_TTL + 1)

    def test_negative_raises(self):
        with pytest.raises(DNSSyntaxError):
            ttl_from_text(-1)

    def test_to_text(self):
        assert ttl_to_text(300) == "300"

    def test_missing_number_raises(self):
        with pytest.raises(DNSSyntaxError):
            ttl_from_text("h30")

"""Tests for network address utilities and core DNS records."""

import struct
import pytest
from dnscore.ipv4 import text_to_binary as ipv4_to_bin, binary_to_text as ipv4_to_text, is_valid as ipv4_valid, canonicalize as ipv4_canon
from dnscore.ipv6 import text_to_binary as ipv6_to_bin, binary_to_text as ipv6_to_text, is_valid as ipv6_valid, is_mapped_ipv4, canonicalize as ipv6_canon
from dnscore.net_utils import address_family, is_address, AF_INET, AF_INET6
from dnscore.record_data import (
    ARecord, AAAARecord, NSRecord, CNAMERecord, PTRRecord,
    MXRecord, TXTRecord, SOARecord, SRVRecord,
    create_from_text, create_from_wire,
    RecordData, register_type, get_record_class,
)
from dnscore.record_type import RecordType
from dnscore.record_class import RecordClass
from dnscore.domain_name import from_text as name_from_text
from dnscore.exceptions import SyntaxError as DNSSyntaxError, FormError


class TestIPv4:
    def test_text_to_binary(self):
        assert ipv4_to_bin("192.168.1.1") == b"\xc0\xa8\x01\x01"

    def test_binary_to_text(self):
        assert ipv4_to_text(b"\xc0\xa8\x01\x01") == "192.168.1.1"

    def test_roundtrip(self):
        for addr in ["0.0.0.0", "255.255.255.255", "10.0.0.1", "192.168.0.1"]:
            assert ipv4_to_text(ipv4_to_bin(addr)) == addr

    def test_leading_zeros_rejected(self):
        with pytest.raises(DNSSyntaxError):
            ipv4_to_bin("192.168.01.1")

    def test_too_few_parts(self):
        with pytest.raises(DNSSyntaxError):
            ipv4_to_bin("192.168.1")

    def test_too_many_parts(self):
        with pytest.raises(DNSSyntaxError):
            ipv4_to_bin("192.168.1.1.1")

    def test_out_of_range(self):
        with pytest.raises(DNSSyntaxError):
            ipv4_to_bin("256.1.1.1")

    def test_is_valid(self):
        assert ipv4_valid("192.168.1.1")
        assert not ipv4_valid("not-an-ip")

    def test_canonicalize(self):
        assert ipv4_canon("192.168.1.1") == "192.168.1.1"

    def test_wrong_length_binary(self):
        with pytest.raises(DNSSyntaxError):
            ipv4_to_text(b"\x00\x00")


class TestIPv6:
    def test_full_address(self):
        data = ipv6_to_bin("2001:0db8:0000:0000:0000:0000:0000:0001")
        assert len(data) == 16
        text = ipv6_to_text(data)
        assert text == "2001:db8::1"

    def test_compressed(self):
        data = ipv6_to_bin("2001:db8::1")
        text = ipv6_to_text(data)
        assert text == "2001:db8::1"

    def test_all_zeros(self):
        data = ipv6_to_bin("::")
        assert data == b"\x00" * 16
        assert ipv6_to_text(data) == "::"

    def test_loopback(self):
        data = ipv6_to_bin("::1")
        text = ipv6_to_text(data)
        assert text == "::1"

    def test_all_ones(self):
        data = ipv6_to_bin("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
        text = ipv6_to_text(data)
        assert text == "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"

    def test_scope_stripped(self):
        data = ipv6_to_bin("fe80::1%eth0")
        assert len(data) == 16

    def test_is_valid(self):
        assert ipv6_valid("2001:db8::1")
        assert ipv6_valid("::")
        assert not ipv6_valid("not-ipv6")

    def test_is_mapped(self):
        data = ipv6_to_bin("::ffff:192.168.1.1")
        assert is_mapped_ipv4(data)
        data2 = ipv6_to_bin("2001:db8::1")
        assert not is_mapped_ipv4(data2)

    def test_roundtrip(self):
        for addr in ["::", "::1", "2001:db8::1", "fe80::1"]:
            data = ipv6_to_bin(addr)
            result = ipv6_to_text(data)
            data2 = ipv6_to_bin(result)
            assert data == data2

    def test_wrong_length_binary(self):
        with pytest.raises(DNSSyntaxError):
            ipv6_to_text(b"\x00" * 4)


class TestNetUtils:
    def test_address_family_ipv4(self):
        assert address_family("192.168.1.1") == AF_INET

    def test_address_family_ipv6(self):
        assert address_family("2001:db8::1") == AF_INET6

    def test_is_address(self):
        assert is_address("192.168.1.1")
        assert is_address("2001:db8::1")
        assert not is_address("not-an-address")


class TestARecord:
    def test_create(self):
        rec = ARecord("192.168.1.1")
        assert rec.address == "192.168.1.1"
        assert rec.rdtype == RecordType.A

    def test_to_text(self):
        rec = ARecord("10.0.0.1")
        assert rec.to_text() == "10.0.0.1"

    def test_to_wire(self):
        rec = ARecord("192.168.1.1")
        wire = rec.to_wire()
        assert wire == b"\xc0\xa8\x01\x01"

    def test_from_text(self):
        rec = ARecord.from_text("192.168.1.1")
        assert rec.address == "192.168.1.1"

    def test_from_wire(self):
        rec = ARecord.from_wire(b"\xc0\xa8\x01\x01")
        assert rec.address == "192.168.1.1"

    def test_roundtrip(self):
        original = ARecord("10.20.30.40")
        wire = original.to_wire()
        restored = ARecord.from_wire(wire)
        assert restored.address == original.address

    def test_invalid_address(self):
        with pytest.raises(DNSSyntaxError):
            ARecord("not-an-ip")

    def test_equality(self):
        a1 = ARecord("1.2.3.4")
        a2 = ARecord("1.2.3.4")
        assert a1 == a2

    def test_inequality(self):
        a1 = ARecord("1.2.3.4")
        a2 = ARecord("5.6.7.8")
        assert a1 != a2

    def test_hash(self):
        a1 = ARecord("1.2.3.4")
        a2 = ARecord("1.2.3.4")
        assert hash(a1) == hash(a2)


class TestAAAARecord:
    def test_create(self):
        rec = AAAARecord("2001:db8::1")
        assert rec.address == "2001:db8::1"
        assert rec.rdtype == RecordType.AAAA

    def test_to_wire(self):
        rec = AAAARecord("::1")
        wire = rec.to_wire()
        assert len(wire) == 16
        assert wire[-1] == 1

    def test_from_text(self):
        rec = AAAARecord.from_text("2001:db8::1")
        assert rec.address == "2001:db8::1"

    def test_from_wire(self):
        data = b"\x20\x01\x0d\xb8" + b"\x00" * 10 + b"\x00\x01"
        rec = AAAARecord.from_wire(data)
        assert rec.address == "2001:db8::1"

    def test_roundtrip(self):
        original = AAAARecord("fe80::1")
        wire = original.to_wire()
        restored = AAAARecord.from_wire(wire)
        assert restored == original


class TestNSRecord:
    def test_create(self):
        rec = NSRecord("ns1.example.com.")
        assert rec.target == name_from_text("ns1.example.com.")
        assert rec.rdtype == RecordType.NS

    def test_to_text(self):
        rec = NSRecord("ns1.example.com.")
        assert rec.to_text() == "ns1.example.com."

    def test_from_text(self):
        rec = NSRecord.from_text("ns2.example.com.")
        assert rec.target == name_from_text("ns2.example.com.")

    def test_roundtrip_wire(self):
        original = NSRecord("ns1.example.com.")
        wire = original.to_wire()
        restored = NSRecord.from_wire(wire)
        assert restored.target == original.target


class TestCNAMERecord:
    def test_create(self):
        rec = CNAMERecord("www.example.com.")
        assert rec.rdtype == RecordType.CNAME

    def test_to_text(self):
        rec = CNAMERecord("alias.example.com.")
        assert rec.to_text() == "alias.example.com."


class TestPTRRecord:
    def test_create(self):
        rec = PTRRecord("host.example.com.")
        assert rec.rdtype == RecordType.PTR
        assert rec.target == name_from_text("host.example.com.")


class TestMXRecord:
    def test_create(self):
        rec = MXRecord(10, "mail.example.com.")
        assert rec.preference == 10
        assert rec.exchange == name_from_text("mail.example.com.")
        assert rec.rdtype == RecordType.MX

    def test_to_text(self):
        rec = MXRecord(10, "mail.example.com.")
        assert rec.to_text() == "10 mail.example.com."

    def test_from_text(self):
        rec = MXRecord.from_text("20 smtp.example.com.")
        assert rec.preference == 20
        assert rec.exchange == name_from_text("smtp.example.com.")

    def test_to_wire(self):
        rec = MXRecord(10, "mail.example.com.")
        wire = rec.to_wire()
        pref = struct.unpack("!H", wire[:2])[0]
        assert pref == 10

    def test_from_wire(self):
        rec = MXRecord(10, "mail.example.com.")
        wire = rec.to_wire()
        restored = MXRecord.from_wire(wire)
        assert restored.preference == 10
        assert restored.exchange == rec.exchange

    def test_invalid_preference(self):
        with pytest.raises(ValueError):
            MXRecord(70000, "mail.example.com.")


class TestTXTRecord:
    def test_single_string(self):
        rec = TXTRecord("hello world")
        assert rec.strings == (b"hello world",)

    def test_multiple_strings(self):
        rec = TXTRecord(["first", "second"])
        assert rec.strings == (b"first", b"second")

    def test_to_text(self):
        rec = TXTRecord("hello")
        assert rec.to_text() == '"hello"'

    def test_to_text_multiple(self):
        rec = TXTRecord(["a", "b"])
        assert rec.to_text() == '"a" "b"'

    def test_from_text_quoted(self):
        rec = TXTRecord.from_text('"hello world"')
        assert rec.strings == (b"hello world",)

    def test_from_text_multiple(self):
        rec = TXTRecord.from_text('"first" "second"')
        assert rec.strings == (b"first", b"second")

    def test_to_wire(self):
        rec = TXTRecord("hello")
        wire = rec.to_wire()
        assert wire[0] == 5
        assert wire[1:] == b"hello"

    def test_from_wire(self):
        wire = b"\x05hello"
        rec = TXTRecord.from_wire(wire)
        assert rec.strings == (b"hello",)

    def test_from_wire_multiple(self):
        wire = b"\x05hello\x05world"
        rec = TXTRecord.from_wire(wire, length=12)
        assert rec.strings == (b"hello", b"world")

    def test_bytes_input(self):
        rec = TXTRecord(b"binary data")
        assert rec.strings == (b"binary data",)

    def test_string_too_long(self):
        with pytest.raises(ValueError):
            TXTRecord("x" * 256)

    def test_roundtrip(self):
        original = TXTRecord(["v=spf1 include:example.com ~all"])
        wire = original.to_wire()
        restored = TXTRecord.from_wire(wire, length=len(wire))
        assert restored.strings == original.strings


class TestSOARecord:
    def test_create(self):
        rec = SOARecord("ns.example.com.", "admin.example.com.",
                        2024010101, 3600, 1800, 604800, 86400)
        assert rec.serial == 2024010101
        assert rec.refresh == 3600
        assert rec.retry == 1800
        assert rec.expire == 604800
        assert rec.minimum == 86400

    def test_to_text(self):
        rec = SOARecord("ns.example.com.", "admin.example.com.",
                        2024010101, 3600, 1800, 604800, 86400)
        text = rec.to_text()
        assert "ns.example.com." in text
        assert "admin.example.com." in text
        assert "2024010101" in text

    def test_from_text(self):
        rec = SOARecord.from_text(
            "ns.example.com. admin.example.com. 2024010101 3600 1800 604800 86400"
        )
        assert rec.serial == 2024010101
        assert rec.mname == name_from_text("ns.example.com.")

    def test_roundtrip_wire(self):
        original = SOARecord("ns.example.com.", "admin.example.com.",
                             2024010101, 3600, 1800, 604800, 86400)
        wire = original.to_wire()
        restored = SOARecord.from_wire(wire)
        assert restored.serial == original.serial
        assert restored.mname == original.mname
        assert restored.rname == original.rname
        assert restored.refresh == original.refresh
        assert restored.retry == original.retry
        assert restored.expire == original.expire
        assert restored.minimum == original.minimum


class TestSRVRecord:
    def test_create(self):
        rec = SRVRecord(10, 20, 443, "server.example.com.")
        assert rec.priority == 10
        assert rec.weight == 20
        assert rec.port == 443
        assert rec.rdtype == RecordType.SRV

    def test_to_text(self):
        rec = SRVRecord(10, 20, 443, "server.example.com.")
        assert rec.to_text() == "10 20 443 server.example.com."

    def test_from_text(self):
        rec = SRVRecord.from_text("10 20 443 server.example.com.")
        assert rec.priority == 10
        assert rec.weight == 20
        assert rec.port == 443

    def test_roundtrip_wire(self):
        original = SRVRecord(10, 60, 80, "web.example.com.")
        wire = original.to_wire()
        restored = SRVRecord.from_wire(wire)
        assert restored.priority == original.priority
        assert restored.weight == original.weight
        assert restored.port == original.port
        assert restored.target == original.target

    def test_invalid_port(self):
        with pytest.raises(ValueError):
            SRVRecord(10, 20, 70000, "server.example.com.")


class TestRecordRegistry:
    def test_known_types_registered(self):
        assert get_record_class(RecordType.A) is ARecord
        assert get_record_class(RecordType.AAAA) is AAAARecord
        assert get_record_class(RecordType.NS) is NSRecord
        assert get_record_class(RecordType.MX) is MXRecord
        assert get_record_class(RecordType.TXT) is TXTRecord
        assert get_record_class(RecordType.SOA) is SOARecord
        assert get_record_class(RecordType.SRV) is SRVRecord

    def test_create_from_text(self):
        rec = create_from_text(RecordType.A, "1.2.3.4")
        assert isinstance(rec, ARecord)
        assert rec.address == "1.2.3.4"

    def test_create_from_wire(self):
        rec = create_from_wire(RecordType.A, b"\x01\x02\x03\x04")
        assert isinstance(rec, ARecord)
        assert rec.address == "1.2.3.4"

    def test_unknown_type(self):
        with pytest.raises(ValueError):
            create_from_text(9999, "data")


class TestRecordDataBase:
    def test_repr(self):
        rec = ARecord("1.2.3.4")
        assert "1.2.3.4" in repr(rec)

    def test_str(self):
        rec = ARecord("1.2.3.4")
        assert str(rec) == "1.2.3.4"

    def test_not_equal_to_non_record(self):
        rec = ARecord("1.2.3.4")
        assert rec != "1.2.3.4"

    def test_lt(self):
        a1 = ARecord("1.2.3.4")
        a2 = ARecord("5.6.7.8")
        assert a1 < a2

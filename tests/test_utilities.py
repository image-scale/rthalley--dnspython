"""Tests for reverse DNS, serial number arithmetic, and E.164 conversion."""

import pytest

from dnscore.reversename import (
    from_address, to_address,
    ipv4_reverse_domain, ipv6_reverse_domain,
)
from dnscore.serial import Serial
from dnscore.e164 import from_e164, to_e164, public_enum_domain
from dnscore.domain_name import from_text as name_from_text
from dnscore.exceptions import SyntaxError as DNSSyntaxError


# --- Reverse DNS: IPv4 ---

class TestReverseIPv4:
    def test_from_address_simple(self):
        name = from_address("192.168.1.1")
        assert name.to_text() == "1.1.168.192.in-addr.arpa."

    def test_from_address_zeros(self):
        name = from_address("0.0.0.0")
        assert name.to_text() == "0.0.0.0.in-addr.arpa."

    def test_from_address_broadcast(self):
        name = from_address("255.255.255.255")
        assert name.to_text() == "255.255.255.255.in-addr.arpa."

    def test_to_address_ipv4(self):
        name = from_address("10.20.30.40")
        addr = to_address(name)
        assert addr == "10.20.30.40"

    def test_roundtrip_ipv4(self):
        original = "172.16.0.1"
        assert to_address(from_address(original)) == original

    def test_to_address_from_string(self):
        addr = to_address("1.0.168.192.in-addr.arpa.")
        assert addr == "192.168.0.1"

    def test_custom_v4_origin(self):
        origin = name_from_text("my-reverse.example.")
        name = from_address("1.2.3.4", v4_origin=origin)
        assert name.to_text() == "4.3.2.1.my-reverse.example."


# --- Reverse DNS: IPv6 ---

class TestReverseIPv6:
    def test_from_address_loopback(self):
        name = from_address("::1")
        expected = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."
        assert name.to_text() == expected

    def test_from_address_full(self):
        name = from_address("2001:db8::1")
        text = name.to_text()
        assert text.endswith(".ip6.arpa.")
        assert text.startswith("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2")

    def test_to_address_ipv6(self):
        name = from_address("2001:db8::1")
        addr = to_address(name)
        assert addr == "2001:db8::1"

    def test_roundtrip_ipv6(self):
        original = "fe80::1"
        result = to_address(from_address(original))
        assert result == original

    def test_roundtrip_ipv6_full(self):
        original = "2001:db8:85a3::8a2e:370:7334"
        result = to_address(from_address(original))
        assert result == original


# --- Reverse DNS: errors ---

class TestReverseErrors:
    def test_invalid_address(self):
        with pytest.raises(DNSSyntaxError):
            from_address("not-an-address")

    def test_to_address_not_reverse(self):
        name = name_from_text("www.example.com.")
        with pytest.raises(DNSSyntaxError):
            to_address(name)

    def test_to_address_wrong_label_count_v4(self):
        name = name_from_text("1.2.3.in-addr.arpa.")
        with pytest.raises(DNSSyntaxError):
            to_address(name)

    def test_to_address_wrong_label_count_v6(self):
        name = name_from_text("1.0.0.ip6.arpa.")
        with pytest.raises(DNSSyntaxError):
            to_address(name)


# --- Serial number arithmetic ---

class TestSerialCreation:
    def test_basic(self):
        s = Serial(42)
        assert int(s) == 42

    def test_zero(self):
        s = Serial(0)
        assert int(s) == 0

    def test_max_value(self):
        s = Serial(0xFFFFFFFF)
        assert int(s) == 0xFFFFFFFF

    def test_wraps_on_creation(self):
        s = Serial(0x100000000)
        assert int(s) == 0

    def test_custom_bits(self):
        s = Serial(255, bits=8)
        assert int(s) == 255
        assert s.bits == 8

    def test_repr(self):
        s = Serial(100)
        assert "100" in repr(s)

    def test_str(self):
        assert str(Serial(42)) == "42"


class TestSerialComparison:
    def test_equal(self):
        assert Serial(100) == Serial(100)

    def test_equal_int(self):
        assert Serial(100) == 100

    def test_not_equal(self):
        assert Serial(100) != Serial(200)

    def test_less_than_simple(self):
        assert Serial(1) < Serial(2)

    def test_greater_than_simple(self):
        assert Serial(2) > Serial(1)

    def test_less_than_wraparound(self):
        assert Serial(0xFFFFFFFF) < Serial(1)

    def test_greater_than_wraparound(self):
        assert Serial(1) > Serial(0xFFFFFFFF)

    def test_le(self):
        assert Serial(1) <= Serial(2)
        assert Serial(1) <= Serial(1)

    def test_ge(self):
        assert Serial(2) >= Serial(1)
        assert Serial(2) >= Serial(2)

    def test_midpoint_not_less(self):
        s1 = Serial(0)
        s2 = Serial(0x80000000)
        assert not (s1 < s2)
        assert not (s1 > s2)

    def test_different_bits_not_comparable(self):
        result = Serial(1, bits=32).__eq__(Serial(1, bits=16))
        assert result is NotImplemented


class TestSerialArithmetic:
    def test_add(self):
        s = Serial(100) + 50
        assert int(s) == 150

    def test_add_serial(self):
        s = Serial(10) + Serial(5)
        assert int(s) == 15

    def test_add_wraparound(self):
        s = Serial(0xFFFFFFFF) + 1
        assert int(s) == 0

    def test_add_wraparound_2(self):
        s = Serial(0xFFFFFFF0) + 32
        assert int(s) == 16

    def test_iadd(self):
        s = Serial(100)
        s += 1
        assert int(s) == 101

    def test_sub(self):
        s = Serial(100) - 50
        assert int(s) == 50

    def test_sub_wraparound(self):
        s = Serial(0) - 1
        assert int(s) == 0xFFFFFFFF

    def test_isub(self):
        s = Serial(100)
        s -= 1
        assert int(s) == 99

    def test_add_too_large_raises(self):
        with pytest.raises(ValueError):
            Serial(0) + 0x80000000

    def test_sub_too_large_raises(self):
        with pytest.raises(ValueError):
            Serial(0) - 0x80000000

    def test_add_max_allowed(self):
        s = Serial(0) + (0x80000000 - 1)
        assert int(s) == 0x7FFFFFFF

    def test_hash(self):
        assert hash(Serial(42)) == hash(Serial(42))
        assert hash(Serial(1)) != hash(Serial(2))

    def test_custom_bits_arithmetic(self):
        s = Serial(250, bits=8) + 10
        assert int(s) == 4  # (250 + 10) % 256


# --- E.164 conversion ---

class TestE164:
    def test_from_e164_basic(self):
        name = from_e164("+16505551212")
        assert name.to_text() == "2.1.2.1.5.5.5.0.5.6.1.e164.arpa."

    def test_from_e164_with_spaces(self):
        name = from_e164("+1 650 555 1212")
        assert name.to_text() == "2.1.2.1.5.5.5.0.5.6.1.e164.arpa."

    def test_from_e164_with_dashes(self):
        name = from_e164("+1-650-555-1212")
        assert name.to_text() == "2.1.2.1.5.5.5.0.5.6.1.e164.arpa."

    def test_from_e164_with_parens(self):
        name = from_e164("+1 (650) 555-1212")
        assert name.to_text() == "2.1.2.1.5.5.5.0.5.6.1.e164.arpa."

    def test_from_e164_no_plus(self):
        name = from_e164("16505551212")
        assert name.to_text() == "2.1.2.1.5.5.5.0.5.6.1.e164.arpa."

    def test_to_e164_basic(self):
        name = name_from_text("2.1.2.1.5.5.5.0.5.6.1.e164.arpa.")
        number = to_e164(name)
        assert number == "+16505551212"

    def test_to_e164_no_plus(self):
        name = name_from_text("2.1.2.1.5.5.5.0.5.6.1.e164.arpa.")
        number = to_e164(name, want_plus_prefix=False)
        assert number == "16505551212"

    def test_roundtrip(self):
        original = "+442071234567"
        result = to_e164(from_e164(original))
        assert result == original

    def test_from_e164_no_digits_raises(self):
        with pytest.raises(DNSSyntaxError):
            from_e164("+++---")

    def test_to_e164_not_under_origin(self):
        name = name_from_text("www.example.com.")
        with pytest.raises(DNSSyntaxError):
            to_e164(name)

    def test_to_e164_bad_label(self):
        name = name_from_text("a.b.c.e164.arpa.")
        with pytest.raises(DNSSyntaxError):
            to_e164(name)

    def test_to_e164_multi_digit_label(self):
        name = name_from_text("12.34.e164.arpa.")
        with pytest.raises(DNSSyntaxError):
            to_e164(name)

    def test_custom_origin(self):
        origin = name_from_text("enum.example.com.")
        name = from_e164("+1234", origin=origin)
        assert name.to_text() == "4.3.2.1.enum.example.com."
        result = to_e164(name, origin=origin)
        assert result == "+1234"

    def test_to_e164_from_string(self):
        number = to_e164("2.1.2.1.5.5.5.0.5.6.1.e164.arpa.")
        assert number == "+16505551212"

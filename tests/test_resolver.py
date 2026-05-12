"""Tests for DNS stub resolver."""

import struct
import pytest
from unittest.mock import patch, MagicMock

from dnscore.resolver import (
    Resolver, ResolverConfig, Answer,
    NXDOMAINError, NoAnswerError, NoNameserversError,
)
from dnscore.domain_name import from_text as name_from_text, ROOT
from dnscore.record_type import RecordType
from dnscore.record_class import RecordClass
from dnscore.record_data import ARecord, AAAARecord, NSRecord
from dnscore.record_sets import RRSet
from dnscore.message import DNSMessage, build_query, build_response, MessageSection
from dnscore.msg_flags import MessageFlag
from dnscore.resp_code import ResponseCode
from dnscore.wire_format import message_to_wire, message_from_wire


# --- ResolverConfig tests ---

class TestResolverConfig:
    def test_default_config(self):
        config = ResolverConfig()
        assert config.nameservers == []
        assert config.search == []
        assert config.domain is None
        assert config.timeout == 5.0
        assert config.attempts == 3
        assert config.ndots == 1

    def test_from_text_nameservers(self):
        text = "nameserver 8.8.8.8\nnameserver 8.8.4.4\n"
        config = ResolverConfig.from_text(text)
        assert config.nameservers == ["8.8.8.8", "8.8.4.4"]

    def test_from_text_search(self):
        text = "nameserver 127.0.0.1\nsearch example.com foo.bar.com\n"
        config = ResolverConfig.from_text(text)
        assert config.search == ["example.com", "foo.bar.com"]

    def test_from_text_domain(self):
        text = "nameserver 127.0.0.1\ndomain example.com\n"
        config = ResolverConfig.from_text(text)
        assert config.domain == "example.com"

    def test_from_text_options_timeout(self):
        text = "nameserver 127.0.0.1\noptions timeout:10\n"
        config = ResolverConfig.from_text(text)
        assert config.timeout == 10.0

    def test_from_text_options_attempts(self):
        text = "nameserver 127.0.0.1\noptions attempts:5\n"
        config = ResolverConfig.from_text(text)
        assert config.attempts == 5

    def test_from_text_options_ndots(self):
        text = "nameserver 127.0.0.1\noptions ndots:3\n"
        config = ResolverConfig.from_text(text)
        assert config.ndots == 3

    def test_from_text_multiple_options(self):
        text = "nameserver 10.0.0.1\noptions timeout:2 attempts:1 ndots:5\n"
        config = ResolverConfig.from_text(text)
        assert config.timeout == 2.0
        assert config.attempts == 1
        assert config.ndots == 5

    def test_from_text_comments_ignored(self):
        text = "# this is a comment\nnameserver 8.8.8.8\n; also a comment\n"
        config = ResolverConfig.from_text(text)
        assert config.nameservers == ["8.8.8.8"]

    def test_from_text_empty_lines_ignored(self):
        text = "\n\nnameserver 8.8.8.8\n\n"
        config = ResolverConfig.from_text(text)
        assert config.nameservers == ["8.8.8.8"]

    def test_from_text_bad_timeout_ignored(self):
        text = "nameserver 127.0.0.1\noptions timeout:xyz\n"
        config = ResolverConfig.from_text(text)
        assert config.timeout == 5.0

    def test_from_text_short_lines_ignored(self):
        text = "nameserver\n"
        config = ResolverConfig.from_text(text)
        assert config.nameservers == []

    def test_from_file_missing(self):
        config = ResolverConfig.from_file("/nonexistent/resolv.conf")
        assert config.nameservers == ["127.0.0.1"]

    def test_search_overrides_previous(self):
        text = "search a.com b.com\nsearch c.com\n"
        config = ResolverConfig.from_text(text)
        assert config.search == ["c.com"]


# --- Resolver creation tests ---

class TestResolverCreation:
    def test_default_resolver(self):
        resolver = Resolver()
        assert resolver.nameservers == ["127.0.0.1"]

    def test_custom_nameservers(self):
        resolver = Resolver(nameservers=["8.8.8.8", "8.8.4.4"])
        assert resolver.nameservers == ["8.8.8.8", "8.8.4.4"]

    def test_from_resolv_conf(self):
        text = "nameserver 10.0.0.1\nsearch corp.example.com\n"
        resolver = Resolver.from_resolv_conf(text)
        assert resolver.nameservers == ["10.0.0.1"]
        assert resolver.search == ["corp.example.com"]

    def test_from_config(self):
        config = ResolverConfig()
        config.nameservers = ["192.168.1.1"]
        config.timeout = 2.0
        resolver = Resolver(config=config)
        assert resolver.nameservers == ["192.168.1.1"]
        assert resolver.timeout == 2.0

    def test_set_nameservers(self):
        resolver = Resolver()
        resolver.nameservers = ["1.1.1.1"]
        assert resolver.nameservers == ["1.1.1.1"]

    def test_set_timeout(self):
        resolver = Resolver()
        resolver.timeout = 10.0
        assert resolver.timeout == 10.0


# --- Answer tests ---

def _make_response_with_answer(qname, rdtype, rdclass, records, rcode=0):
    """Build a DNS response message with answer records."""
    query = build_query(qname, rdtype, rdclass)
    response = build_response(query, rcode=rcode)
    if records:
        rrset = response.find_rrset(
            response.answer, qname, rdtype, rdclass, create=True
        )
        for rdata in records:
            rrset.add(rdata, ttl=300)
    return response


class TestAnswer:
    def test_answer_with_records(self):
        qname = name_from_text("example.com.")
        response = _make_response_with_answer(
            qname, RecordType.A, RecordClass.IN,
            [ARecord("93.184.216.34")]
        )
        answer = Answer(qname, RecordType.A, RecordClass.IN, response)
        assert answer.rrset is not None
        assert len(answer) == 1
        assert answer.qname == qname
        assert answer.rdtype == int(RecordType.A)
        assert answer.rdclass == int(RecordClass.IN)
        assert answer.response is response

    def test_answer_iteration(self):
        qname = name_from_text("example.com.")
        response = _make_response_with_answer(
            qname, RecordType.A, RecordClass.IN,
            [ARecord("1.2.3.4"), ARecord("5.6.7.8")]
        )
        answer = Answer(qname, RecordType.A, RecordClass.IN, response)
        records = list(answer)
        assert len(records) == 2

    def test_answer_empty(self):
        qname = name_from_text("example.com.")
        response = _make_response_with_answer(
            qname, RecordType.A, RecordClass.IN, []
        )
        answer = Answer(qname, RecordType.A, RecordClass.IN, response)
        assert answer.rrset is None
        assert len(answer) == 0
        assert list(answer) == []

    def test_answer_no_matching_type(self):
        qname = name_from_text("example.com.")
        response = _make_response_with_answer(
            qname, RecordType.A, RecordClass.IN,
            [ARecord("1.2.3.4")]
        )
        answer = Answer(qname, RecordType.AAAA, RecordClass.IN, response)
        assert answer.rrset is None


# --- Search list tests ---

class TestSearchList:
    def test_should_use_search_no_dots(self):
        resolver = Resolver.from_resolv_conf(
            "nameserver 127.0.0.1\nsearch example.com\n"
        )
        name = name_from_text("host")
        assert resolver._should_use_search(name) is True

    def test_should_not_use_search_with_dot(self):
        resolver = Resolver.from_resolv_conf(
            "nameserver 127.0.0.1\nsearch example.com\n"
        )
        name = name_from_text("host.sub")
        assert resolver._should_use_search(name) is False

    def test_should_use_search_ndots_2(self):
        resolver = Resolver.from_resolv_conf(
            "nameserver 127.0.0.1\nsearch example.com\noptions ndots:2\n"
        )
        name = name_from_text("host.sub")
        assert resolver._should_use_search(name) is True

    def test_get_query_names_with_search(self):
        resolver = Resolver.from_resolv_conf(
            "nameserver 127.0.0.1\nsearch example.com test.org\n"
        )
        names = resolver._get_query_names("host", RecordType.A)
        texts = [n.to_text() for n in names]
        assert "host.example.com." in texts
        assert "host.test.org." in texts
        assert "host." in texts

    def test_get_query_names_with_domain(self):
        resolver = Resolver.from_resolv_conf(
            "nameserver 127.0.0.1\ndomain example.com\n"
        )
        names = resolver._get_query_names("host", RecordType.A)
        texts = [n.to_text() for n in names]
        assert "host.example.com." in texts
        assert "host." in texts

    def test_get_query_names_absolute(self):
        resolver = Resolver.from_resolv_conf(
            "nameserver 127.0.0.1\nsearch example.com\n"
        )
        names = resolver._get_query_names("www.example.com.", RecordType.A)
        assert len(names) == 1
        assert names[0].to_text() == "www.example.com."

    def test_get_query_names_no_search(self):
        resolver = Resolver(nameservers=["127.0.0.1"])
        names = resolver._get_query_names("host", RecordType.A)
        assert len(names) >= 1
        assert names[0].to_text() == "host."


# --- Error classes ---

class TestErrors:
    def test_nxdomain_with_name(self):
        err = NXDOMAINError(qname="example.com")
        assert "example.com" in str(err)
        assert err.qname == "example.com"

    def test_nxdomain_without_name(self):
        err = NXDOMAINError()
        assert "does not exist" in str(err)
        assert err.qname is None

    def test_no_answer_with_name(self):
        err = NoAnswerError(qname="example.com")
        assert "example.com" in str(err)

    def test_no_answer_without_name(self):
        err = NoAnswerError()
        assert "No answer" in str(err)

    def test_no_nameservers(self):
        err = NoNameserversError("no servers")
        assert "no servers" in str(err)


# --- Resolver.resolve() with mocked transport ---

def _build_wire_response(query_wire, records, rcode=0):
    """Parse a query from wire, build a matching response, serialize it."""
    query = message_from_wire(query_wire)
    response = build_response(query, rcode=rcode)
    if records and query.question:
        q = query.question[0]
        rrset = response.find_rrset(
            response.answer, q.name, q.rdtype, q.rdclass, create=True
        )
        for rdata in records:
            rrset.add(rdata, ttl=300)
    return message_to_wire(response)


class TestResolveWithMock:
    def test_resolve_a_record(self):
        resolver = Resolver(nameservers=["127.0.0.1"])

        def mock_send(wire, ns, port=53, timeout=5.0):
            return _build_wire_response(wire, [ARecord("93.184.216.34")])

        with patch("dnscore.resolver._send_udp_query", side_effect=mock_send):
            answer = resolver.resolve("example.com.", RecordType.A)
            assert len(answer) == 1
            assert answer.rrset is not None

    def test_resolve_nxdomain(self):
        resolver = Resolver(nameservers=["127.0.0.1"])

        def mock_send(wire, ns, port=53, timeout=5.0):
            return _build_wire_response(wire, [], rcode=ResponseCode.NXDOMAIN)

        with patch("dnscore.resolver._send_udp_query", side_effect=mock_send):
            with pytest.raises(NXDOMAINError):
                resolver.resolve("nonexistent.example.com.", RecordType.A)

    def test_resolve_no_answer(self):
        resolver = Resolver(nameservers=["127.0.0.1"])

        def mock_send(wire, ns, port=53, timeout=5.0):
            return _build_wire_response(wire, [])

        with patch("dnscore.resolver._send_udp_query", side_effect=mock_send):
            with pytest.raises(NoAnswerError):
                resolver.resolve("example.com.", RecordType.AAAA)

    def test_resolve_tcp(self):
        resolver = Resolver(nameservers=["127.0.0.1"])

        def mock_send(wire, ns, port=53, timeout=5.0):
            return _build_wire_response(wire, [ARecord("1.2.3.4")])

        with patch("dnscore.resolver._send_tcp_query", side_effect=mock_send):
            answer = resolver.resolve("example.com.", RecordType.A, tcp=True)
            assert len(answer) == 1

    def test_resolve_string_rdtype(self):
        resolver = Resolver(nameservers=["127.0.0.1"])

        def mock_send(wire, ns, port=53, timeout=5.0):
            return _build_wire_response(wire, [ARecord("1.2.3.4")])

        with patch("dnscore.resolver._send_udp_query", side_effect=mock_send):
            answer = resolver.resolve("example.com.", "A")
            assert len(answer) == 1

    def test_resolve_timeout_raises_no_nameservers(self):
        import socket
        resolver = Resolver(nameservers=["127.0.0.1"])
        resolver._config.attempts = 1

        def mock_send(wire, ns, port=53, timeout=5.0):
            raise socket.timeout("timed out")

        with patch("dnscore.resolver._send_udp_query", side_effect=mock_send):
            with pytest.raises(NoNameserversError):
                resolver.resolve("example.com.", RecordType.A)

    def test_resolve_retries_on_servfail(self):
        resolver = Resolver(nameservers=["127.0.0.1"])
        resolver._config.attempts = 2
        call_count = [0]

        def mock_send(wire, ns, port=53, timeout=5.0):
            call_count[0] += 1
            if call_count[0] == 1:
                return _build_wire_response(wire, [], rcode=ResponseCode.SERVFAIL)
            return _build_wire_response(wire, [ARecord("1.2.3.4")])

        with patch("dnscore.resolver._send_udp_query", side_effect=mock_send):
            answer = resolver.resolve("example.com.", RecordType.A)
            assert len(answer) == 1
            assert call_count[0] == 2

    def test_resolve_tries_multiple_nameservers(self):
        import socket
        resolver = Resolver(nameservers=["10.0.0.1", "10.0.0.2"])
        resolver._config.attempts = 1
        servers_tried = []

        def mock_send(wire, ns, port=53, timeout=5.0):
            servers_tried.append(ns)
            if ns == "10.0.0.1":
                raise socket.timeout("timed out")
            return _build_wire_response(wire, [ARecord("1.2.3.4")])

        with patch("dnscore.resolver._send_udp_query", side_effect=mock_send):
            answer = resolver.resolve("example.com.", RecordType.A)
            assert len(answer) == 1
            assert "10.0.0.1" in servers_tried
            assert "10.0.0.2" in servers_tried

    def test_resolve_search_list_fallback(self):
        resolver = Resolver.from_resolv_conf(
            "nameserver 127.0.0.1\nsearch example.com\n"
        )

        def mock_send(wire, ns, port=53, timeout=5.0):
            query = message_from_wire(wire)
            qname = query.question[0].name.to_text()
            if qname == "host.example.com.":
                return _build_wire_response(wire, [], rcode=ResponseCode.NXDOMAIN)
            return _build_wire_response(wire, [ARecord("1.2.3.4")])

        with patch("dnscore.resolver._send_udp_query", side_effect=mock_send):
            answer = resolver.resolve("host", RecordType.A)
            assert len(answer) == 1

    def test_resolve_id_mismatch_retries(self):
        resolver = Resolver(nameservers=["127.0.0.1"])
        resolver._config.attempts = 2
        call_count = [0]

        def mock_send(wire, ns, port=53, timeout=5.0):
            call_count[0] += 1
            resp_wire = _build_wire_response(wire, [ARecord("1.2.3.4")])
            if call_count[0] == 1:
                bad = bytearray(resp_wire)
                bad[0] = (bad[0] + 1) & 0xFF
                return bytes(bad)
            return resp_wire

        with patch("dnscore.resolver._send_udp_query", side_effect=mock_send):
            answer = resolver.resolve("example.com.", RecordType.A)
            assert len(answer) == 1

"""DNS stub resolver.

Provides a high-level interface for performing DNS lookups using
system nameservers. Reads configuration from resolv.conf format,
supports search lists, and handles NXDOMAIN and NoAnswer conditions.
"""

import socket
import struct
import random
import time

from dnscore.domain_name import DomainName, from_text as name_from_text, ROOT
from dnscore.record_type import RecordType
from dnscore.record_class import RecordClass
from dnscore.message import DNSMessage, build_query, MessageSection
from dnscore.msg_flags import MessageFlag
from dnscore.resp_code import ResponseCode
from dnscore.record_sets import RRSet
from dnscore.wire_format import message_to_wire, message_from_wire
from dnscore.exceptions import DNSError, TimeoutError as DNSTimeoutError


class NXDOMAINError(DNSError):
    """The DNS query name does not exist."""
    def __init__(self, qname=None):
        self.qname = qname
        if qname:
            super().__init__(f"The DNS query name does not exist: {qname}")
        else:
            super().__init__("The DNS query name does not exist")


class NoAnswerError(DNSError):
    """The DNS query returned no answer records."""
    def __init__(self, qname=None):
        self.qname = qname
        if qname:
            super().__init__(f"No answer for: {qname}")
        else:
            super().__init__("No answer")


class NoNameserversError(DNSError):
    """No nameservers could be reached."""
    pass


class Answer:
    """The result of a DNS resolution.

    Provides access to the response message and the answer RRSet.
    """

    def __init__(self, qname, rdtype, rdclass, response):
        self._qname = qname
        self._rdtype = int(rdtype)
        self._rdclass = int(rdclass)
        self._response = response
        self._rrset = self._find_answer()

    def _find_answer(self):
        """Find the matching RRSet in the answer section."""
        for rrset in self._response.answer:
            if (isinstance(rrset, RRSet) and
                    rrset.name == self._qname and
                    rrset.rdtype == self._rdtype and
                    rrset.rdclass == self._rdclass):
                return rrset
        for rrset in self._response.answer:
            if isinstance(rrset, RRSet) and rrset.rdtype == self._rdtype:
                return rrset
        return None

    @property
    def qname(self):
        return self._qname

    @property
    def rdtype(self):
        return self._rdtype

    @property
    def rdclass(self):
        return self._rdclass

    @property
    def response(self):
        return self._response

    @property
    def rrset(self):
        return self._rrset

    def __iter__(self):
        if self._rrset:
            return iter(self._rrset)
        return iter([])

    def __len__(self):
        if self._rrset:
            return len(self._rrset)
        return 0


class ResolverConfig:
    """DNS resolver configuration parsed from resolv.conf format."""

    def __init__(self):
        self.nameservers = []
        self.search = []
        self.domain = None
        self.timeout = 5.0
        self.attempts = 3
        self.ndots = 1

    @classmethod
    def from_text(cls, text):
        """Parse resolv.conf format text."""
        config = cls()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            directive = parts[0].lower()
            if directive == "nameserver":
                config.nameservers.append(parts[1])
            elif directive == "search":
                config.search = parts[1:]
            elif directive == "domain":
                config.domain = parts[1]
            elif directive == "options":
                for opt in parts[1:]:
                    if opt.startswith("timeout:"):
                        try:
                            config.timeout = float(opt.split(":")[1])
                        except ValueError:
                            pass
                    elif opt.startswith("attempts:"):
                        try:
                            config.attempts = int(opt.split(":")[1])
                        except ValueError:
                            pass
                    elif opt.startswith("ndots:"):
                        try:
                            config.ndots = int(opt.split(":")[1])
                        except ValueError:
                            pass
        return config

    @classmethod
    def from_file(cls, path="/etc/resolv.conf"):
        """Read configuration from a file."""
        try:
            with open(path, "r") as f:
                return cls.from_text(f.read())
        except (IOError, OSError):
            config = cls()
            config.nameservers = ["127.0.0.1"]
            return config


def _send_udp_query(wire, nameserver, port=53, timeout=5.0):
    """Send a DNS query over UDP and return the response bytes."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(wire, (nameserver, port))
        data, addr = sock.recvfrom(65535)
        return data
    finally:
        sock.close()


def _send_tcp_query(wire, nameserver, port=53, timeout=5.0):
    """Send a DNS query over TCP and return the response bytes."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((nameserver, port))
        length_prefix = struct.pack("!H", len(wire))
        sock.sendall(length_prefix + wire)
        length_data = b""
        while len(length_data) < 2:
            chunk = sock.recv(2 - len(length_data))
            if not chunk:
                raise DNSError("connection closed")
            length_data += chunk
        response_len = struct.unpack("!H", length_data)[0]
        response_data = b""
        while len(response_data) < response_len:
            chunk = sock.recv(response_len - len(response_data))
            if not chunk:
                raise DNSError("connection closed")
            response_data += chunk
        return response_data
    finally:
        sock.close()


class Resolver:
    """A DNS stub resolver.

    Sends queries to configured nameservers and returns parsed responses.
    """

    def __init__(self, nameservers=None, config=None):
        if config is not None:
            self._config = config
        else:
            self._config = ResolverConfig()
            if nameservers:
                self._config.nameservers = list(nameservers)
            else:
                self._config.nameservers = ["127.0.0.1"]

    @property
    def nameservers(self):
        return self._config.nameservers

    @nameservers.setter
    def nameservers(self, value):
        self._config.nameservers = list(value)

    @property
    def search(self):
        return self._config.search

    @property
    def timeout(self):
        return self._config.timeout

    @timeout.setter
    def timeout(self, value):
        self._config.timeout = value

    @classmethod
    def from_resolv_conf(cls, text):
        """Create a Resolver from resolv.conf format text."""
        config = ResolverConfig.from_text(text)
        return cls(config=config)

    def _should_use_search(self, name):
        """Check if the search list should be applied."""
        name_str = name.to_text(omit_final_dot=True)
        dot_count = name_str.count(".")
        return dot_count < self._config.ndots

    def _get_query_names(self, name, rdtype):
        """Get the list of names to query, applying search list if needed."""
        if isinstance(name, str):
            if name.endswith("."):
                name = name_from_text(name)
            else:
                name = name_from_text(name, origin=None)

        if name.is_absolute():
            return [name]

        names = []
        if self._should_use_search(name) and self._config.search:
            for suffix in self._config.search:
                suffix_name = name_from_text(suffix)
                if not suffix_name.is_absolute():
                    suffix_name = suffix_name.derelativize(ROOT)
                names.append(name.derelativize(suffix_name))
        elif self._should_use_search(name) and self._config.domain:
            domain_name = name_from_text(self._config.domain)
            if not domain_name.is_absolute():
                domain_name = domain_name.derelativize(ROOT)
            names.append(name.derelativize(domain_name))

        if not name.is_absolute():
            names.append(name.derelativize(ROOT))

        return names if names else [name.derelativize(ROOT)]

    def resolve(self, name, rdtype=RecordType.A, rdclass=RecordClass.IN,
                tcp=False, raise_on_no_answer=True):
        """Resolve a DNS name.

        name: the domain name to look up
        rdtype: the record type to query
        rdclass: the record class
        tcp: if True, use TCP instead of UDP
        raise_on_no_answer: if True, raise NoAnswerError when answer is empty

        Returns an Answer object.
        Raises NXDOMAINError if the name does not exist.
        Raises NoAnswerError if no matching records are found.
        Raises NoNameserversError if no nameservers respond.
        """
        if isinstance(rdtype, str):
            from dnscore.record_type import type_from_text
            rdtype = type_from_text(rdtype)

        query_names = self._get_query_names(name, rdtype)

        last_error = None
        for qname in query_names:
            try:
                answer = self._do_query(qname, rdtype, rdclass, tcp)
                return answer
            except NXDOMAINError as e:
                last_error = e
                continue
            except (DNSTimeoutError, NoNameserversError) as e:
                last_error = e
                continue

        if isinstance(last_error, NXDOMAINError):
            raise last_error
        if last_error:
            raise last_error
        raise NXDOMAINError(name)

    def _do_query(self, qname, rdtype, rdclass, tcp=False):
        """Send a query to nameservers and parse the response."""
        query = build_query(qname, rdtype, rdclass)
        wire = message_to_wire(query)

        send_fn = _send_tcp_query if tcp else _send_udp_query

        errors = []
        for nameserver in self._config.nameservers:
            for attempt in range(self._config.attempts):
                try:
                    response_data = send_fn(
                        wire, nameserver, timeout=self._config.timeout
                    )
                    response = message_from_wire(response_data)

                    if response.id != query.id:
                        continue

                    rcode = response.rcode()
                    if rcode == ResponseCode.NXDOMAIN:
                        raise NXDOMAINError(qname)
                    if rcode == ResponseCode.SERVFAIL:
                        continue
                    if rcode != ResponseCode.NOERROR:
                        continue

                    answer = Answer(qname, rdtype, rdclass, response)
                    if answer.rrset is None or len(answer.rrset) == 0:
                        raise NoAnswerError(qname)
                    return answer

                except socket.timeout:
                    errors.append(DNSTimeoutError(f"timeout querying {nameserver}"))
                except OSError as e:
                    errors.append(DNSError(str(e)))

        if errors:
            raise NoNameserversError(f"no nameservers responded: {errors[0]}")
        raise NoNameserversError("no nameservers configured")

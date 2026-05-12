"""DNS dynamic update message construction (RFC 2136).

Builds DNS UPDATE messages for adding, deleting, and replacing resource
records in a zone, with optional prerequisite conditions.
"""

import random

from dnscore.domain_name import DomainName, from_text as name_from_text
from dnscore.record_type import RecordType
from dnscore.record_class import RecordClass
from dnscore.record_sets import RRSet
from dnscore.message import DNSMessage, QuestionEntry
from dnscore.op_code import OpCode
from dnscore.record_data import create_from_text


class UpdateSection:
    """Section indices for DNS UPDATE messages."""
    ZONE = 0
    PREREQ = 1
    UPDATE = 2
    ADDITIONAL = 3


class UpdateMessage(DNSMessage):
    """A DNS UPDATE message.

    The four standard message sections are reinterpreted:
      - Question  -> Zone (which zone to update)
      - Answer    -> Prerequisite (conditions that must be true)
      - Authority -> Update (operations to perform)
      - Additional -> Additional data
    """

    def __init__(self, zone, rdclass=RecordClass.IN, msg_id=None):
        super().__init__(msg_id)
        self.set_opcode(OpCode.UPDATE)

        if isinstance(zone, str):
            zone = name_from_text(zone)
        self._zone_name = zone
        self._zone_rdclass = int(rdclass)

        self.add_question(zone, RecordType.SOA, rdclass)

    @property
    def zone_name(self):
        return self._zone_name

    @property
    def zone_rdclass(self):
        return self._zone_rdclass

    @property
    def zone_section(self):
        return self._question

    @property
    def prerequisite(self):
        return self._answer

    @property
    def update_section(self):
        return self._authority

    def _find_or_create_rrset(self, section, name, rdtype, rdclass, ttl=0):
        for rrset in section:
            if (isinstance(rrset, RRSet) and
                    rrset.name == name and
                    rrset.rdtype == int(rdtype) and
                    rrset.rdclass == int(rdclass)):
                return rrset
        rrset = RRSet(name, int(rdtype), int(rdclass), ttl)
        section.append(rrset)
        return rrset

    def _ensure_name(self, name):
        if isinstance(name, str):
            return name_from_text(name)
        return name

    # --- Prerequisites ---

    def present(self, name, rdtype=None, *rdata_args):
        """Add a prerequisite that a name or record exists.

        present(name) — name must exist (any type)
        present(name, rdtype) — rdtype must exist at name
        present(name, rdtype, rdata_text...) — specific records must exist
        """
        name = self._ensure_name(name)

        if rdtype is None:
            rrset = self._find_or_create_rrset(
                self.prerequisite, name, RecordType.ANY, RecordClass.ANY, ttl=0
            )
            return

        if isinstance(rdtype, str):
            from dnscore.record_type import type_from_text
            rdtype = type_from_text(rdtype)

        if not rdata_args:
            rrset = self._find_or_create_rrset(
                self.prerequisite, name, rdtype, RecordClass.ANY, ttl=0
            )
        else:
            rrset = self._find_or_create_rrset(
                self.prerequisite, name, rdtype, self._zone_rdclass, ttl=0
            )
            for text in rdata_args:
                rdata = create_from_text(int(rdtype), text, rdclass=self._zone_rdclass)
                rrset.add(rdata, ttl=0)

    def absent(self, name, rdtype=None):
        """Add a prerequisite that a name or rdtype does not exist.

        absent(name) — name must not exist
        absent(name, rdtype) — rdtype must not exist at name
        """
        name = self._ensure_name(name)

        if rdtype is None:
            rrset = self._find_or_create_rrset(
                self.prerequisite, name, RecordType.ANY, RecordClass.NONE, ttl=0
            )
        else:
            if isinstance(rdtype, str):
                from dnscore.record_type import type_from_text
                rdtype = type_from_text(rdtype)
            rrset = self._find_or_create_rrset(
                self.prerequisite, name, rdtype, RecordClass.NONE, ttl=0
            )

    # --- Update operations ---

    def add(self, name, ttl, rdtype, *rdata_args):
        """Add records to the zone.

        name: domain name
        ttl: TTL for the records
        rdtype: record type
        rdata_args: one or more rdata text strings
        """
        name = self._ensure_name(name)
        if isinstance(rdtype, str):
            from dnscore.record_type import type_from_text
            rdtype = type_from_text(rdtype)

        rrset = self._find_or_create_rrset(
            self.update_section, name, rdtype, self._zone_rdclass, ttl=int(ttl)
        )
        for text in rdata_args:
            rdata = create_from_text(int(rdtype), text, rdclass=self._zone_rdclass)
            rrset.add(rdata, ttl=int(ttl))

    def delete(self, name, rdtype=None, *rdata_args):
        """Delete records from the zone.

        delete(name) — delete all records at name
        delete(name, rdtype) — delete all records of type at name
        delete(name, rdtype, rdata_text...) — delete specific records
        """
        name = self._ensure_name(name)

        if rdtype is None:
            self._find_or_create_rrset(
                self.update_section, name, RecordType.ANY, RecordClass.ANY, ttl=0
            )
            return

        if isinstance(rdtype, str):
            from dnscore.record_type import type_from_text
            rdtype = type_from_text(rdtype)

        if not rdata_args:
            self._find_or_create_rrset(
                self.update_section, name, rdtype, RecordClass.ANY, ttl=0
            )
        else:
            rrset = self._find_or_create_rrset(
                self.update_section, name, rdtype, RecordClass.NONE, ttl=0
            )
            for text in rdata_args:
                rdata = create_from_text(int(rdtype), text, rdclass=self._zone_rdclass)
                rrset.add(rdata, ttl=0)

    def replace(self, name, ttl, rdtype, *rdata_args):
        """Replace all records of a type with new records.

        First deletes the existing rrset, then adds the new records.
        """
        name = self._ensure_name(name)
        if isinstance(rdtype, str):
            from dnscore.record_type import type_from_text
            rdtype = type_from_text(rdtype)

        self._find_or_create_rrset(
            self.update_section, name, rdtype, RecordClass.ANY, ttl=0
        )

        rrset = self._find_or_create_rrset(
            self.update_section, name, rdtype, self._zone_rdclass, ttl=int(ttl)
        )
        for text in rdata_args:
            rdata = create_from_text(int(rdtype), text, rdclass=self._zone_rdclass)
            rrset.add(rdata, ttl=int(ttl))

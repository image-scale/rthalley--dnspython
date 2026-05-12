# Todo

## Plan
Implement the DNS toolkit top-down starting with the most important user-facing features. Begin with DNS name handling (the fundamental building block), then add the type system, record implementations, message construction, wire format, zone management, and resolver. Each task delivers complete, testable functionality.

## Tasks
- [x] Task 1: DNS name handling — parse, create, compare, and manipulate DNS domain names with support for absolute/relative names, wildcards, label operations, case-insensitive comparison, and text/wire format conversion (core package + name module + tests)
- [x] Task 2: DNS type system and protocol constants — record type enumerations (A, AAAA, MX, TXT, SOA, etc.), record class enumerations (IN, CH), message flags (QR, AA, TC, RD, RA), operation codes (QUERY, STATUS, UPDATE), response codes (NOERROR, NXDOMAIN, SERVFAIL), and TTL parsing from BIND-style time strings (type/class/flags/opcode/rcode/ttl modules + tests)
- [x] Task 3: Network address utilities and core DNS records — IPv4/IPv6 address text-to-binary conversion, plus SOA, A, AAAA, NS, CNAME, MX, TXT, PTR, SRV record types with text representation, wire format serialization, and base record data framework (inet/ipv4/ipv6/rdata/record modules + tests)
- [x] Task 4: Record collections and DNS messages — resource record sets (rdatasets with TTL), named record sets (rrsets), zone nodes, plus DNS message construction with question/answer/authority/additional sections and query creation helpers (rdataset/rrset/node/message modules + tests)
- [x] Task 5: Wire format serialization and parsing — serialize DNS messages to binary wire format with name compression, parse binary DNS messages back to objects, complete round-trip support (wire parser/renderer modules + tests)
- [x] Task 6: Tokenizer and zone file parsing — tokenize DNS master file text with support for quoted strings, comments, parentheses for multi-line, escape sequences; parse zone files with $ORIGIN and $TTL directives (tokenizer/zonefile modules + tests)
- [x] Task 7: DNS zone management — zone class for managing DNS zone data as a mapping of names to nodes, node lookups, iteration, zone file text output, zone validation for SOA and NS records (zone module + tests)
- [x] Task 8: Stub resolver — high-level DNS resolver for looking up records using system nameservers, configuration from resolv.conf, search list support, NXDOMAIN and NoAnswer handling (resolver module + tests)
- [x] Task 9: Reverse DNS and utility features — convert IP addresses to reverse DNS names (in-addr.arpa, ip6.arpa) and back, serial number arithmetic with wraparound per RFC 1982, E.164 phone number to ENUM name conversion (reversename/serial/e164 modules + tests)
- [ ] Task 10: Dynamic DNS updates — create DNS UPDATE messages for adding, deleting, and replacing records in a zone, with prerequisite conditions (update module + tests)

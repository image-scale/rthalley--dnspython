# Acceptance Criteria

## Tasks 1-7: Completed (see progress.md)

## Task 8: Stub resolver (completed)

### Acceptance Criteria
- [x] A Resolver class can be created with default or custom nameserver addresses
- [x] Resolver can read nameserver configuration from resolv.conf format text
- [x] resolv.conf parsing extracts nameserver addresses and search/domain directives
- [x] Resolver.resolve(name, rdtype) sends a DNS query and returns an Answer object
- [x] The Answer object provides access to the RRSet with the response records
- [x] NXDOMAIN responses raise a specific NXDOMAINError exception
- [x] NoAnswer responses (empty answer section) raise a NoAnswerError exception
- [x] The resolver uses UDP transport by default
- [x] The resolver retries with different nameservers on failure
- [x] Search list is applied when configured and the name has no dots

## Task 9: Reverse DNS and utility features

### Acceptance Criteria
- [x] from_address() converts an IPv4 address to a reverse DNS name under in-addr.arpa
- [x] from_address() converts an IPv6 address to a reverse DNS name under ip6.arpa
- [x] to_address() converts a reverse DNS name back to an IPv4 address string
- [x] to_address() converts a reverse DNS name back to an IPv6 address string
- [x] Serial class implements RFC 1982 comparison with wraparound semantics
- [x] Serial arithmetic (add/subtract) uses modular 2^bits arithmetic
- [x] Serial rejects deltas exceeding 2^(bits-1) - 1
- [x] from_e164() converts a phone number string to an ENUM DNS name under e164.arpa
- [x] to_e164() converts an ENUM DNS name back to a phone number string
- [x] Non-digit characters in E.164 input are silently stripped

## Task 10: Dynamic DNS updates

### Acceptance Criteria
- [x] UpdateMessage creates a message with UPDATE opcode and SOA zone entry
- [x] present(name) adds a prerequisite that the name exists
- [x] present(name, rdtype) adds a prerequisite that the rdtype exists at name
- [x] present(name, rdtype, rdata) adds a prerequisite for specific records
- [x] absent(name) adds a prerequisite that the name does not exist
- [x] absent(name, rdtype) adds a prerequisite that the rdtype does not exist
- [x] add(name, ttl, rdtype, rdata) adds records to the update section
- [x] delete(name) deletes all records at name
- [x] delete(name, rdtype) deletes all records of a type
- [x] delete(name, rdtype, rdata) deletes specific records
- [x] replace(name, ttl, rdtype, rdata) replaces all records of a type

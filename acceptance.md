# Acceptance Criteria

## Tasks 1-7: Completed (see progress.md)

## Task 8: Stub resolver

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

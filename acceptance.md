# Acceptance Criteria

## Task 1: DNS name handling
- [x] All 15 criteria met (see Round 1)

## Task 2: DNS type system and protocol constants

### Acceptance Criteria
- [ ] Record types can be created from text ("A" -> type 1) and converted back to text
- [ ] Unknown type numbers use "TYPENN" format (e.g., TYPE999)
- [ ] Standard types include A (1), AAAA (28), CNAME (5), MX (15), NS (2), PTR (12), SOA (6), TXT (16), SRV (33)
- [ ] Meta types like ANY (255), AXFR (252), OPT (41) are recognized and identifiable as meta
- [ ] Record classes can be created from text ("IN" -> class 1) and converted back
- [ ] Unknown class numbers use "CLASSNN" format
- [ ] Standard classes include IN (1), CH (3), HS (4), NONE (254), ANY (255)
- [ ] Meta classes (ANY, NONE) are identifiable
- [ ] DNS message flags (QR, AA, TC, RD, RA, AD, CD) can be set, read, and converted to/from text
- [ ] Operation codes (QUERY=0, STATUS=2, NOTIFY=4, UPDATE=5) can be created from text, converted to text, and extracted from message flags
- [ ] Response codes (NOERROR=0, FORMERR=1, SERVFAIL=2, NXDOMAIN=3, REFUSED=5) support text conversion and extraction from flags
- [ ] Extended response codes use both message flags (low 4 bits) and EDNS flags (high 8 bits)
- [ ] TTL parsing supports integer values and BIND time strings like "1h30m", "1w2d", "300"
- [ ] TTL values are validated (0 to 2^32-1)
- [ ] Invalid TTL strings raise appropriate errors

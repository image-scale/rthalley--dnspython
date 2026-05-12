# Acceptance Criteria

## Tasks 1-3: Completed (see progress.md)

## Task 4: Record collections and DNS messages

### Acceptance Criteria
- [ ] An RRDataSet holds multiple record data objects of the same type/class with a shared TTL
- [ ] Adding a record with different TTL uses the minimum TTL
- [ ] RRDataSets can be converted to text showing all records
- [ ] An RRSet associates an owner name with an RRDataSet
- [ ] RRSets can be created from text, from individual rdata, or from lists
- [ ] A ZoneNode holds multiple RRDataSets for different types at a single name
- [ ] DNS messages have question, answer, authority, and additional sections
- [ ] Messages have an ID, flags, opcode, and rcode
- [ ] A query message can be created for a name/type/class combination
- [ ] Messages can be converted to text showing all sections
- [ ] Messages track the QR flag to distinguish queries from responses
- [ ] The find_rrset method locates an RRSet in a message section by name/type/class

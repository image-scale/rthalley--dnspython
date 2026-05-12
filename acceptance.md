# Acceptance Criteria

## Tasks 1-6: Completed (see progress.md)

## Task 7: DNS zone management

### Acceptance Criteria
- [ ] A Zone object stores DNS data as a mapping of names to nodes
- [ ] Zones can be loaded from zone file text using from_text()
- [ ] Zones have an origin name and a default rdclass
- [ ] Finding a node by name returns its rdatasets
- [ ] Finding a non-existent node returns None or raises KeyError
- [ ] Zone data can be iterated (names and nodes)
- [ ] Zones can be exported to text format matching zone file syntax
- [ ] Adding/removing records and rdatasets from zones works
- [ ] Zones validate the presence of SOA and NS records at the origin
- [ ] Zones support the dict-like interface (len, contains, getitem)

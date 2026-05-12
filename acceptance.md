# Acceptance Criteria

## Task 1: DNS name handling

### Acceptance Criteria
- [ ] Create a DNS name from text like "example.com." and get it back as text
- [ ] An absolute name ends with a dot (root label), a relative name does not
- [ ] Names are case-insensitive: "Example.COM." equals "example.com."
- [ ] Names support label access: get individual labels, count them, get label count
- [ ] A name can be checked as subdomain/superdomain of another name
- [ ] Concatenating a relative name with an absolute name produces an absolute name
- [ ] The root name "." has zero labels (just the empty root label)
- [ ] Names can be compared and sorted in DNSSEC canonical order
- [ ] Names can be converted to wire format (binary) and parsed back
- [ ] Wildcard names (starting with "*") are detected correctly
- [ ] Names are hashable and can be used as dictionary keys
- [ ] Empty label in a name raises an appropriate error
- [ ] from_text(".") produces the root name
- [ ] Relative names can be made absolute by appending an origin
- [ ] Names support parent() to get the parent domain

# Acceptance Criteria

## Tasks 1-5: Completed (see progress.md)

## Task 6: Tokenizer and zone file parsing

### Acceptance Criteria
- [ ] Tokenizer reads identifiers (unquoted tokens) from text
- [ ] Tokenizer handles quoted strings preserving spaces inside quotes
- [ ] Tokenizer handles semicolon comments (rest of line ignored)
- [ ] Tokenizer supports parentheses for multi-line grouping
- [ ] Tokenizer handles backslash escape sequences (\\DDD and \\X)
- [ ] Tokenizer recognizes end-of-line and end-of-file
- [ ] Zone file parser processes $ORIGIN directive to set the origin
- [ ] Zone file parser processes $TTL directive to set default TTL
- [ ] Zone file parser reads resource records with owner, TTL, class, type, and rdata
- [ ] Zone file parser handles @ as the current origin name
- [ ] Zone file parser handles blank owner names (continuation of previous owner)
- [ ] Zone file parser produces a collection of (name, rdataset) pairs

# aegis-relay

`aegis-relay` is the untrusted store-and-forward service for AMP envelopes and encrypted blobs.

It should be boring in the best possible way:

- validate the outer envelope shape
- store opaque ciphertext safely
- return recipient-scoped message sets
- never require plaintext access

## Early goals

- file-backed storage for local development
- simple HTTP API
- recipient-indexed fetch
- size limits and basic retention hooks
- a clean boundary for future auth, quotas, and anti-replay bookkeeping

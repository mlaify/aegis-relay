# Security Policy

## Status

This repository is part of the Aegis `v0.1.0-alpha` prototype effort.

- It is not production-ready.
- Demo crypto and experimental-PQ components are non-production.
- Security properties may change as RFCs and implementations evolve.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately to project maintainers rather than opening a public issue.

Include:

- affected repo and commit/version
- reproduction steps and impact
- whether identity, relay, gateway, or crypto boundaries are affected

Maintainers should acknowledge receipt and coordinate a fix/update path before public disclosure.

## Scope Notes

- Relay remains a zero-trust transport/storage component.
- Gateway remains outside trusted core and is policy/scaffold oriented in alpha.
- Production PQ/resolver/signature lifecycle guarantees are out of scope for v0.1.0-alpha.

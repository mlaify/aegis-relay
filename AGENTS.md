# AGENTS.md

## Project purpose
This repository is part of the Aegis secure messaging platform.

## Rules
- Preserve protocol compatibility with `aegis-spec`.
- Prefer small, reviewable commits.
- Do not invent new wire fields without updating the spec.
- Do not move gateway logic into core crates.
- Keep private headers encrypted by default.
- Treat relays as untrusted infrastructure.
- For crypto changes, prefer trait boundaries and incremental integration.
- When unsure, propose the smallest viable change.

## Build/test expectations
- Run formatting before finalizing changes.
- Run linting if configured.
- Run tests relevant to changed code.
- If a dependency spans repos, document required follow-up work.

## Repo-specific notes
(Add per-repo notes here.)

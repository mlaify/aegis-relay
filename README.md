# aegis-relay

Reference relay server for Aegis.

For local end-to-end developer workflow (including running this relay with `aegit`), see:

- `../aegit-cli/DEV-SETUP.md`

## Endpoints

- `GET /healthz`
- `POST /v1/envelopes`
- `GET /v1/envelopes/:recipient_id`

## Behavior

- `POST /v1/envelopes` accepts `StoreEnvelopeRequest` JSON from `aegis-api-types` and persists the embedded `Envelope`.
- `GET /v1/envelopes/:recipient_id` returns `FetchEnvelopeResponse` JSON from `aegis-api-types`.
- `aegit relay fetch --out <dir>` can materialize that response into individual envelope files for local opening with `aegit msg open`.

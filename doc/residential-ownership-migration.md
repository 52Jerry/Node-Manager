# Atomic residential ownership migration

`POST /api/user/migrate-residential-ownership` requires bearer authentication and
`Idempotency-Key` (missing key: 428). JSON fields:

- `sourceUserId`: existing historical user ID. Both early random IDs and later
  `res-*` IDs are accepted; the live proxy and resource proof below must match.
- `targetUserId`: `primary-<accessProfileId>`.
- `resourceId`, `subscriptionId`, `accessProfileId`: positive allocation identifiers.
- `targetUuid`: UUID for the purchased subscription profile.
- `expectedProxy`: exact `server`, `port`, `username`, `password` of its SOCKS exit.
- `expiresAt`: future ISO timestamp supplied by the entitlement owner.

The caller must first establish the purchased resource/subscription relationship.
The node verifies registry ownership, exact proxy identity (including credentials),
exclusive routes/authentication, a single non-shared old UUID, and an unoccupied
target. Existing resource metadata must match. Ambiguity or mismatch returns 409
without writing configuration. There is no fallback that steals an outbound.

A successful migration renames registry ownership, managed inbound auth labels,
SOCKS usernames that equal the old identity, outbound tags and route references
under one configuration lock and one reload. VLESS/VMess/Trojan credentials rotate
to `targetUuid`; local SOCKS passwords and explicit custom usernames are retained.
Purchased expiration replaces the old expiration; only an expiration block is
removed. Access/traffic policy blocks cause rejection. WireGuard peers are not
reassigned: subsequent reconciliation must provision peers for the new owner.

Response includes `success`, `userId`, `sourceUserId`, `resourceId`, `subscriptionId`,
`uuid`, `expiresAt`, `migrated`. The first success has `migrated=true`; a live-verified
retry has `migrated=false` and does not reload. Same-key changed requests return 409.
The registry stores a non-secret migration proof; idempotency storage contains only
a request fingerprint. Validation errors do not echo proxy credentials. Runtime
reload failure restores the prior registry through the standard mutation transaction.

This endpoint does not move historical traffic store entries or transfer existing
WireGuard peer ownership. It does not operate on flux_agent.

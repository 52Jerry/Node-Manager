# sing-box

The universal proxy platform.

[![Packaging status](https://repology.org/badge/vertical-allrepos/sing-box.svg)](https://repology.org/project/sing-box/versions)

## Documentation

https://sing-box.sagernet.org

## License

```
Copyright (C) 2022 by nekohasekai <contact-sagernet@sekai.icu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.

In addition, no derivative work may use the name or imply association
with this application without prior consent.
```
## NiuSu user runtime extension

This local branch is based on v1.13.18. Named VLESS, AEAD VMess and authenticated
SOCKS users can be added, removed, reordered or have credentials changed without
recreating listeners. User-specific direct/SOCKS outbounds and simple
`auth_user` route/reject rules are prepared before publication. Only users whose
credentials or effective policy changed have their existing sessions closed.
Native mux parents, sing-mux parents, TCP streams and SOCKS UDP associations are
tracked by credential identity rather than a user-array position or outbound tag.

Start the optional management server with an absolute Unix socket path in a
private directory owned by the service account:

```sh
sing-box --management-socket /run/niusu/users.sock -c /etc/sing-box/config.json run
curl --unix-socket /run/niusu/users.sock http://localhost/management/v1/status
```

The socket has mode `0600`; it is never exposed on a TCP port. An existing socket
path is not overwritten. After a crash, remove a stale socket only after checking
that no instance still owns it.

`GET /management/v1/status` returns `instanceId`, `revision`, `contentHash` and
`activeSessions` (managed authenticated parent sessions, not mux child streams).
`PUT /management/v1/users` accepts a complete desired sing-box configuration:

```json
{
  "expectedInstanceId": "copy the current instanceId from status",
  "expectedRevision": 0,
  "config": {
    "log": {"disabled": true},
    "inbounds": [],
    "outbounds": [{"type": "direct", "tag": "direct"}]
  }
}
```

The configuration above illustrates the request envelope; replace `config` with
the complete configuration for the running instance. Send it from a private file:

```sh
curl --unix-socket /run/niusu/users.sock -X PUT \
  -H 'Content-Type: application/json' --data-binary @update-request.json \
  http://localhost/management/v1/users
```

A successful response includes the new revision/hash and `closedSessions`.
Identical desired content is idempotent within an instance. A changed instance or
stale revision is rejected with HTTP 409; invalid/unsupported changes with HTTP
422. A timeout does not establish failure: query status and compare the desired
hash. Before proving that the old configuration remains applied, issue a CAS
fence to invalidate any delayed PUT with the old revision. If `cleanupPending` is true,
the configuration is already committed; it must not be treated as a rolled-back
request.

`POST /management/v1/preview` accepts `{"config": {...}}` and returns the current
`runtime` status, normalized desired `contentHash` and `supported` boolean without
mutation. Agents should obtain this fingerprint from the core, since typed option
defaults and JSON field normalization cannot be reproduced by generic JSON hashing.
`POST /management/v1/fence` accepts `expectedInstanceId` and `expectedRevision`;
on a match it advances the revision without changing configuration. A mismatch
returns 409. A failed/unavailable fence leaves recovery unproven.

SOCKS inbounds managed this way should specify `"require_auth": true`. Empty user
tables then reject connections both immediately and after restart. Deleting the
last authenticated SOCKS account without this flag is rejected, so a future
restart cannot silently reopen an anonymous proxy. Explicitly anonymous legacy
SOCKS inbounds retain their previous behavior.

`GET /management/v1/counters` returns per-inbound/per-authenticated-user cumulative
upload/download bytes plus `instanceId`. Closed and deleted users' totals remain
available for the process lifetime. Collectors must persist these values and use
the instance ID as the process epoch; do not add them to native counters for the
same traffic a second time.

The API updates runtime state only. Node Manager remains responsible for its
configuration/registry lock, durable desired configuration, transaction journal,
startup reconciliation and billing persistence. The companion Node Manager now
provides an opt-in `singbox.runtime_socket` mode for these responsibilities, using
preview, CAS publication, recovery fences and cumulative counters. See its
`docs/singbox-runtime-integration.md`. Existing VLESS generation processes/NAT
must be migrated separately.

Global settings, listeners/TLS/Reality, default/shared/dependent outbounds,
selector/urltest groups, rule sets, logical/inverted rules and legacy VMess
AlterId changes are outside the user transaction. They are rejected while the
current instance keeps serving. Trojan/WireGuard and other protocols keep their
existing implementation and are not dynamically changed by this extension.
SIGHUP uses the same user transaction; disruptive topology reload is disabled
unless the operator starts the process with `--allow-disruptive-reload`.

Core validation:

```sh
go test -race -timeout 180s . ./common/userstate ./protocol/vless \
  ./protocol/vmess ./protocol/socks ./route ./cmd/sing-box
```

The integration tests use loopback echo/marker servers. They verify continuous
unaffected-user transfers through credential rotation, deletion, 100 updates,
new user/outbound creation, actual outbound replacement, UDP/native mux, idle
mux/UDP revocation, TLS Vision, replay protection, cumulative traffic, failure
atomicity and HTTP instance/revision fences. Linux build/runtime staging is still
required before replacing a production binary. The Windows LLVM-MinGW test
linker may require `-ldflags=-extldflags=-Wl,--disable-dynamicbase` for the race
runtime's address layout; that flag is only for local test executables.


## r3 bounded runtime management (2026-10-28)

The paired r3 Agent uses `PUT /management/v1/configuration` for atomic user,
outbound and route updates. `/management/v1/users` remains a compatibility alias.
`PUT /management/v1/routes` replaces the user-scoped rules/outbounds snapshot
while preserving inbound authentication. It requires `expectedInstanceId`,
`expectedRevision`, `rules`, and `outbounds`; the same topology validation applies.

Configuration/preview/route handlers admit one heavy request before decoding;
excess requests receive HTTP 429 and Retry-After. Status reads use cached committed
metadata rather than rehashing the configuration. Agent persistence, bounded FIFO
coalescing and task recovery are described in `Node Manager/docs/runtime-write-queue.md`.
This remains a local candidate; no production generation migration is automatic.

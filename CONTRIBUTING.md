# Contributing

Open Folio Connect is a reimplementation of the Wealthfolio Connect backend
with an explicit, narrow scope: encrypted device sync for personal use. Pull
requests that expand scope (broker sync, billing, multi-user, social login)
will be declined by design.

## Development

Requirements: Go 1.27.2 and PostgreSQL. 

```sh
make run                 # build and run
make test                # unit + contract tests
make lint                # gofmt check and go vet
make e2e                 # end-to-end flow against a running server
make docker-build        # build a multi-arch image and push it to the registry
```

`make e2e` needs a running server and a database. It drives the full lifecycle
(sign in, enroll, bootstrap keys, push and pull, upload and download a snapshot,
pair a second device, revoke, reset) and asserts the wire contract at each
step. It is re-runnable (each run resets team sync first).

## Publishing an image

```sh
make docker-build
make docker-build PLATFORMS=linux/amd64        # single architecture
```

`make docker-build` cross-compiles for `linux/amd64` and `linux/arm64` and
pushes two tags (the version from `cmd/ofc/main.go` and `latest`) so both an
amd64 and an arm64 computers pull the correct image from one manifest. The
first run creates a `buildx` builder named `ofc-builder`; subsequent runs reuse
it.

The version is stamped into the binary at host-compile time with `-ldflags -X`,
so `ofc version` inside the image reports exactly the tag it was published
under. `make docker-up` likewise builds the two host binaries first.

## Project layout

```text
cmd/ofc/               entrypoint and CLI
internal/auth/         GoTrue-compatible auth: JWT, PKCE, one-time codes
internal/blobs/        filesystem snapshot storage
internal/connect/      Connect API handlers
internal/store/        all Postgres queries
internal/pairingcode/  pairing-code normalization
internal/httpx/        shared HTTP plumbing and the error envelope
internal/db/           pool and migrations
test/contract/         wire-shape assertions
tools/e2e.sh           end-to-end flow
```

## Design constraints worth knowing

- **The server never decrypts anything.** Event payloads and snapshot blobs are
  opaque ciphertext stored and replayed verbatim; root keys never exist outside
  a device. The only cryptography here is SHA-256 of normalized pairing codes,
  SHA-256 of key-init challenge responses, and SHA-256 of snapshot bytes (the
  size/checksum headers).
- **The migrations are append-only.** `0001_init.sql` is checksumged by `db.Migrate`;
  edit a new migration, never an applied one.

## Release

Bump `version` in `cmd/ofc/main.go`, then `make docker-build`. The image tag
and `ofc version` both come from that one string.

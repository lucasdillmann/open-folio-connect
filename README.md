# Open Folio Connect

A self-hosted, single-binary replacement for the Wealthfolio Connect backend.

Wealthfolio's apps talk to Connect through two APIs: a GoTrue-compatible auth
service for signing in, and the device-sync API for encrypted replication.
Open Folio Connect implements both on one port.

It enables encrypted device sync between your own devices (laptop,
phone, NAS, etc) with end-to-end encryption and zero data leaving your network.

> **Homelab or private use only**
>
> This project is intended for local, private, personal, homelab use only. It is
> not ready to be exposed to the internet. Do not publish it on a public
> host or forward its ports to the open internet. If you need access from
> outside your home network, reach it through a VPN.

> **Not affiliated with Wealthfolio**
>
> This project is not recognized, endorsed, approved, or otherwise
> affiliated with Wealthfolio, its creators, its company, or any related
> parties. It is an independent, community-made reimplementation. Its
> development relied solely on public API contracts and the expected behavior
> observed in Wealthfolio's client-side source; no proprietary Connect backend
> code was used or copied. 

## Compatibility

Tested against **Wealthfolio v3.11.0**. The device-sync wire protocol is
unchanged from v3.10.0, so clients from v3.10.0 onward are supported.

Wealthfolio releases before v3.10.0 use the old single-call snapshot endpoints.
They can still sign in and replicate the oplog, but snapshot upload and download
will fail against this server.

## How to use it

Three pieces come together: a running server, a Wealthfolio build pointed at it,
and signing in from the app.

### 1. Run the server

The published image is **`dillmann/open-folio-connect`**. It needs a PostgreSQL
database and, on first start, an admin account from `OFC_ADMIN_EMAIL`.

`docker-compose.yml`:

```yaml
services:
  postgres:
    image: postgres:18-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: ofc
      POSTGRES_USER: ofc
      POSTGRES_PASSWORD: change-me-to-a-strong-password
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ofc -d ofc"]
      interval: 5s
      timeout: 5s
      retries: 20

  ofc:
    image: dillmann/open-folio-connect:latest
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
    ports:
      - "8080:8080"
    environment:
      OFC_DATABASE_URL: postgres://ofc:change-me-to-a-strong-password@db:5432/ofc?sslmode=disable
      # Generate using `openssl rand -hex 32`
      OFC_JWT_SECRET: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
      OFC_BASE_URL: https://ofc.myhomelab.com
      OFC_ADMIN_EMAIL: you@example.com
      OFC_DEV_OTP: "true"
      OFC_ALLOWED_ORIGINS: ALL
    volumes:
      - ofc-data:/data

volumes:
  postgres-data:
  ofc-data:
```

```sh
docker compose up -d
```

#### Configuration

| Variable              | Default                 | Purpose                                                            |
|-----------------------|-------------------------|--------------------------------------------------------------------|
| `OFC_DATABASE_URL`    |                         | Postgres connection string (required)                              |
| `OFC_JWT_SECRET`      | generated               | Signs access tokens. Changing it signs everyone out.               |
| `OFC_BASE_URL`        | `http://localhost:8080` | Public URL clients reach the server on. Snapshot transfers require an `https` URL with no explicit port |
| `OFC_DATA_DIR`        | `./data`                | Where snapshot ciphertext is stored                                |
| `OFC_ADMIN_EMAIL`     |                         | Account created on first start                                     |
| `OFC_DEV_OTP`         | `false`                 | Return login codes in the API response                             |
| `OFC_ALLOWED_ORIGINS` |                         | CORS allowlist; only needed for a browser client on another origin |
| `OFC_ADDR`            | `:8080`                 | Listen address                                                     |
| `OFC_LOG_LEVEL`       | `info`                  | `debug`, `info`, `warn`, `error`                                   |
| `OFC_TRANSFER_TTL`    | `10m`                   | How long a signed snapshot transfer URL stays valid                |

For trusted-LAN use, put it behind TLS in a reverse proxy.

### 2. Point a Wealthfolio build at it

Wealthfolio bakes these settings in at build time (both the JS bundle and
the Rust binary read them from the repository root `.env`). There are two
minimal source changes:

**a) Root `.env`**: put this in the Wealthfolio repo root before building:

```dotenv
CONNECT_AUTH_URL=https://ofc.myhomelab.com
CONNECT_API_URL=https://ofc.myhomelab.com
CONNECT_AUTH_PUBLISHABLE_KEY=sb_publishable_openfolioconnect
CONNECT_OAUTH_CALLBACK_URL=wealthfolio://auth/callback
CONNECT_STORAGE_ALLOWED_HOSTS=ofc.myhomelab.com
```

`CONNECT_AUTH_URL` and `CONNECT_AUTH_PUBLISHABLE_KEY` must both be set,
otherwise the Connect feature is compiled out entirely. The publishable key is
a public identifier, not a secret, and just needs to match what the app sends.

`CONNECT_STORAGE_ALLOWED_HOSTS` is a comma-separated hostname allowlist, not a
URL. It must contain the host open-folio-connect serves snapshot transfers from
(the host part of `OFC_BASE_URL`). The matching `OFC_BASE_URL` must be `https`
with no explicit port, or the client refuses the transfer URL.

**b) One-line CSP edit**: open `apps/tauri/tauri.conf.json`, find the
`security.csp` line, and add your origin to `connect-src` (do the same in
`devCsp` if you use dev builds):

```json
"connect-src 'self' https://ofc.myhomelab.com https://wealthfolio.app ..."
```

Without this, the app's webview blocks the login request before it leaves the
device. The same class of error you'd see in a browser console.

The web/self-hosted server (instead of the desktop/mobile apps) reads
`CONNECT_AUTH_URL`, `CONNECT_API_URL`, and `CONNECT_STORAGE_ALLOWED_HOSTS` as
runtime environment variables, so that deployment path needs the env vars set on
the container rather than a recompile. The wealthfolio Dockerfile instead bakes
the storage host through its `connect-storage-hosts` build secret.

**Toolchain notes** (desktop/mobile builds): Wealthfolio has its own set of
development dependencies. Please read the official guide to setup your PC in
order to build the project
locally (run the commands below).

Build and install:

```sh
pnpm tauri android build --debug --apk --target aarch64
adb install -r apps/tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk
```

### 3. Sign in and sync

The app's login is email-based, not social (social login is unavailable in a
self-hosted setup):

1. Open the Connect page and choose **Sign in with email**.
2. Enter your email. A 6-digit code is printed in the server log and, when
   `OFC_DEV_OTP` is enabled, returned in the API response. You can also print one
   from the server shell:
   `docker compose exec ofc /bin/ofc code you@example.com`.
3. Paste the code. This device bootstraps the team's encryption keys and becomes
   the trusted device.
4. On the next device, sign in with the same email, then use **Pair a device**
   and type the six-character code shown on the trusted device. The new device
   receives the root key over an end-to-end-encrypted channel and pulls the
   latest snapshot.

From then on devices replicate over the oplog in the background.

## Operational notes

- **Back up two things**: the Postgres database (oplog + device records) and
  `OFC_DATA_DIR` (snapshot ciphertext). The snapshot bytes are useless without a
  device's root key, so the database matters most.
- **Snapshot bytes move over signed URLs**: the client fetches short-lived
  transfer links from `/api/v1/sync/snapshots/...`, then PUTs or GETs the
  ciphertext directly. The signature in the URL is the credential; those requests
  carry no bearer token.
- **The oplog is never pruned**: that is what lets a new device bootstrap from
  a snapshot and replay the tail. It grows slowly; a personal portfolio is a few
  megabytes a year.
- **`keys/reset` is irreversible**: it clears the oplog and snapshots, revokes
  every device, and starts a new key epoch. Every device must be re-added by
  pairing.

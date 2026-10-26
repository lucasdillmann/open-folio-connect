#!/usr/bin/env bash
set -uo pipefail

EMAIL="${OFC_ADMIN_EMAIL:-me@example.com}"
BASE="${BASE:-}"
LOG="${OFC_LOG:-}"
RUN="$(python3 -c 'import uuid;print(uuid.uuid4().hex[:8])')"
PASS=0
FAIL=0
BOOTED=""
SERVER_PID=""
CONTAINER=""
E2E_DIR=""
ADMIN="${OFC_ADMIN_EMAIL:-me@example.com}"

pass() {
  printf '  \033[32mok\033[0m   %s\n' "$1"
  PASS=$((PASS + 1))
}

fail() {
  printf '  \033[31mFAIL\033[0m %s\n       %s\n' "$1" "$2"
  FAIL=$((FAIL + 1))
}

check() {
  if [[ "$2" == *"$3"* ]]; then
    pass "$1"
  else
    fail "$1" "expected to contain '$3', got: $2"
  fi
}

absent() {
  if [[ "$2" != *"$3"* ]]; then
    pass "$1"
  else
    fail "$1" "must NOT contain '$3', got: $2"
  fi
}

equal() {
  if [[ "$2" == "$3" ]]; then
    pass "$1"
  else
    fail "$1" "expected '$3', got '$2'"
  fi
}

status() {
  local name="$1"
  local want="$2"
  local got
  shift 2
  got=$(curl -s -o /tmp/ofc-status.body -w '%{http_code}' "$@")
  if [[ "$got" == "$want" ]]; then
    pass "$name"
  else
    fail "$name" "expected HTTP $want, got $got: $(head -c 300 /tmp/ofc-status.body)"
  fi
}

section() {
  printf '\n\033[1m%s\033[0m\n' "$1"
}

jqr() {
  python3 -c "import json,sys
try:
    print(json.load(sys.stdin)$1)
except Exception as e:
    print('<unparsable: %s>' % e)" 2>/dev/null
}

j() {
  printf '%s' "$1" | jqr "$2"
}

uuid() {
  python3 -c 'import uuid;print(uuid.uuid4())'
}

free_port() {
  python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()"
}

snapshot_prepare_reject() {
  local name="$1"
  shift
  status "$name" 400 -X POST "$BASE/api/v1/sync/snapshots/prepare-upload" \
    "${AUTH[@]}" \
    -H "x-wf-device-id: $DEVICE_A" \
    -H 'Content-Type: application/json' \
    "$@"
}

if [ -z "$BASE" ]; then
  ROOT="$(cd "$(dirname "$0")/.." && pwd)"
  E2E_DIR="$(mktemp -d)"
  SVPORT="$(free_port)"
  PGPORT="$(free_port)"
  BASE="http://127.0.0.1:$SVPORT"
  LOG="$E2E_DIR/server.log"
  CONTAINER="ofc-e2e-pg-$RUN"
  BIN="$E2E_DIR/ofc-e2e"
  if ! command -v docker >/dev/null 2>&1; then
    echo "e2e self-boot requires docker" >&2
    exit 2
  fi
  if ! (cd "$ROOT" && go build -o "$BIN" ./cmd/ofc); then
    exit 2
  fi
  docker run -d --name "$CONTAINER" \
    -e POSTGRES_DB=ofc \
    -e POSTGRES_USER=ofc \
    -e POSTGRES_PASSWORD=e2e \
    -p "$PGPORT:5432" postgres:17-alpine >/dev/null || exit 2
  for _ in $(seq 1 60); do
    if docker exec "$CONTAINER" pg_isready -U ofc -d ofc >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
  OFC_DATABASE_URL="postgres://ofc:e2e@127.0.0.1:$PGPORT/ofc?sslmode=disable" \
  OFC_JWT_SECRET="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" \
  OFC_BASE_URL="$BASE" \
  OFC_ADMIN_EMAIL="$ADMIN" \
  OFC_DEV_OTP=true \
  OFC_DATA_DIR="$E2E_DIR/data" \
  OFC_ADDR=":$SVPORT" \
    "$BIN" >"$LOG" 2>&1 &
  SERVER_PID=$!
  BOOTED=1
  trap 'kill "$SERVER_PID" 2>/dev/null; docker rm -f "$CONTAINER" >/dev/null 2>&1; rm -rf "$E2E_DIR"' EXIT
  for _ in $(seq 1 90); do
    if curl -sf "$BASE/readyz" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done
fi

LOG="${LOG:-/tmp/ofc.log}"
if ! curl -sf "$BASE/healthz" >/dev/null 2>&1; then
  echo "no server at $BASE; start one or run make e2e with no BASE set" >&2
  exit 2
fi

section "1. health"
check "healthz" "$(curl -sf "$BASE/healthz")" '"status":"ok"'
check "readyz" "$(curl -sf "$BASE/readyz")" '"status":"ready"'

section "2. auth"
OTP=$(curl -sf -X POST "$BASE/auth/v1/otp" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\"}")
check "otp request returns a dev code" "$OTP" '"dev_code"'

CODE=$(j "$OTP" "['dev_code']")
if [[ -n "$CODE" && "$CODE" != \<* ]]; then
  pass "read login code from the dev response"
else
  CODE=$(python3 -c "
import re
text = open('$LOG').read()
for line in reversed(text.splitlines()):
    if 'one-time login code' in line:
        m = re.search(r'code=(\d{6})', line)
        if m:
            print(m.group(1))
            break
else:
    print('')" 2>/dev/null)
  if [[ -n "$CODE" ]]; then
    pass "read login code from the server log"
  else
    fail "obtain a login code" "no code in the response or $LOG"
    printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
    exit 1
  fi
fi

SESSION=$(curl -sf -X POST "$BASE/auth/v1/verify" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"token\":\"$CODE\",\"type\":\"email\"}")
ACCESS=$(j "$SESSION" "['access_token']")
REFRESH=$(j "$SESSION" "['refresh_token']")
check "verify returns a session" "$SESSION" '"access_token"'
check "session embeds a user object" "$SESSION" '"app_metadata"'
check "GET /auth/v1/user works" "$(curl -sf -H "Authorization: Bearer $ACCESS" "$BASE/auth/v1/user")" "$EMAIL"

equal "access token has three segments" "$(awk -F. '{print NF}' <<<"$ACCESS")" '3'
if echo "$ACCESS" | cut -d. -f2 | python3 -c "
import base64, json, sys
p = sys.stdin.read().strip(); p += '=' * (-len(p) % 4)
c = json.loads(base64.urlsafe_b64decode(p))
assert 'exp' in c and isinstance(c['exp'], int), 'missing integer exp'
assert 'sub' in c, 'missing sub'
" 2>/dev/null; then
  pass "access token carries integer exp and sub"
else
  fail "access token carries integer exp and sub" "claim validation failed"
fi

ROTATED=$(curl -sf -X POST "$BASE/auth/v1/token?grant_type=refresh_token" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$REFRESH\"}")
NEW_REFRESH=$(j "$ROTATED" "['refresh_token']")
if [[ -n "$NEW_REFRESH" && "$NEW_REFRESH" != "$REFRESH" ]]; then
  pass "refresh token rotates"
else
  fail "refresh token rotates" "got '$NEW_REFRESH' back"
fi

status "replayed refresh token is rejected" 400 -X POST "$BASE/auth/v1/token?grant_type=refresh_token" \
  -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$REFRESH\"}"
check "refresh failure is invalid_grant" \
  "$(curl -s -X POST "$BASE/auth/v1/token?grant_type=refresh_token" \
    -H 'Content-Type: application/json' -d "{\"refresh_token\":\"$REFRESH\"}")" 'invalid_grant'

ACCESS=$(j "$ROTATED" "['access_token']")
AUTH=(-H "Authorization: Bearer $ACCESS")

section "3. entitlement gate"
ME=$(curl -sf "${AUTH[@]}" "$BASE/api/v1/user/me")
check "user/me returns an id" "$ME" '"id"'
check "team subscriptionStatus is camelCase" "$ME" '"subscriptionStatus"'
check "subscription reports active" "$ME" '"subscriptionStatus":"active"'
check "plans are served" \
  "$(curl -sf "${AUTH[@]}" "$BASE/api/v1/subscription/plans")" '"plans"'
check "broker connections report empty" \
  "$(curl -sf "${AUTH[@]}" "$BASE/api/v1/sync/brokerage/connections")" '"connections":[]'

section "4. device A: enroll and bootstrap the key epoch"
RESET0=$(curl -sf -X POST "$BASE/api/v1/sync/team/keys/reset" "${AUTH[@]}" \
  -H 'Content-Type: application/json' -d '{"reason":"e2e reset"}')
check "reset clears prior state" "$RESET0" '"success":true'

NONCE_A=$(uuid)
ENROLL_A=$(curl -sf -X POST "$BASE/api/v1/sync/team/devices" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d "{\"device_nonce\":\"$NONCE_A\",\"display_name\":\"Laptop-$RUN\",\"platform\":\"mac\",\"app_version\":\"1.0.0\"}")
DEVICE_A=$(j "$ENROLL_A" "['device_id']")
MODE=$(j "$ENROLL_A" "['mode']")
if [[ "$MODE" == BOOTSTRAP || "$MODE" == READY ]]; then
  pass "enroll mode is BOOTSTRAP or READY"
else
  fail "enroll mode is BOOTSTRAP or READY" "got '$MODE'"
fi
check "enroll uses snake_case device_id" "$ENROLL_A" '"device_id"'
check "enroll uses snake_case key version" "$ENROLL_A" '"e2ee_key_version"'
absent "enroll omits camelCase deviceId" "$ENROLL_A" '"deviceId"'

if [[ "$MODE" == BOOTSTRAP ]]; then
  INIT_A=$(curl -sf -X POST "$BASE/api/v1/sync/team/keys/initialize" "${AUTH[@]}" \
    -H 'Content-Type: application/json' -H "x-wf-device-id: $DEVICE_A" \
    -d "{\"device_id\":\"$DEVICE_A\"}")
  CHALLENGE=$(j "$INIT_A" "['challenge']")
  NONCEV=$(j "$INIT_A" "['nonce']")
  check "initialize returns BOOTSTRAP" "$INIT_A" '"mode":"BOOTSTRAP"'
  check "initialize uses snake_case key_version" "$INIT_A" '"key_version"'

  status "wrong challenge_response refused" 400 -X POST "$BASE/api/v1/sync/team/keys/initialize/commit" \
    "${AUTH[@]}" -H 'Content-Type: application/json' -H "x-wf-device-id: $DEVICE_A" \
    -d "{\"device_id\":\"$DEVICE_A\",\"key_version\":1,\"device_key_envelope\":\"x\",\"signature\":\"y\",\"challenge_response\":\"00\"}"

  RESP=$(python3 -c "import hashlib;print(hashlib.sha256(f'$CHALLENGE:$NONCEV'.encode()).hexdigest())")
  COMMIT_A=$(curl -sf -X POST "$BASE/api/v1/sync/team/keys/initialize/commit" "${AUTH[@]}" \
    -H 'Content-Type: application/json' -H "x-wf-device-id: $DEVICE_A" \
    -d "{\"device_id\":\"$DEVICE_A\",\"key_version\":1,\"device_key_envelope\":\"ZW5jbGFvc2Vk\",\"signature\":\"deadbeef\",\"challenge_response\":\"$RESP\"}")
  check "commit succeeds" "$COMMIT_A" '"success":true'
  check "key state is ACTIVE" "$COMMIT_A" '"key_state":"ACTIVE"'

  status "a consumed challenge cannot be replayed" 409 -X POST "$BASE/api/v1/sync/team/keys/initialize/commit" \
    "${AUTH[@]}" -H 'Content-Type: application/json' -H "x-wf-device-id: $DEVICE_A" \
    -d "{\"device_id\":\"$DEVICE_A\",\"key_version\":1,\"device_key_envelope\":\"x\",\"signature\":\"y\",\"challenge_response\":\"$RESP\"}"
  check "initialize stops offering BOOTSTRAP" \
    "$(curl -sf -X POST "$BASE/api/v1/sync/team/keys/initialize" "${AUTH[@]}" \
      -H 'Content-Type: application/json' -H "x-wf-device-id: $DEVICE_A" \
      -d "{\"device_id\":\"$DEVICE_A\"}")" '"mode":"PAIRING_REQUIRED"'
fi

DEV_A=$(curl -sf "${AUTH[@]}" -H "x-wf-device-id: $DEVICE_A" "$BASE/api/v1/sync/team/devices/$DEVICE_A")
check "device A is trusted" "$DEV_A" '"trustState":"trusted"'
check "trustedKeyVersion is camelCase" "$DEV_A" '"trustedKeyVersion"'
KV=$(j "$DEV_A" "['trustedKeyVersion']")

REENROLL=$(curl -sf -X POST "$BASE/api/v1/sync/team/devices" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d "{\"device_nonce\":\"$NONCE_A\",\"display_name\":\"Laptop-$RUN\",\"platform\":\"mac\"}")
equal "re-enroll is idempotent" "$(j "$REENROLL" "['device_id']")" "$DEVICE_A"

section "5. oplog: push, cursor, pull"
E1="evt-$RUN-1"
E2="evt-$RUN-2"
PUSH=$(curl -sf -X POST "$BASE/api/v1/sync/events/push" "${AUTH[@]}" \
  -H 'Content-Type: application/json' -H "x-wf-device-id: $DEVICE_A" \
  -d "{\"events\":[
        {\"event_id\":\"$E1\",\"device_id\":\"$DEVICE_A\",\"type\":\"account.update.v1\",
         \"entity\":\"account\",\"entity_id\":\"acc-$RUN\",\"client_timestamp\":\"2026-01-01T10:00:00.000Z\",
         \"payload\":\"Y2lwaGVydGV4dA==\",\"payload_key_version\":$KV},
        {\"event_id\":\"$E2\",\"device_id\":\"$DEVICE_A\",\"type\":\"activity.create.v1\",
         \"entity\":\"activity\",\"entity_id\":\"act-$RUN\",\"client_timestamp\":\"2026-01-01T10:05:00.000Z\",
         \"payload\":\"Y2lwaGVydGV4dA==\",\"payload_key_version\":$KV}]}")
check "push accepts the batch" "$PUSH" '"accepted"'
check "push reports empty duplicates" "$PUSH" '"duplicate":[]'
CURSOR=$(j "$PUSH" "['serverCursor']")
SEQ1=$(j "$PUSH" "['accepted'][0]['seq']")
SEQ2=$(j "$PUSH" "['accepted'][1]['seq']")
check "serverCursor advanced past zero" "$([[ "$CURSOR" -gt 0 ]] && echo yes || echo no)" 'yes'
check "seqs are assigned in ascending order" "$([[ "$SEQ2" -gt "$SEQ1" ]] && echo yes || echo no)" 'yes'
equal "serverCursor is the last assigned seq" "$CURSOR" "$SEQ2"

PUSH2=$(curl -sf -X POST "$BASE/api/v1/sync/events/push" "${AUTH[@]}" \
  -H 'Content-Type: application/json' -H "x-wf-device-id: $DEVICE_A" \
  -d "{\"events\":[{\"event_id\":\"$E1\",\"device_id\":\"$DEVICE_A\",\"type\":\"account.update.v1\",
       \"entity\":\"account\",\"entity_id\":\"acc-$RUN\",\"client_timestamp\":\"2026-01-01T10:00:00.000Z\",
       \"payload\":\"Y2lwaGVydGV4dA==\",\"payload_key_version\":$KV}]}")
check "replay is reported as duplicate" "$PUSH2" "$E1"
check "accepted is empty on replay" "$PUSH2" '"accepted":[]'
equal "duplicate carries the original seq" "$(j "$PUSH2" "['duplicate'][0]['seq']")" "$SEQ1"
equal "replay does not move the cursor" "$(j "$PUSH2" "['serverCursor']")" "$CURSOR"

KVM=$(curl -s -X POST "$BASE/api/v1/sync/events/push" "${AUTH[@]}" \
  -H 'Content-Type: application/json' -H "x-wf-device-id: $DEVICE_A" \
  -d "{\"events\":[{\"event_id\":\"evt-$RUN-bad\",\"device_id\":\"$DEVICE_A\",
       \"type\":\"account.update.v1\",\"entity\":\"account\",\"entity_id\":\"acc-bad\",
       \"client_timestamp\":\"2026-01-01T10:00:00.000Z\",\"payload\":\"eA==\",
       \"payload_key_version\":9999}]}")
check "wrong key version is reported" "$KVM" 'KEY_VERSION_MISMATCH'

BADDOC=$(curl -s -X POST "$BASE/api/v1/sync/events/push" "${AUTH[@]}" \
  -H 'Content-Type: application/json' -H "x-wf-device-id: $DEVICE_A" \
  -d "{\"events\":[{\"event_id\":\"evt-$RUN-bad2\",\"device_id\":\"$DEVICE_A\",
       \"type\":\"account.frobnicate.v1\",\"entity\":\"account\",\"entity_id\":\"acc-bad\",
       \"client_timestamp\":\"2026-01-01T10:00:00.000Z\",\"payload\":\"eA==\",
       \"payload_key_version\":$KV}]}")
check "malformed event type is rejected" "$BADDOC" 'INVALID_EVENT_TYPE'

PULL=$(curl -sf "${AUTH[@]}" -H "x-wf-device-id: $DEVICE_A" "$BASE/api/v1/sync/events/pull?since=0&limit=500")
check "pull returns events" "$PULL" '"events"'
equal "pull nextCursor matches the cursor" "$(j "$PULL" "['nextCursor']")" "$CURSOR"
check "pull reports hasMore false" "$PULL" '"hasMore":false'
absent "pull omits gcWatermark" "$PULL" 'gcWatermark'
check "event type round-trips" "$PULL" '"type":"account.update.v1"'
check "payloadKeyVersion is camelCase" "$PULL" '"payloadKeyVersion"'
check "clientTimestamp is echoed verbatim" "$PULL" '"clientTimestamp":"2026-01-01T10:00:00.000Z"'
check "our event is present" "$PULL" "\"eventId\":\"$E1\""

PULL2=$(curl -sf "${AUTH[@]}" -H "x-wf-device-id: $DEVICE_A" "$BASE/api/v1/sync/events/pull?since=$CURSOR&limit=500")
check "pull past the end is empty" "$PULL2" '"events":[]'
equal "empty page keeps the cursor" "$(j "$PULL2" "['nextCursor']")" "$CURSOR"
check "empty page is not hasMore" "$PULL2" '"hasMore":false'

RECON=$(curl -sf "${AUTH[@]}" -H "x-wf-device-id: $DEVICE_A" "$BASE/api/v1/sync/events/reconcile-ready-state")
check "reconcile returns PULL_TAIL" "$RECON" '"action":"PULL_TAIL"'
equal "reconcile reports the current cursor" "$(j "$RECON" "['cursor']")" "$CURSOR"

section "6. snapshots"
printf 'snapshot-%s\000\001\002binary' "$RUN" > /tmp/ofc-snap.bin
SUM=$(shasum -a 256 /tmp/ofc-snap.bin | cut -d' ' -f1)
SIZE=$(wc -c < /tmp/ofc-snap.bin | tr -d ' ')
CHECKSUM="sha256:$SUM"

PREP=$(curl -sf -X POST "$BASE/api/v1/sync/snapshots/prepare-upload" "${AUTH[@]}" \
  -H "x-wf-device-id: $DEVICE_A" -H 'Content-Type: application/json' \
  -d "{\"event_id\":\"$(uuid)\",\"snapshot_seq\":$CURSOR,\"schema_version\":4,\"size_bytes\":$SIZE,\"checksum\":\"$CHECKSUM\",\"metadata_payload\":\"bWV0YQ==\",\"payload_key_version\":$KV}")
TICKET=$(j "$PREP" "['ticket']")
TRANSFER_URL=$(j "$PREP" "['transfer']['url']")
TRANSFER_METHOD=$(j "$PREP" "['transfer']['method']")
TRANSFER_SUM=$(j "$PREP" "['transfer']['headers']['x-amz-checksum-sha256']")
check "prepare-upload returns a ticket" "$PREP" '"ticket"'
equal "prepare-upload returns a PUT transfer" "$TRANSFER_METHOD" "PUT"
check "prepare-upload scopes the transfer to the snapshot" "$TRANSFER_URL" '/api/v1/sync/transfers/'

status "the transfer PUT accepts the ciphertext" 204 -X PUT "$TRANSFER_URL" \
  -H "content-length: $SIZE" -H "x-amz-checksum-sha256: $TRANSFER_SUM" \
  --data-binary @/tmp/ofc-snap.bin

UP=$(curl -sf -X POST "$BASE/api/v1/sync/snapshots/complete-upload" "${AUTH[@]}" \
  -H "x-wf-device-id: $DEVICE_A" -H 'Content-Type: application/json' \
  -d "{\"ticket\":\"$TICKET\"}")
SNAP_ID=$(j "$UP" "['snapshotId']")
check "complete-upload returns a snapshotId" "$UP" '"snapshotId"'
equal "complete-upload records the client base seq" "$(j "$UP" "['oplogSeq']")" "$CURSOR"

LATEST=$(curl -sf "${AUTH[@]}" -H "x-wf-device-id: $DEVICE_A" "$BASE/api/v1/sync/snapshots/latest")
equal "latest reports the uploaded id" "$(j "$LATEST" "['snapshotId']")" "$SNAP_ID"
equal "latest reports the byte size" "$(j "$LATEST" "['sizeBytes']")" "$SIZE"
check "latest checksum uses the sha256 prefix" "$LATEST" '"checksum":"sha256:'

DL=$(curl -sf -X POST "$BASE/api/v1/sync/snapshots/$SNAP_ID/download-url" "${AUTH[@]}" \
  -H "x-wf-device-id: $DEVICE_A" -H 'Content-Type: application/json' -d '{}')
equal "download-url returns a GET transfer" "$(j "$DL" "['transfer']['method']")" "GET"
equal "download-url echoes the snapshot id" "$(j "$DL" "['snapshot']['snapshotId']")" "$SNAP_ID"
DL_URL=$(j "$DL" "['transfer']['url']")
curl -sf "$DL_URL" -o /tmp/ofc-dl.bin
check "download returns byte-identical content" \
  "$(cmp -s /tmp/ofc-snap.bin /tmp/ofc-dl.bin && echo same || echo differ)" 'same'

snapshot_prepare_reject "non-uuid event id is refused" \
  -d "{\"event_id\":\"not-a-uuid\",\"snapshot_seq\":$CURSOR,\"schema_version\":4,\"size_bytes\":$SIZE,\"checksum\":\"$CHECKSUM\",\"payload_key_version\":$KV}"
snapshot_prepare_reject "malformed checksum is refused" \
  -d "{\"event_id\":\"$(uuid)\",\"snapshot_seq\":$CURSOR,\"schema_version\":4,\"size_bytes\":$SIZE,\"checksum\":\"nope\",\"payload_key_version\":$KV}"
snapshot_prepare_reject "zero size is refused" \
  -d "{\"event_id\":\"$(uuid)\",\"snapshot_seq\":$CURSOR,\"schema_version\":4,\"size_bytes\":0,\"checksum\":\"$CHECKSUM\",\"payload_key_version\":$KV}"
snapshot_prepare_reject "negative snapshot seq is refused" \
  -d "{\"event_id\":\"$(uuid)\",\"snapshot_seq\":-1,\"schema_version\":4,\"size_bytes\":$SIZE,\"checksum\":\"$CHECKSUM\",\"payload_key_version\":$KV}"

status "an unsigned transfer link is refused" 403 -X PUT "$BASE/api/v1/sync/transfers/not-a-token" \
  --data-binary @/tmp/ofc-snap.bin

cp /tmp/ofc-snap.bin /tmp/ofc-tampered.bin
printf 'X' | dd of=/tmp/ofc-tampered.bin bs=1 seek=0 conv=notrunc count=1 2>/dev/null
PREP_T=$(curl -sf -X POST "$BASE/api/v1/sync/snapshots/prepare-upload" "${AUTH[@]}" \
  -H "x-wf-device-id: $DEVICE_A" -H 'Content-Type: application/json' \
  -d "{\"event_id\":\"$(uuid)\",\"snapshot_seq\":$CURSOR,\"schema_version\":4,\"size_bytes\":$SIZE,\"checksum\":\"$CHECKSUM\",\"payload_key_version\":$KV}")
T_URL=$(j "$PREP_T" "['transfer']['url']")
T_SUM=$(j "$PREP_T" "['transfer']['headers']['x-amz-checksum-sha256']")
status "tampered transfer bytes are refused" 409 -X PUT "$T_URL" \
  -H "content-length: $SIZE" -H "x-amz-checksum-sha256: $T_SUM" \
  --data-binary @/tmp/ofc-tampered.bin

PREP_M=$(curl -sf -X POST "$BASE/api/v1/sync/snapshots/prepare-upload" "${AUTH[@]}" \
  -H "x-wf-device-id: $DEVICE_A" -H 'Content-Type: application/json' \
  -d "{\"event_id\":\"$(uuid)\",\"snapshot_seq\":$CURSOR,\"schema_version\":4,\"size_bytes\":$SIZE,\"checksum\":\"$CHECKSUM\",\"payload_key_version\":$KV}")
status "complete-upload before the bytes is refused" 409 \
  -X POST "$BASE/api/v1/sync/snapshots/complete-upload" "${AUTH[@]}" \
  -H "x-wf-device-id: $DEVICE_A" -H 'Content-Type: application/json' \
  -d "{\"ticket\":\"$(j "$PREP_M" "['ticket']")\"}"

section "7. device B: enroll, pair, confirm"
NONCE_B=$(uuid)
ENROLL_B=$(curl -sf -X POST "$BASE/api/v1/sync/team/devices" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d "{\"device_nonce\":\"$NONCE_B\",\"display_name\":\"Phone-$RUN\",\"platform\":\"ios\"}")
DEVICE_B=$(j "$ENROLL_B" "['device_id']")
check "second device gets PAIR" "$ENROLL_B" '"mode":"PAIR"'
check "PAIR lists the trusted device" "$ENROLL_B" "$DEVICE_A"
check "trusted summary uses camelCase lastSeenAt" "$ENROLL_B" '"lastSeenAt"'
absent "trusted summary omits snake_case" "$ENROLL_B" '"last_seen_at"'
check "PAIR uses snake_case ttl" "$ENROLL_B" '"pairing_ttl_seconds"'
check "PAIR uses snake_case sas" "$ENROLL_B" '"require_sas"'

PAIR_CODE="ab${RUN}"
CODE_HASH=$(python3 -c "
import hashlib, re
code = '$PAIR_CODE'
print(hashlib.sha256(re.sub(r'[^0-9A-Z]', '', code.upper()).encode()).hexdigest())")
PAIR=$(curl -sf -X POST "$BASE/api/v1/sync/team/devices/$DEVICE_A/pairings" "${AUTH[@]}" \
  -H 'Content-Type: application/json' -H "x-wf-device-id: $DEVICE_A" \
  -d "{\"code_hash\":\"$CODE_HASH\",\"ephemeral_public_key\":\"aXNzdWVycHVibGlja2V5\"}")
PAIR_ID=$(j "$PAIR" "['pairingId']")
check "create pairing returns an id" "$PAIR" '"pairingId"'
check "create pairing uses camelCase" "$PAIR" '"keyVersion"'
check "requireSas is set" "$PAIR" '"requireSas":true'

TYPED=$(printf '%s' "$PAIR_CODE" | sed 's/./&-/g')
CLAIM=$(curl -sf -X POST "$BASE/api/v1/sync/team/devices/$DEVICE_B/pairings/claim" "${AUTH[@]}" \
  -H 'Content-Type: application/json' -H "x-wf-device-id: $DEVICE_B" \
  -d "{\"code\":\"$(echo "$TYPED" | tr 'A-Z' 'a-z')\",\"ephemeral_public_key\":\"Y2xhaW1lcnB1YmxpYw==\"}")
check "claim accepts a normalized code" "$CLAIM" '"sessionId"'
check "claim returns the issuer key" "$CLAIM" '"issuerEphemeralPub"'
check "claim uses camelCase version" "$CLAIM" '"e2eeKeyVersion"'

status "an unknown code is rejected" 400 -X POST "$BASE/api/v1/sync/team/devices/$DEVICE_B/pairings/claim" \
  "${AUTH[@]}" -H 'Content-Type: application/json' -H "x-wf-device-id: $DEVICE_B" \
  -d '{"code":"ZZZZZZ","ephemeral_public_key":"eA=="}'

GETP=$(curl -sf "${AUTH[@]}" -H "x-wf-device-id: $DEVICE_A" \
  "$BASE/api/v1/sync/team/devices/$DEVICE_A/pairings/$PAIR_ID")
check "issuer sees the claimer" "$GETP" "$DEVICE_B"
check "status is lowercase claimed" "$GETP" '"status":"claimed"'

check "approve succeeds" "$(curl -sf -X POST "$BASE/api/v1/sync/team/devices/$DEVICE_A/pairings/$PAIR_ID/approve" \
  "${AUTH[@]}" -H "x-wf-device-id: $DEVICE_A")" '"success":true'

status "re-approve returns 409" 409 -X POST "$BASE/api/v1/sync/team/devices/$DEVICE_A/pairings/$PAIR_ID/approve" \
  "${AUTH[@]}" -H "x-wf-device-id: $DEVICE_A"
check "re-approve code says already_approved" \
  "$(curl -s -X POST "$BASE/api/v1/sync/team/devices/$DEVICE_A/pairings/$PAIR_ID/approve" \
    "${AUTH[@]}" -H "x-wf-device-id: $DEVICE_A" | tr 'A-Z' 'a-z')" 'already_approved'

check "complete succeeds" "$(curl -sf -X POST "$BASE/api/v1/sync/team/devices/$DEVICE_A/pairings/$PAIR_ID/complete" \
  "${AUTH[@]}" -H 'Content-Type: application/json' -H "x-wf-device-id: $DEVICE_A" \
  -d '{"encrypted_key_bundle":"cmtfd2J1bmRsZQ==","sas_proof":"123456","signature":"aabb"}')" '"success":true'

MSGS=$(curl -sf "${AUTH[@]}" -H "x-wf-device-id: $DEVICE_B" \
  "$BASE/api/v1/sync/team/devices/$DEVICE_B/pairings/$PAIR_ID/messages")
check "messages reports session status" "$MSGS" '"sessionStatus"'
check "the key bundle is published" "$MSGS" '"payloadType":"rk_transfer_v1"'
check "the bundle payload is delivered" "$MSGS" '"payload":"cmtfd2J1bmRsZQ=="'

status "the issuer cannot confirm the claimer" 403 \
  -X POST "$BASE/api/v1/sync/team/devices/$DEVICE_B/pairings/$PAIR_ID/confirm" \
  "${AUTH[@]}" -H 'Content-Type: application/json' -H "x-wf-device-id: $DEVICE_A" -d '{}'

CONFIRM=$(curl -sf -X POST "$BASE/api/v1/sync/team/devices/$DEVICE_B/pairings/$PAIR_ID/confirm" \
  "${AUTH[@]}" -H 'Content-Type: application/json' -H "x-wf-device-id: $DEVICE_B" \
  -d '{"proof":"aabbcc"}')
check "confirm grants trust" "$CONFIRM" '"success":true'
check "confirm reports the epoch" "$CONFIRM" '"keyVersion"'
check "device B is now trusted" "$(curl -sf "${AUTH[@]}" -H "x-wf-device-id: $DEVICE_B" \
  "$BASE/api/v1/sync/team/devices/$DEVICE_B")" '"trustState":"trusted"'

status "re-confirm returns 409" 409 -X POST "$BASE/api/v1/sync/team/devices/$DEVICE_B/pairings/$PAIR_ID/confirm" \
  "${AUTH[@]}" -H 'Content-Type: application/json' -H "x-wf-device-id: $DEVICE_B" -d '{}'
check "re-confirm code says already_confirmed" \
  "$(curl -s -X POST "$BASE/api/v1/sync/team/devices/$DEVICE_B/pairings/$PAIR_ID/confirm" \
    "${AUTH[@]}" -H 'Content-Type: application/json' -H "x-wf-device-id: $DEVICE_B" -d '{}' | tr 'A-Z' 'a-z')" 'already_confirmed'

PULL_B=$(curl -sf "${AUTH[@]}" -H "x-wf-device-id: $DEVICE_B" "$BASE/api/v1/sync/events/pull?since=0&limit=500")
check "device B pulls device A's events" "$PULL_B" "$E1"
equal "device B sees the same cursor as A" "$(j "$PULL_B" "['nextCursor']")" "$CURSOR"

section "8. authorization boundaries"
status "no token is rejected" 401 "$BASE/api/v1/user/me"
status "a malformed token is rejected" 401 -H 'Authorization: Bearer not-a-jwt' "$BASE/api/v1/user/me"
status "an unknown device is 404" 404 "${AUTH[@]}" \
  -H "x-wf-device-id: $(uuid)" "$BASE/api/v1/sync/events/cursor"
status "push without a device header is rejected" 401 -X POST "$BASE/api/v1/sync/events/push" \
  "${AUTH[@]}" -H 'Content-Type: application/json' -d '{"events":[]}'
status "an unknown snapshot is 404" 404 -X POST "${AUTH[@]}" -H "x-wf-device-id: $DEVICE_A" \
  -H 'Content-Type: application/json' -d '{}' "$BASE/api/v1/sync/snapshots/$(uuid)/download-url"

ENROLL_C=$(curl -sf -X POST "$BASE/api/v1/sync/team/devices" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d "{\"device_nonce\":\"$(uuid)\",\"display_name\":\"Tablet-$RUN\",\"platform\":\"android\"}")
DEVICE_C=$(j "$ENROLL_C" "['device_id']")
if [[ -z "$DEVICE_C" || "$DEVICE_C" == \<* ]]; then
  fail "enroll a third device for the authorization checks" "got: $ENROLL_C"
  DEVICE_C=$(uuid)
fi
status "a third party cannot read pairing messages" 403 "${AUTH[@]}" \
  -H "x-wf-device-id: $DEVICE_C" \
  "$BASE/api/v1/sync/team/devices/$DEVICE_A/pairings/$PAIR_ID/messages"
status "a third party cannot confirm the pairing" 403 "${AUTH[@]}" \
  -H 'Content-Type: application/json' -H "x-wf-device-id: $DEVICE_C" \
  -X POST "$BASE/api/v1/sync/team/devices/$DEVICE_C/pairings/$PAIR_ID/confirm"

check "revoke succeeds" "$(curl -sf -X POST "$BASE/api/v1/sync/team/devices/$DEVICE_B/revoke" \
  "${AUTH[@]}" -H "x-wf-device-id: $DEVICE_A")" '"success":true'
status "a revoked device loses sync access" 403 "${AUTH[@]}" -H "x-wf-device-id: $DEVICE_B" \
  "$BASE/api/v1/sync/events/cursor"
check "a revoked device still reads its record" \
  "$(curl -sf "${AUTH[@]}" -H "x-wf-device-id: $DEVICE_A" "$BASE/api/v1/sync/team/devices/$DEVICE_B")" \
  '"trustState":"revoked"'

section "9. cloud backups"
BPOLICY=$(curl -sf "${AUTH[@]}" "$BASE/api/v1/backups/policy")
check "backup policy is available" "$BPOLICY" '"uploadEntitled":true'
equal "backup policy starts disabled" "$(j "$BPOLICY" "['enabled']")" "False"
check "backup policy reports the team" "$BPOLICY" '"teamId":"'

BSOURCE=$(uuid)
BENABLE=$(curl -sf -X PUT "$BASE/api/v1/backups/policy" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d "{\"revision\":0,\"enabled\":true,\"source_id\":\"$BSOURCE\"}")
check "enabling backups sets the source" "$BENABLE" "\"sourceId\":\"$BSOURCE\""
equal "enabling backups enables the policy" "$(j "$BENABLE" "['enabled']")" "True"
equal "enabling backups bumps the revision" "$(j "$BENABLE" "['revision']")" "1"
check "enabling backups schedules the first capture" "$BENABLE" '"nextDueAt":"'
BREV=$(j "$BENABLE" "['revision']")

BKEY=$(uuid)
RECENV="{\"format\":1,\"recovery_id\":\"$(uuid)\",\"ciphertext\":\"cmVjb3Zlcnk=\"}"
BKEYRESP=$(curl -sf -X PUT "$BASE/api/v1/backups/key" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d "{\"key_id\":\"$BKEY\",\"recovery_envelope\":$RECENV}")
check "backup key is created" "$BKEYRESP" '"created":true'
equal "backup key id round-trips" "$(j "$BKEYRESP" "['keyId']")" "$BKEY"
equal "backup key is readable" \
  "$(j "$(curl -sf "${AUTH[@]}" "$BASE/api/v1/backups/key")" "['keyId']")" "$BKEY"

BTRUSTED=$(curl -sf "${AUTH[@]}" -H "x-wf-device-id: $DEVICE_A" \
  "$BASE/api/v1/backups/key/trusted-envelope")
equal "trusted envelope starts at revision zero" "$(j "$BTRUSTED" "['revision']")" "0"
equal "trusted envelope is null before sharing" "$(j "$BTRUSTED" "['envelope']")" "None"

TRUSTENV="{\"format\":1,\"team_id\":\"$(uuid)\",\"sync_key_version\":1,\"ciphertext\":\"dHJ1c3RlZA==\"}"
curl -sf -X PUT "$BASE/api/v1/backups/key/trusted-envelope" "${AUTH[@]}" \
  -H 'Content-Type: application/json' -H "x-wf-device-id: $DEVICE_A" \
  -d "{\"revision\":0,\"envelope\":$TRUSTENV}" >/dev/null
BTRUSTED2=$(curl -sf "${AUTH[@]}" -H "x-wf-device-id: $DEVICE_A" \
  "$BASE/api/v1/backups/key/trusted-envelope")
equal "trusted envelope is published" "$(j "$BTRUSTED2" "['revision']")" "1"
check "trusted envelope round-trips" "$BTRUSTED2" '"ciphertext":"dHJ1c3RlZA=="'
status "a stale trusted envelope is refused" 409 -X PUT \
  "$BASE/api/v1/backups/key/trusted-envelope" "${AUTH[@]}" \
  -H 'Content-Type: application/json' -H "x-wf-device-id: $DEVICE_A" \
  -d "{\"revision\":0,\"envelope\":$TRUSTENV}"

printf 'backup-%s\000\001\002binary' "$RUN" > /tmp/ofc-backup.bin
BSUM=$(shasum -a 256 /tmp/ofc-backup.bin | cut -d' ' -f1)
BSIZE=$(wc -c < /tmp/ofc-backup.bin | tr -d ' ')
BBACKUP=$(uuid)
BPREP=$(curl -sf -X POST "$BASE/api/v1/backups/prepare-upload" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d "{\"request_id\":\"$(uuid)\",\"backup_id\":\"$BBACKUP\",\"key_id\":\"$BKEY\",\"source_id\":\"$BSOURCE\",\"policy_revision\":$BREV,\"format\":1,\"size_bytes\":$BSIZE,\"checksum\":\"sha256:$BSUM\",\"encrypted_metadata\":\"bWV0YQ==\",\"trigger\":\"setup\"}")
check "backup prepare returns a ticket" "$BPREP" '"ticket"'
check "backup prepare returns a PUT transfer" "$BPREP" '"method":"PUT"'
BTICKET=$(j "$BPREP" "['ticket']")
BURL=$(j "$BPREP" "['transfer']['url']")
BHEADSUM=$(j "$BPREP" "['transfer']['headers']['x-amz-checksum-sha256']")
status "backup transfer accepts the ciphertext" 204 -X PUT "$BURL" \
  -H "content-length: $BSIZE" -H "x-amz-checksum-sha256: $BHEADSUM" \
  --data-binary @/tmp/ofc-backup.bin

BUP=$(curl -sf -X POST "$BASE/api/v1/backups/complete-upload" "${AUTH[@]}" \
  -H 'Content-Type: application/json' -d "{\"ticket\":\"$BTICKET\"}")
check "backup completion publishes a point" "$BUP" '"backupId"'
equal "backup completion echoes the id" "$(j "$BUP" "['backupId']")" "$BBACKUP"
equal "backup completion records the size" "$(j "$BUP" "['sizeBytes']")" "$BSIZE"
check "backup completion keeps the checksum" "$BUP" "\"checksum\":\"sha256:$BSUM\""

BPOLICY2=$(curl -sf "${AUTH[@]}" "$BASE/api/v1/backups/policy")
check "a published backup sets lastBackupAt" "$BPOLICY2" '"lastBackupAt":"'
check "a published backup sets nextDueAt" "$BPOLICY2" '"nextDueAt":"'
equal "history reports the backup" \
  "$(j "$(curl -sf "${AUTH[@]}" "$BASE/api/v1/backups/history")" "[0]['backupId']")" "$BBACKUP"

BDL=$(curl -sf -X POST "$BASE/api/v1/backups/$BBACKUP/download-url" "${AUTH[@]}" \
  -H 'Content-Type: application/json' -d '{}')
check "backup download-url returns a GET transfer" "$BDL" '"method":"GET"'
BDLURL=$(j "$BDL" "['transfer']['url']")
curl -sf "$BDLURL" -o /tmp/ofc-backup-dl.bin
check "backup download is byte-identical" \
  "$(cmp -s /tmp/ofc-backup.bin /tmp/ofc-backup-dl.bin && echo same || echo differ)" 'same'

check "deleting one backup succeeds" \
  "$(curl -sf -X DELETE "${AUTH[@]}" "$BASE/api/v1/backups/$BBACKUP")" '"deleted":true'
absent "history no longer lists the deleted backup" \
  "$(curl -sf "${AUTH[@]}" "$BASE/api/v1/backups/history")" "$BBACKUP"
status "an unknown backup download is 404" 404 -X POST "${AUTH[@]}" \
  -H 'Content-Type: application/json' -d '{}' \
  "$BASE/api/v1/backups/$(uuid)/download-url"

section "10. destructive reset"
RESET=$(curl -sf -X POST "$BASE/api/v1/sync/team/keys/reset" "${AUTH[@]}" \
  -H 'Content-Type: application/json' -d '{"reason":"e2e"}')
check "reset succeeds" "$RESET" '"success":true'
check "reset uses camelCase" "$RESET" '"keyVersion"'
check "reset reports a timestamp" "$RESET" '"resetAt"'
NEWKV=$(j "$RESET" "['keyVersion']")
check "reset advances the epoch" "$([[ "$NEWKV" -gt "$KV" ]] && echo yes || echo no)" 'yes'
equal "reset clears the oplog" \
  "$(curl -sf "${AUTH[@]}" -H "x-wf-device-id: $DEVICE_A" "$BASE/api/v1/sync/events/cursor" | jqr "['cursor']")" '0'
check "reset revokes every device" \
  "$(curl -sf "${AUTH[@]}" -H "x-wf-device-id: $DEVICE_A" "$BASE/api/v1/sync/team/devices/$DEVICE_A")" \
  '"trustState":"untrusted"'

printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]

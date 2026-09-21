#!/usr/bin/env bash
# Ephemeral-MinIO e2e for btx-modeld cloud origin layouts. Does not start btxd.
#
# No WAN, no operator hosts, no production. Scratch lives on disk (not /tmp
# tmpfs). The MinIO container is published on 127.0.0.1:<ephemeral> only, never
# --network host, so it cannot clash with anything already bound on this box.
#
# Credentials are the fixed sentinels below. They are written once to a 0600
# file and passed to the helper as `credential_ref`; they are never RPC JSON
# arguments. Everything appended to the audit log goes through redact(), so the
# sentinel literals never reach audit/e2e/minio-layouts.log.
#
# Honest scope, from the source of this tree:
#   - setcloudstorage `layout` is a CloudObjectLayout: AUTO|SOURCE_FILES|
#     PIECE_OBJECTS (helper.cpp CloudConfigFromJson).
#   - Only SOURCE_FILES has a data path. PutSourceFile refuses other layouts
#     (s3_store.cpp) and TryHydrateFromCloud declines them (helper.cpp).
#   - WHOLE_FILE / LARGE_EXTENTS are PhysicalObjectLayout values, reported by
#     getmodelobjectlayout as arithmetic only. They are not cloud layouts and
#     no storage code can execute them.
# So cross-layout btx:// identity is provable for AUTO and SOURCE_FILES, and is
# recorded NOT_IMPLEMENTED for the rest rather than asserted.
set -euo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$ROOT/build-gcc13/bin"
MODELD="$BIN/btx-modeld"
AUDIT="$ROOT/audit/e2e/minio-layouts.log"
WORKDIR="$ROOT/e2e-scratch/minio-layouts"
DOCKER="${DOCKER_BIN:-/usr/bin/docker}"
CONTAINER="btx-e2e-minio-$$"
BUCKET="btx-e2e-models"

# MinIO requires MINIO_ROOT_USER >= 3 and MINIO_ROOT_PASSWORD >= 8 characters.
# Both sentinels are 24 characters, so no padding is needed.
ACCESS_SENTINEL="BTX_TEST_ACCESS_SENTINEL"
SECRET_SENTINEL="BTX_TEST_SECRET_SENTINEL"

CONTAINER_STARTED=0
HELPER_PIDFILE="$WORKDIR/helper.pid"

redact() {
  sed -e "s/${ACCESS_SENTINEL}/BTX_TEST_ACCESS_[REDACTED]/g" \
      -e "s/${SECRET_SENTINEL}/BTX_TEST_SECRET_[REDACTED]/g"
}

log() {
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | redact | tee -a "$AUDIT" >&2
}

cleanup() {
  local rc=$?
  if [[ -f "$HELPER_PIDFILE" ]]; then
    local pid
    pid="$(cat "$HELPER_PIDFILE" 2>/dev/null || true)"
    # Test helper only. Never a production btxd, never SIGKILL first.
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null || true
      for _ in $(seq 1 50); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
      done
    fi
  fi
  if [[ "$CONTAINER_STARTED" == "1" ]]; then
    "$DOCKER" rm -f "$CONTAINER" >/dev/null 2>&1 || true
    log "cleanup: removed container $CONTAINER"
  fi
  rm -rf "$WORKDIR"
  exit "$rc"
}
trap cleanup EXIT

mkdir -p "$(dirname "$AUDIT")"
log "=== e2e-minio-layouts start (pid $$) ==="

if [[ ! -x "$MODELD" ]]; then
  log "HONEST_NOT_RUN btx-modeld missing at $MODELD; build it first (this script never compiles)"
  exit 0
fi

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR/modeldir" "$WORKDIR/import" "$WORKDIR/secrets"

CREDS="$WORKDIR/secrets/cloud-creds.ini"
umask 077
printf 'access_key_id=%s\nsecret_access_key=%s\n' "$ACCESS_SENTINEL" "$SECRET_SENTINEL" >"$CREDS"
chmod 600 "$CREDS"
log "wrote 0600 credential_ref file $(basename "$CREDS") with sentinel credentials (values redacted)"

# --- resolve a locally cached MinIO image; only pull as a last resort --------
minio_image() {
  local ref id
  for ref in ${BTX_MINIO_IMAGE:-} minio/minio:latest minio/minio; do
    [[ -n "$ref" ]] || continue
    if "$DOCKER" image inspect "$ref" >/dev/null 2>&1; then printf '%s' "$ref"; return 0; fi
  done
  # A dangling minio/minio (repo present, tag <none>) is still runnable by ID.
  id="$("$DOCKER" images --no-trunc --format '{{.Repository}} {{.ID}}' 2>/dev/null |
        awk '$1=="minio/minio"{print $2; exit}')"
  if [[ -n "$id" ]] && "$DOCKER" image inspect "$id" >/dev/null 2>&1; then printf '%s' "$id"; return 0; fi
  return 1
}

native_only_notes() {
  log "native-only fallback: exercising the same layout matrix against in-process FakeS3"
  log "  FakeS3 leg is use_fake=true, so it proves layout resolution, config"
  log "  persistence, restart rediscovery and secret hygiene, but it is NOT"
  log "  WAN evidence and not evidence of a real S3 wire protocol."
  BTX_MINIO_FAKE_ONLY=1 run_driver
}

if ! "$DOCKER" version >/dev/null 2>&1; then
  log "HONEST_NOT_RUN docker unusable at $DOCKER (not installed, or daemon/permission denied)"
  MINIO_IMAGE=""
elif ! MINIO_IMAGE="$(minio_image)"; then
  log "no local MinIO image; attempting a bounded pull of minio/minio:latest"
  if timeout 300 "$DOCKER" pull minio/minio:latest >/dev/null 2>&1 && MINIO_IMAGE="$(minio_image)"; then
    log "pulled minio/minio:latest"
  else
    log "HONEST_NOT_RUN docker cannot pull minio/minio (offline, rate limited, or registry blocked)"
    MINIO_IMAGE=""
  fi
fi

# --- python driver ----------------------------------------------------------
# Owns the helper lifecycle (so restart is a plain respawn), creates the bucket
# with a self-contained SigV4 PUT, walks the layout matrix, and independently
# GETs the uploaded object back out of the bucket to check byte identity.
run_driver() {
  python3 - "$MODELD" "$WORKDIR" "$CREDS" "$BUCKET" "$AUDIT" "${MINIO_ENDPOINT:-}" <<'PY'
import datetime
import hashlib
import hmac
import json
import os
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

MODELD, WORKDIR, CREDS, BUCKET, AUDIT, ENDPOINT = (
    Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], Path(sys.argv[5]), sys.argv[6]
)
FAKE_ONLY = os.environ.get("BTX_MINIO_FAKE_ONLY") == "1"
MODELDIR = WORKDIR / "modeldir"
SOCK = MODELDIR / "modeld.sock"
REGION = "us-east-1"
PREFIX = "v1"

creds = dict(
    line.split("=", 1) for line in CREDS.read_text(encoding="utf-8").splitlines() if "=" in line
)
ACCESS = creds["access_key_id"].strip()
SECRET = creds["secret_access_key"].strip()
SENTINELS = (ACCESS, SECRET)


def redact(text):
    out = str(text)
    out = out.replace(ACCESS, "BTX_TEST_ACCESS_[REDACTED]")
    out = out.replace(SECRET, "BTX_TEST_SECRET_[REDACTED]")
    return out


def log(msg):
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    line = f"{stamp} {redact(msg)}\n"
    with AUDIT.open("a", encoding="utf-8") as fh:
        fh.write(line)
    sys.stderr.write(line)


def fail(msg):
    log(f"FAIL {msg}")
    raise SystemExit(1)


# --- unix-socket JSON-RPC to the helper -------------------------------------
helper = None


def rpc_raw(method, params, timeout=60):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(str(SOCK))
    s.sendall(json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).encode() + b"\n")
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
        if b"\n" in data:
            break
    s.close()
    reply = json.loads(data.decode())
    if reply.get("error"):
        return None, reply["error"]
    return reply["result"], None


def rpc(method, params, timeout=60):
    result, err = rpc_raw(method, params, timeout)
    if err is not None:
        raise RuntimeError(f"{method}: {redact(err)}")
    return result


def zero_spend(obj, where):
    if not isinstance(obj, dict):
        fail(f"{where} expected object: {redact(obj)}")
    if obj.get("automatic_spend_atoms", 0) not in (0, "0"):
        fail(f"{where} automatic_spend_atoms must be 0: {redact(obj)}")
    blob = json.dumps(obj)
    for needle in SENTINELS:
        if needle in blob:
            fail(f"{where} leaked a sentinel credential into its RPC response")
    return obj


def start_helper():
    global helper
    if SOCK.exists():
        SOCK.unlink()
    logf = (MODELDIR / "modeld.log").open("a", encoding="utf-8")
    helper = subprocess.Popen(
        [str(MODELD), f"-modeldir={MODELDIR}", "-modelstorage=64MiB", f"-modelrpcsocket={SOCK}"],
        stdout=logf, stderr=subprocess.STDOUT, cwd=str(WORKDIR),
    )
    (WORKDIR / "helper.pid").write_text(str(helper.pid), encoding="utf-8")
    deadline = time.time() + 30
    while time.time() < deadline:
        if helper.poll() is not None:
            fail(f"btx-modeld exited {helper.returncode}")
        try:
            if rpc("getmodelnetworkinfo", []).get("helper_ready"):
                return
        except (OSError, RuntimeError, json.JSONDecodeError):
            time.sleep(0.2)
    fail("btx-modeld never reported helper_ready")


def stop_helper():
    global helper
    if helper is None:
        return
    if helper.poll() is None:
        helper.terminate()  # test helper only; never a production btxd
        try:
            helper.wait(timeout=30)
        except subprocess.TimeoutExpired:
            log("warning: test helper ignored SIGTERM; killing the test child only")
            helper.kill()
            helper.wait(timeout=10)
    helper = None


# --- the standing secret-hygiene assertion ----------------------------------
def assert_no_sentinel_in_logs(where):
    """After every op: nothing under modeldir may contain a sentinel."""
    hits = []
    for path in sorted(MODELDIR.rglob("*")):
        if not path.is_file():
            continue
        try:
            blob = path.read_bytes()
        except OSError:
            continue
        for needle in SENTINELS:
            if needle.encode() in blob:
                hits.append(str(path.relative_to(MODELDIR)))
                break
    if hits:
        fail(f"{where}: sentinel credential found in modeldir: {sorted(set(hits))}")
    log(f"  secret hygiene OK after {where}: no sentinel under modeldir")


# --- minimal SigV4 S3, so the harness can verify the bucket independently ----
def sigv4(method, key, query="", body=b""):
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    host = ENDPOINT.split("://", 1)[1]
    canonical_uri = "/" + BUCKET + (f"/{key}" if key else "")
    payload_hash = hashlib.sha256(body).hexdigest()
    canonical_headers = f"host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_request = "\n".join(
        [method, canonical_uri, query, canonical_headers, signed_headers, payload_hash]
    )
    scope = f"{datestamp}/{REGION}/s3/aws4_request"
    to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical_request.encode()).hexdigest()]
    )
    k = ("AWS4" + SECRET).encode()
    for part in (datestamp, REGION, "s3", "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    url = ENDPOINT + canonical_uri + (f"?{query}" if query else "")
    req = urllib.request.Request(url, method=method, data=body if body else None)
    req.add_header("x-amz-date", amz_date)
    req.add_header("x-amz-content-sha256", payload_hash)
    req.add_header(
        "Authorization",
        f"AWS4-HMAC-SHA256 Credential={ACCESS}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}",
    )
    return req


def s3(method, key="", query="", body=b""):
    try:
        with urllib.request.urlopen(sigv4(method, key, query, body), timeout=30) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def wait_minio_live():
    deadline = time.time() + 90
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{ENDPOINT}/minio/health/live", timeout=5) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.5)
    return False


def list_bucket_keys():
    status, body = s3("GET", query="list-type=2")
    if status != 200:
        return None
    ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
    return [el.text for el in ET.fromstring(body).iter(f"{ns}Key")]


def reconstruct_object(keys, artifact):
    """Independent GET of SOURCE_FILES /files/N, else concatenate PIECE_OBJECTS."""
    if not artifact or not keys:
        return None
    files = [k for k in keys if artifact in k and re.search(r"/files/\d+$", k)]
    if files:
        status, body = s3("GET", key=sorted(files)[0])
        if status != 200:
            fail(f"independent GET {files[0]} returned HTTP {status}")
        return body
    pieces = []
    for k in keys:
        m = re.search(r"/(\d+)/(\d+)\.piece$", k)
        if artifact in k and m:
            pieces.append((int(m.group(1)), int(m.group(2)), k))
    if not pieces:
        return None
    pieces.sort()
    buf = b""
    for _, _, k in pieces:
        status, body = s3("GET", key=k)
        if status != 200:
            fail(f"independent GET {k} returned HTTP {status}")
        buf += body
    return buf


# --- fixture ----------------------------------------------------------------
def write_safetensors(path, marker):
    """Valid safetensors: LE64 header length, header JSON, then exactly the
    tensor bytes the header declares. Distinct markers give distinct artifacts."""
    tensor = (marker.encode() * 512)[:8192].ljust(8192, b"\0")
    header = json.dumps(
        {"w": {"dtype": "U8", "shape": [len(tensor)], "data_offsets": [0, len(tensor)]}},
        separators=(",", ":"),
    ).encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(struct.pack("<Q", len(header)) + header + tensor)
    return hashlib.sha384(path.read_bytes()).hexdigest()


# The canonical artifact is imported once and then re-read under every layout.
# Because artifact identity is content-addressed, importing the same bytes twice
# is refused ("destination artifact exists"), so each layout gets its own
# payload for the store path and shares the canonical one for the identity check.
CANON = WORKDIR / "import" / "model.safetensors"
CANON_SHA384 = write_safetensors(CANON, "btx-minio-canonical\n")

# CloudObjectLayout values that setcloudstorage accepts, plus the two
# PhysicalObjectLayout names the operator asked about. AUTO, SOURCE_FILES and
# PIECE_OBJECTS all have a store path. WHOLE_FILE / LARGE_EXTENTS are arithmetic only.
CLOUD_LAYOUTS = ["AUTO", "SOURCE_FILES", "PIECE_OBJECTS"]
PHYSICAL_ONLY = ["WHOLE_FILE", "LARGE_EXTENTS"]

if FAKE_ONLY:
    log("mode: FakeS3 native-only (no container). Not WAN evidence.")
else:
    log(f"mode: real MinIO container at {ENDPOINT} (loopback publish, path-style addressing)")
    if not wait_minio_live():
        fail("MinIO never became live on the published loopback port")
    log("MinIO /minio/health/live returned 200")
    status, _ = s3("PUT")
    if status not in (200, 409):
        fail(f"bucket create PUT /{BUCKET} returned HTTP {status}")
    log(f"bucket {BUCKET} ready (HTTP {status}; 409 means it already existed)")

def cloud_cfg(layout):
    return {
        "endpoint": ENDPOINT if not FAKE_ONLY else "https://fake.invalid",
        "bucket": BUCKET,
        "prefix": PREFIX,
        "region": REGION,
        "provider": "MINIO",
        "layout": layout,
        "credential_ref": str(CREDS),
        "credential_ref_kind": "path",
        "use_fake": FAKE_ONLY,
        "allow_http_loopback": not FAKE_ONLY,
        "automatic_spend_atoms": 0,
        "idempotency_key": f"e2e-minio-{layout}",
    }


start_helper()
assert_no_sentinel_in_logs("helper start")

# Canonical artifact, imported once under SOURCE_FILES. Every layout below
# re-reads this same btx:// identity. PIECE_OBJECTS uploads are a separate
# payload so the identity check stays content-addressed.
zero_spend(rpc("setcloudstorage", [cloud_cfg("SOURCE_FILES")]), "setcloudstorage canonical")
canon = zero_spend(rpc("importmodel", [str(CANON)], timeout=180), "importmodel canonical")
CANON_URI = canon.get("uri") or canon.get("model_id")
CANON_ARTIFACT = canon.get("artifact_id")
if not CANON_URI:
    fail(f"canonical import returned no uri: {redact(canon)}")
log(f"canonical artifact imported uri={CANON_URI} cloud_uploaded={canon.get('cloud_uploaded')}")
assert_no_sentinel_in_logs("canonical import")

observed = {}
for layout in CLOUD_LAYOUTS:
    log(f"--- layout {layout} ---")
    cfg = cloud_cfg(layout)
    applied, err = rpc_raw("setcloudstorage", [cfg])
    if err is not None:
        log(f"  setcloudstorage rejected {layout}: {redact(err)}")
        assert_no_sentinel_in_logs(f"setcloudstorage {layout} reject")
        observed[layout] = {"configured": False, "reject": True}
        continue
    zero_spend(applied, f"setcloudstorage {layout}")
    if applied.get("secrets_in_response") is not False:
        fail(f"setcloudstorage {layout} must report secrets_in_response=false: {redact(applied)}")
    log(f"  setcloudstorage applied={applied.get('applied')} effective_layout={applied.get('layout')} "
        f"credential_ref={applied.get('credential_ref')} init_error={applied.get('init_error', '')}")
    assert_no_sentinel_in_logs(f"setcloudstorage {layout}")

    probe = zero_spend(rpc("testcloudstorage", [{}]), f"testcloudstorage {layout}")
    if probe.get("live_r2_wan") is True:
        fail(f"testcloudstorage must not claim live WAN: {redact(probe)}")
    log(f"  testcloudstorage probe_ok={probe.get('probe_ok')} error={probe.get('probe_error', '')}")
    assert_no_sentinel_in_logs(f"testcloudstorage {layout}")

    info = zero_spend(rpc("getcloudstorageinfo", [{}]), f"getcloudstorageinfo {layout}")
    log(f"  getcloudstorageinfo configured={info.get('configured')} layout={info.get('layout')} "
        f"auth_ok={info.get('auth_ok')} https_enabled={info.get('https_enabled')}")
    assert_no_sentinel_in_logs(f"getcloudstorageinfo {layout}")

    # A payload unique to this layout, so the store path is genuinely exercised
    # under this layout rather than short-circuited by an existing artifact.
    src = WORKDIR / f"import-{layout.lower()}" / "model.safetensors"
    src_sha384 = write_safetensors(src, f"btx-minio-{layout}\n")
    imported = zero_spend(rpc("importmodel", [str(src)], timeout=180), f"importmodel {layout}")
    uri = imported.get("uri") or imported.get("model_id")
    if not uri:
        fail(f"importmodel {layout} returned no uri: {redact(imported)}")
    log(f"  importmodel uri={uri} cloud_uploaded={imported.get('cloud_uploaded')} "
        f"cloud_layout={imported.get('cloud_layout')} cloud_error={imported.get('cloud_error', '')}")
    assert_no_sentinel_in_logs(f"importmodel {layout}")

    # Restart the helper, then let it rediscover the origin from cloud.json and
    # re-report residency before any read.
    stop_helper()
    log("  helper stopped (SIGTERM); restarting to force cloud.json rediscovery")
    start_helper()
    assert_no_sentinel_in_logs(f"helper restart {layout}")
    rediscovered = zero_spend(rpc("getcloudstorageinfo", [{}]), f"getcloudstorageinfo after restart {layout}")
    if rediscovered.get("layout") != info.get("layout"):
        fail(f"layout not rediscovered after restart: {redact(rediscovered)} vs {redact(info)}")
    log(f"  rediscovered configured={rediscovered.get('configured')} layout={rediscovered.get('layout')}")
    residency = zero_spend(rpc("getmodelresidency", [{}]), f"getmodelresidency {layout}")
    log("  residency vocabulary: "
        f"VERIFIED_REMOTE={residency.get('VERIFIED_REMOTE')} "
        f"head_object_implies_verified_remote={residency.get('remote_existence_implies_verified_remote')}")
    assert_no_sentinel_in_logs(f"getmodelresidency {layout}")

    got = zero_spend(rpc("getmodel", [uri], timeout=180), f"getmodel {layout}")
    if (got.get("uri") or "") != uri:
        fail(f"getmodel returned a different uri after restart: {redact(got)} vs {uri}")
    log(f"  getmodel status={got.get('status')} plan={got.get('plan')} "
        f"artifact_id={got.get('artifact_id')} cloud_hydrated={got.get('cloud_hydrated')}")
    assert_no_sentinel_in_logs(f"getmodel {layout}")

    # The identity check: the canonical btx:// must resolve to exactly the same
    # uri and artifact_id while the origin is configured for this layout.
    canon_read = zero_spend(rpc("getmodel", [CANON_URI], timeout=180), f"getmodel canonical under {layout}")
    if (canon_read.get("uri") or "") != CANON_URI:
        fail(f"canonical uri changed under layout {layout}: {redact(canon_read)}")
    if canon_read.get("artifact_id") != CANON_ARTIFACT:
        fail(f"canonical artifact_id changed under layout {layout}: "
             f"{canon_read.get('artifact_id')} vs {CANON_ARTIFACT}")
    log(f"  canonical btx:// unchanged under {layout} (artifact_id {CANON_ARTIFACT})")
    assert_no_sentinel_in_logs(f"canonical read under {layout}")

    # Independent reads straight out of the bucket, bypassing the helper, so byte
    # identity is checked against the stored objects rather than against a claim.
    layout_object_sha384 = None
    canon_object_sha384 = None
    if not FAKE_ONLY:
        keys = list_bucket_keys()
        log(f"  bucket objects: {keys if keys is not None else 'LIST_FAILED'}")
        for want_artifact, want_sha, tag in (
            (got.get("artifact_id"), src_sha384, f"{layout} payload"),
            (CANON_ARTIFACT, CANON_SHA384, "canonical payload"),
        ):
            hit_body = reconstruct_object(keys, want_artifact)
            if hit_body is None:
                log(f"  no source-file or piece object for the {tag}: nothing to read back")
                continue
            digest = hashlib.sha384(hit_body).hexdigest()
            if digest != want_sha:
                fail(f"object bytes differ from the local file for the {tag} under {layout}")
            log(f"  independent GET of the {tag} sha384 matches the local file")
            if tag.startswith("canonical"):
                canon_object_sha384 = digest
            else:
                layout_object_sha384 = digest

    observed[layout] = {
        "configured": True,
        "reject": False,
        "uri": uri,
        "artifact_id": got.get("artifact_id"),
        "effective_layout": rediscovered.get("layout"),
        "cloud_uploaded": bool(imported.get("cloud_uploaded")),
        "cloud_hydrated": got.get("cloud_hydrated"),
        "object_sha384": layout_object_sha384,
        "canon_object_sha384": canon_object_sha384,
    }

# PhysicalObjectLayout names are not cloud layouts. Confirm setcloudstorage says
# so, then record the arithmetic the planner does publish for them.
for layout in PHYSICAL_ONLY:
    log(f"--- layout {layout} (PhysicalObjectLayout, arithmetic only) ---")
    cfg = {
        "endpoint": ENDPOINT if not FAKE_ONLY else "https://fake.invalid",
        "bucket": BUCKET,
        "credential_ref": str(CREDS),
        "layout": layout,
        "use_fake": FAKE_ONLY,
        "allow_http_loopback": not FAKE_ONLY,
    }
    _, perr0 = rpc_raw("setcloudstorage", [cfg])
    if perr0 is None:
        fail(f"setcloudstorage unexpectedly accepted {layout} as a CloudObjectLayout")
    err = perr0
    log(f"  setcloudstorage correctly rejects {layout}: {redact(err)}")
    plan, perr = rpc_raw("getmodelobjectlayout", [{"layout": layout, "file_size_bytes": CANON.stat().st_size}])
    if perr is not None:
        log(f"  HONEST_NOT_RUN getmodelobjectlayout {layout}: {redact(perr)}")
    else:
        log(f"  getmodelobjectlayout effective={plan.get('effective')} "
            f"objects={plan.get('objects', plan.get('extent_objects'))} "
            f"cloud_r2_auto={plan.get('cloud_r2_auto')}")
    assert_no_sentinel_in_logs(f"{layout} arithmetic")
    observed[layout] = {"configured": False, "cloud_layout": False}

# --- verdicts ---------------------------------------------------------------
log("--- verdict ---")
byte_layouts = sorted(k for k, v in observed.items() if v.get("cloud_uploaded"))
canon_checked = sorted(k for k, v in observed.items() if v.get("canon_object_sha384"))

log(f"btx:// identity: canonical {CANON_URI} resolved to the same artifact_id under all "
    f"configured layouts {sorted(k for k in CLOUD_LAYOUTS if observed[k].get('configured'))}")
if canon_checked:
    shas = {observed[k]["canon_object_sha384"] for k in canon_checked}
    if len(shas) > 1 or shas != {CANON_SHA384}:
        fail(f"canonical object bytes are not layout-invariant in the bucket: {canon_checked}")
    log(f"canonical object bytes in the bucket unchanged and equal to the source while the "
        f"origin was configured for {canon_checked}")

if not byte_layouts:
    log("HONEST_NOT_RUN no layout completed a byte round-trip on this run")
elif FAKE_ONLY:
    log(f"FakeS3 store+read succeeded for layouts {byte_layouts}. HONEST_NOT_RUN real S3 wire "
        f"protocol: FakeS3 is in-process, so there was no socket, no MinIO, and no independent "
        f"reader. This is layout-resolution and hygiene evidence only.")
else:
    log(f"PROVEN cloud byte round-trip (store + independent GET + sha384) for layouts: {byte_layouts}")

for layout in CLOUD_LAYOUTS:
    if observed[layout].get("configured") and not observed[layout].get("cloud_uploaded"):
        log(f"NOT_IMPLEMENTED {layout}: config accepted and rediscovered, but no object was "
            f"stored.")
for layout in PHYSICAL_ONLY:
    log(f"NOT_A_CLOUD_LAYOUT {layout}: PhysicalObjectLayout arithmetic only; no cloud "
        f"representation, so cross-layout byte identity is unprovable by construction.")

if any(o.get("cloud_hydrated") for o in observed.values() if isinstance(o, dict)):
    log("cloud hydration exercised")
else:
    log("HONEST_NOT_RUN TryHydrateFromCloud: it only runs for an `incomplete` catalog entry, "
        "and this script imports from local bytes, so every entry is complete. The bucket read "
        "above is an independent S3 GET, not a helper hydration.")

assert_no_sentinel_in_logs("final")
log("=== e2e-minio-layouts PASS ===")
PY
}

if [[ -n "${MINIO_IMAGE:-}" ]]; then
  PORT="$(python3 -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()')"
  export MINIO_ENDPOINT="http://127.0.0.1:$PORT"
  log "starting ephemeral MinIO on $MINIO_ENDPOINT (published to loopback only, never --network host)"
  if "$DOCKER" run -d --name "$CONTAINER" --pull never \
      -p "127.0.0.1:$PORT:9000" \
      -e "MINIO_ROOT_USER=$ACCESS_SENTINEL" \
      -e "MINIO_ROOT_PASSWORD=$SECRET_SENTINEL" \
      "$MINIO_IMAGE" server /data >/dev/null 2>"$WORKDIR/docker-run.err"; then
    CONTAINER_STARTED=1
    log "container $CONTAINER started"
    run_driver
  else
    log "HONEST_NOT_RUN docker run failed: $(tr '\n' ' ' <"$WORKDIR/docker-run.err")"
    native_only_notes
  fi
else
  native_only_notes
fi

log "=== e2e-minio-layouts end ==="

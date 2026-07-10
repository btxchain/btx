#!/usr/bin/env bash
#
# Source-build installer used by the BTX auto-update path.
#
# This mirrors the behavior of https://btx.dev/install.sh: fetch and verify a
# signed manifest, resolve a source ref, build btxd/btx-cli, verify the produced
# binaries, install them into a versioned release tree, then stop/restart the
# running node only after the new binaries are ready.

set -euo pipefail
IFS=$'\n\t'

BTX_MANIFEST_URL="${BTX_MANIFEST_URL:-https://btx.dev/version.txt}"
BTX_MANIFEST_SIG_URL="${BTX_MANIFEST_SIG_URL:-}"
BTX_VERSION="${BTX_VERSION:-}"
BTX_REPO_URL="${BTX_REPO_URL:-}"
BTX_RELEASE_TAG="${BTX_RELEASE_TAG:-}"
BTX_GIT_REF="${BTX_GIT_REF:-}"
BTX_RELEASE_PUB="${BTX_RELEASE_PUB:-}"
BTX_TRUSTED_ORIGIN="${BTX_TRUSTED_ORIGIN:-https://btx.dev}"
# Honor the XDG base-dir spec so service accounts can redirect state without $HOME (see
# validate_home_roots). Fall back to the conventional ~ locations otherwise.
BTX_INSTALL_ROOT="${BTX_INSTALL_ROOT:-${XDG_DATA_HOME:-$HOME/.local/share}/btx-updater}"
BTX_LINK_DIR="${BTX_LINK_DIR:-${XDG_BIN_HOME:-$HOME/.local/bin}}"
BTX_CACHE_ROOT="${BTX_CACHE_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/btx-updater}"
BTX_JOBS="${BTX_JOBS:-}"
BTX_AUTO_RESTART="${BTX_AUTO_RESTART:-1}"
BTX_START_IF_STOPPED="${BTX_START_IF_STOPPED:-0}"
# Prefer a signed prebuilt binary matching this platform (manifest `prebuilt` map) over a source
# build, when the manifest pins git_commit. Set 0 to always build from source.
BTX_PREFER_PREBUILT="${BTX_PREFER_PREBUILT:-1}"
BTX_ALLOW_GIT_REF_FALLBACK="${BTX_ALLOW_GIT_REF_FALLBACK:-1}"
BTX_ENSURE_RETAIN_INDEX="${BTX_ENSURE_RETAIN_INDEX:-1}"
BTX_AUTOUPDATE="${BTX_AUTOUPDATE:-0}"
BTX_AUTOUPDATE_PID="${BTX_AUTOUPDATE_PID:-}"
BTX_AUTOUPDATE_DATADIR="${BTX_AUTOUPDATE_DATADIR:-}"
BTX_AUTOUPDATE_TELEMETRY_QUERY="${BTX_AUTOUPDATE_TELEMETRY_QUERY:-}"
# Release-signature scheme + key forwarded by the node. When the scheme is a post-quantum one
# (ml-dsa-44 / slh-dsa-128s) the installer verifies signatures with `btx-util verifyupdatesig`
# instead of openssl, so the source/commit trust is quantum-safe and matches the node.
BTX_AUTOUPDATE_PUBKEY_ALGO="${BTX_AUTOUPDATE_PUBKEY_ALGO:-secp256k1}"
BTX_AUTOUPDATE_PUBKEY="${BTX_AUTOUPDATE_PUBKEY:-}"
BTX_UTIL="${BTX_UTIL:-}"
BTX_TARGET_PID="${BTX_TARGET_PID:-}"
BTX_TARGET_DATADIR="${BTX_TARGET_DATADIR:-}"
BTX_TARGET_CONF="${BTX_TARGET_CONF:-}"
BTX_TARGET_WALLETDIR="${BTX_TARGET_WALLETDIR:-}"
BTX_TARGET_BLOCKSDIR="${BTX_TARGET_BLOCKSDIR:-}"
BTX_TARGET_PIDFILE="${BTX_TARGET_PIDFILE:-}"
BTX_TARGET_CHAIN_FLAG="${BTX_TARGET_CHAIN_FLAG:-}"
BTX_UPDATER_TEST_ALLOW_NON_BTXD_PID="${BTX_UPDATER_TEST_ALLOW_NON_BTXD_PID:-0}"
BTX_STOP_TIMEOUT_SECONDS="${BTX_STOP_TIMEOUT_SECONDS:-120}"
BTX_CLEANUP_CACHE_REPO=""
BTX_CLEANUP_WORKTREE_PATH=""
BTX_CLEANUP_LOCK_DIR=""
BTX_TMPDIR=""
BTX_RELEASE_RETENTION="${BTX_RELEASE_RETENTION:-3}"
BTX_MIN_FREE_GB="${BTX_MIN_FREE_GB:-6}"
# Machine-readable, append-only progress log (JSON lines) so operators/monitoring can see exactly
# what each auto-update run did and where it stopped. Set empty to disable.
BTX_STATUS_FILE="${BTX_STATUS_FILE:-$BTX_INSTALL_ROOT/status.jsonl}"
BTX_STAGE="startup"
BTX_STATUS_VERSION=""
BTX_STATUS_COMMIT=""

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
note() { printf '[btx-updater] %s\n' "$*"; }
warn() { printf '[btx-updater] warning: %s\n' "$*" >&2; }

# Append one JSON record to the status log; never fails the run if it cannot write.
status_event() {
  [[ -n "$BTX_STATUS_FILE" ]] || return 0
  local stage="$1" state="$2" detail="${3:-}"
  mkdir -p "$(dirname "$BTX_STATUS_FILE")" 2>/dev/null || return 0
  python3 - "$BTX_STATUS_FILE" "$stage" "$state" "$detail" "$BTX_STATUS_VERSION" "$BTX_STATUS_COMMIT" "$$" <<'PY' 2>/dev/null || true
import json, sys, time
path, stage, state, detail, version, commit, pid = sys.argv[1:8]
rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "pid": int(pid),
       "stage": stage, "state": state}
for k, v in (("detail", detail), ("version", version), ("commit", commit)):
    if v:
        rec[k] = v
with open(path, "a", encoding="utf8") as f:
    f.write(json.dumps(rec) + "\n")
PY
}

# Mark the current stage and emit a "begin" event, so a later die() records where it failed.
stage() { BTX_STAGE="$1"; status_event "$1" "begin" "${2:-}"; }

die() { status_event "$BTX_STAGE" "failed" "$*"; printf '[btx-updater] error: %s\n' "$*" >&2; exit 1; }

# Refuse to scatter state under an unusable "/.local" etc. when a service account has no $HOME.
# Operators must set the roots explicitly (or XDG_*_HOME) in that case.
validate_home_roots() {
  if [[ -n "${HOME:-}" && "$HOME" != "/" ]]; then
    return 0
  fi
  local var
  for var in BTX_INSTALL_ROOT BTX_LINK_DIR BTX_CACHE_ROOT BTX_STATUS_FILE; do
    case "${!var}" in
      /.local/*|/.cache/*|/.config/*|/.btx*|/.*)
        die "no usable \$HOME for this account; set $var explicitly (or XDG_*_HOME). Got: '${!var}'" ;;
    esac
  done
}

cleanup_worktree() {
  if [[ -n "$BTX_CLEANUP_CACHE_REPO" && -n "$BTX_CLEANUP_WORKTREE_PATH" ]]; then
    git -C "$BTX_CLEANUP_CACHE_REPO" worktree remove --force "$BTX_CLEANUP_WORKTREE_PATH" >/dev/null 2>&1 || true
  fi
  if [[ -n "$BTX_TMPDIR" && -d "$BTX_TMPDIR" ]]; then
    rm -rf "$BTX_TMPDIR"
  fi
  if [[ -n "$BTX_CLEANUP_LOCK_DIR" && -d "$BTX_CLEANUP_LOCK_DIR" ]]; then
    rm -rf "$BTX_CLEANUP_LOCK_DIR" 2>/dev/null || true
  fi
}

# Exclusive per-install-root lock so two concurrent updater runs (e.g. the node re-firing before a
# long build finishes) cannot both stop/swap/restart the same node and corrupt its datadir. mkdir
# is atomic on POSIX; a lock left by a crashed run whose pid is dead is reclaimed.
acquire_lock() {
  local lock_dir="$BTX_INSTALL_ROOT/.updater.lock"
  mkdir -p "$BTX_INSTALL_ROOT"
  local tries=0
  while ! mkdir "$lock_dir" 2>/dev/null; do
    local holder=""
    [[ -f "$lock_dir/pid" ]] && holder="$(cat "$lock_dir/pid" 2>/dev/null || true)"
    if [[ -n "$holder" ]] && kill -0 "$holder" 2>/dev/null; then
      die "another btx-updater run (pid $holder) is in progress for $BTX_INSTALL_ROOT"
    fi
    rm -rf "$lock_dir" 2>/dev/null || true
    tries=$((tries + 1))
    [[ "$tries" -ge 3 ]] && die "could not acquire updater lock at $lock_dir"
  done
  printf '%s\n' "$$" >"$lock_dir/pid"
  BTX_CLEANUP_LOCK_DIR="$lock_dir"
}

# Fail early (before the running node is touched) if there is not enough free space for a source
# build + a new release tree. Portable via python os.statvfs; never blocks if it cannot measure.
require_free_space() {
  local path="$1"
  mkdir -p "$path"
  python3 - "$path" "$BTX_MIN_FREE_GB" <<'PY' || die "insufficient free disk space for the update build"
import os, sys
path, min_gb = sys.argv[1], float(sys.argv[2])
try:
    st = os.statvfs(path)
    free_gb = (st.f_bavail * st.f_frsize) / (1024 ** 3)
except OSError:
    raise SystemExit(0)
if free_gb < min_gb:
    sys.stderr.write(f"[btx-updater] only {free_gb:.1f} GiB free at {path}, need >= {min_gb} GiB\n")
    raise SystemExit(1)
PY
}

# Keep the current + the most recent N release trees; remove older ones so a long-lived fleet node
# does not exhaust disk over many updates. Never removes the tree the `current` symlink points at.
prune_old_releases() {
  local release_root="$1"
  [[ -d "$release_root" ]] || return 0
  python3 - "$release_root" "$BTX_INSTALL_ROOT/current" "$BTX_RELEASE_RETENTION" <<'PY' || true
import os, sys, shutil
root, current_link, keep = sys.argv[1], sys.argv[2], int(sys.argv[3])
try:
    active = os.path.realpath(current_link)
except OSError:
    active = ""
dirs = []
for name in os.listdir(root):
    p = os.path.join(root, name)
    if os.path.isdir(p):
        dirs.append((os.path.getmtime(p), p))
dirs.sort(reverse=True)
for _, p in dirs[keep:]:
    if os.path.realpath(p) == active:
        continue
    shutil.rmtree(p, ignore_errors=True)
PY
}

# Keep the most recent N persistent build worktrees + build dirs (so incremental rebuilds stay
# fast) but bound disk use over a long-lived fleet. Detaches old git worktrees cleanly so no stale
# admin entries leak. Never touches the one we just built.
prune_build_cache() {
  local cache_repo="$1" worktree_root="$2" build_root="$3" keep_key="$4"
  local entry name
  if [[ -d "$worktree_root" ]]; then
    local -a entries=()
    while IFS= read -r entry; do entries+=("$entry"); done < <(
      python3 - "$worktree_root" "$BTX_RELEASE_RETENTION" "$keep_key" <<'PY'
import os, sys
root, keep, keep_key = sys.argv[1], int(sys.argv[2]), sys.argv[3]
dirs = [(os.path.getmtime(os.path.join(root, n)), n)
        for n in os.listdir(root) if os.path.isdir(os.path.join(root, n))]
dirs.sort(reverse=True)
for _, n in dirs[keep:]:
    if n != keep_key:
        print(n)
PY
    )
    if ((${#entries[@]})); then
      for name in "${entries[@]}"; do
        [[ -n "$name" ]] || continue
        git -C "$cache_repo" worktree remove --force "$worktree_root/$name" >/dev/null 2>&1 || true
        # ${var:?} guards: never let an empty root expand "rm -rf" toward "/" (SC2115).
        rm -rf "${worktree_root:?}/$name" "${build_root:?}/$name" 2>/dev/null || true
      done
    fi
  fi
  git -C "$cache_repo" worktree prune >/dev/null 2>&1 || true
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

default_jobs() {
  if [[ -n "$BTX_JOBS" ]]; then
    printf '%s\n' "$BTX_JOBS"
    return 0
  fi
  # Cap parallelism by BOTH cpu count and RAM: BTX's PQ/MatMul translation units are memory-heavy,
  # so -j$(nproc) OOM-kills small nodes mid-build. Allow ~one job per 2 GiB of total RAM. Portable
  # (SC_PHYS_PAGES works on Linux + macOS); falls back to cpu count if anything is unavailable.
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY' 2>/dev/null && return 0
import os
cpus = os.cpu_count() or 4
try:
    total = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
    mem_cap = max(1, total // (2 * 1024 ** 3))
except (OSError, ValueError):
    mem_cap = cpus
print(max(1, min(cpus, mem_cap)))
PY
  fi
  if command -v getconf >/dev/null 2>&1; then
    getconf _NPROCESSORS_ONLN 2>/dev/null || printf '4\n'
    return 0
  fi
  printf '4\n'
}

default_datadir() {
  case "$(uname -s)" in
    Darwin) printf '%s\n' "$HOME/Library/Application Support/BTX" ;;
    *) printf '%s\n' "$HOME/.btx" ;;
  esac
}

default_conf_path() {
  printf '%s/btx.conf\n' "$1"
}

manifest_sig_url_default() {
  printf '%s.sig\n' "$1"
}

with_telemetry_query() {
  local url="$1"
  local query="${BTX_AUTOUPDATE_TELEMETRY_QUERY:-}"
  if [[ -z "$query" ]]; then
    printf '%s\n' "$url"
    return 0
  fi
  case "$url" in
    http://*|https://*) ;;
    *) printf '%s\n' "$url"; return 0 ;;
  esac
  case "$url" in
    *\?|*\&) printf '%s%s\n' "$url" "$query" ;;
    *\?*) printf '%s&%s\n' "$url" "$query" ;;
    *) printf '%s?%s\n' "$url" "$query" ;;
  esac
}

json_field() {
  local key="$1"
  local default_value="${2:-}"
  python3 -c '
import json
import sys

key = sys.argv[1]
default = sys.argv[2]
payload = json.loads(sys.stdin.read())
value = payload
for part in key.split("."):
    if isinstance(value, dict) and part in value:
        value = value[part]
    else:
        print(default)
        raise SystemExit(0)
if value is None:
    print(default)
elif isinstance(value, (dict, list)):
    print(json.dumps(value))
else:
    print(str(value))
' "$key" "$default_value"
}

json_file_field() {
  local file_path="$1"
  local key="$2"
  local default_value="${3:-}"
  [[ -f "$file_path" ]] || {
    printf '%s\n' "$default_value"
    return 0
  }
  json_field "$key" "$default_value" <"$file_path"
}

require_trusted_url() {
  local url="$1"
  local label="$2"
  case "$url" in
    "$BTX_TRUSTED_ORIGIN"/*) ;;
    *) die "refusing untrusted ${label}: ${url}" ;;
  esac
}

write_default_release_pub() {
  local target_path="$1"
  cat >"$target_path" <<'EOF'
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAER46df5hoI6HXfE4rt19GANPcy1R1Nx5F
ki6/w5UhQgxBcePbnlrBeXjZ9nWUvnKdzucPwpvaFks18AP2qsbjQQ==
-----END PUBLIC KEY-----
EOF
}

resolve_release_pub_path() {
  if [[ -n "$BTX_RELEASE_PUB" ]]; then
    [[ -f "$BTX_RELEASE_PUB" ]] || die "BTX_RELEASE_PUB does not exist: $BTX_RELEASE_PUB"
    printf '%s\n' "$BTX_RELEASE_PUB"
    return 0
  fi

  local embedded_pub="$BTX_TMPDIR/btx-release.pub"
  write_default_release_pub "$embedded_pub"
  printf '%s\n' "$embedded_pub"
}

# Locate the installed btx-util used for post-quantum signature verification, portably (macOS/BSD
# have no /proc). Resolution order: explicit BTX_UTIL; the node-forwarded binary directory; the
# previously-installed release tree / link dir; the sibling of the running btxd via /proc on Linux;
# then PATH.
resolve_btx_util_path() {
  local candidate
  if [[ -n "$BTX_UTIL" && -x "$BTX_UTIL" ]]; then
    printf '%s\n' "$BTX_UTIL"
    return 0
  fi
  if [[ -n "${BTX_AUTOUPDATE_BIN_DIR:-}" && -x "${BTX_AUTOUPDATE_BIN_DIR}/btx-util" ]]; then
    printf '%s\n' "${BTX_AUTOUPDATE_BIN_DIR}/btx-util"
    return 0
  fi
  for candidate in "$BTX_INSTALL_ROOT/current/bin/btx-util" "$BTX_LINK_DIR/btx-util"; do
    [[ -x "$candidate" ]] && { printf '%s\n' "$candidate"; return 0; }
  done
  if [[ -n "${BTX_TARGET_PID:-}" && -r "/proc/$BTX_TARGET_PID/exe" ]]; then
    local exe bindir
    # /proc/<pid>/exe already resolves to an absolute path, so plain readlink (no GNU -f) suffices.
    exe="$(readlink "/proc/$BTX_TARGET_PID/exe" 2>/dev/null || true)"
    if [[ -n "$exe" ]]; then
      bindir="$(dirname "$exe")"
      [[ -x "$bindir/btx-util" ]] && { printf '%s\n' "$bindir/btx-util"; return 0; }
    fi
  fi
  command -v btx-util 2>/dev/null && return 0
  return 1
}

verify_detached_signature() {
  local file_path="$1"
  local sig_path="$2"
  local pub_path="$3"
  local algo
  algo="$(printf '%s' "$BTX_AUTOUPDATE_PUBKEY_ALGO" | tr '[:upper:]' '[:lower:]')"
  case "$algo" in
    ml-dsa-44|mldsa44|slh-dsa-128s|slhdsa128s)
      [[ -n "$BTX_AUTOUPDATE_PUBKEY" ]] \
        || die "post-quantum signature verification requested ($algo) but BTX_AUTOUPDATE_PUBKEY is empty"
      local util
      util="$(resolve_btx_util_path)" \
        || die "btx-util not found for post-quantum ($algo) signature verification"
      "$util" verifyupdatesig "$algo" "$BTX_AUTOUPDATE_PUBKEY" "$file_path" "$sig_path" >/dev/null 2>&1 \
        || die "post-quantum ($algo) signature verification failed for $(basename "$file_path")"
      ;;
    *)
      openssl dgst -sha256 -verify "$pub_path" -signature "$sig_path" "$file_path" >/dev/null 2>&1 \
        || die "signature verification failed for $(basename "$file_path")"
      ;;
  esac
}

# Non-fatal variant of verify_detached_signature: returns 0/1 instead of dying. Used for prebuilt
# artifacts so a download glitch / signature problem falls back to a source build (independently
# trusted) rather than aborting the whole update.
verify_artifact_signature() {
  local file_path="$1" sig_path="$2" pub_path="$3" algo
  algo="$(printf '%s' "$BTX_AUTOUPDATE_PUBKEY_ALGO" | tr '[:upper:]' '[:lower:]')"
  case "$algo" in
    ml-dsa-44|mldsa44|slh-dsa-128s|slhdsa128s)
      [[ -n "$BTX_AUTOUPDATE_PUBKEY" ]] || return 1
      local util
      util="$(resolve_btx_util_path)" || return 1
      "$util" verifyupdatesig "$algo" "$BTX_AUTOUPDATE_PUBKEY" "$file_path" "$sig_path" >/dev/null 2>&1
      ;;
    *)
      openssl dgst -sha256 -verify "$pub_path" -signature "$sig_path" "$file_path" >/dev/null 2>&1
      ;;
  esac
}

verify_sha256() {
  local file="$1" expected="$2" actual
  expected="$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')"
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$file" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$file" | awk '{print $1}')"
  else
    actual="$(openssl dgst -sha256 "$file" | awk '{print $NF}')"
  fi
  [[ -n "$actual" && "$actual" == "$expected" ]]
}

# Print the CUDA release flavors supported by the installed NVIDIA driver, most
# specific first. `nvidia-smi` must successfully see a GPU; merely having nvcc
# or a CUDA toolkit directory is not enough to select a GPU release archive.
detect_cuda_release_flavors() {
  local output major
  command -v nvidia-smi >/dev/null 2>&1 || return 0
  output="$(nvidia-smi 2>/dev/null)" || return 0
  major="$(printf '%s\n' "$output" | sed -n 's/.*CUDA Version:[[:space:]]*\([0-9][0-9]*\)\([.][0-9][0-9]*\)\{0,1\}.*/\1/p' | head -n 1)"
  [[ "$major" =~ ^[0-9]+$ ]] || return 0

  # A CUDA 13-capable driver can also run the CUDA 12 release, so retain that
  # as a fallback before the CPU-only archive. Drivers older than CUDA 12 do
  # not match either of the release flavors currently published by BTX.
  if (( major >= 13 )); then
    printf '%s\n' "cuda13" "cuda12"
  elif (( major == 12 )); then
    printf '%s\n' "cuda12"
  fi
}

# Candidate platform keys, most specific first, used to select a matching
# prebuilt artifact from the manifest's `prebuilt` map. The canonical CUDA keys
# match package_release_archive.py / btx-release-manifest.json. Linux CPU builds
# distinguish glibc vs musl; both aarch64 and arm64 spellings are offered so
# either release-naming convention matches.
detect_platform_keys() {
  local os arch libc cuda_flavor
  case "$(uname -s)" in
    Linux) os="linux" ;;
    Darwin) os="darwin" ;;
    *) os="$(uname -s | tr '[:upper:]' '[:lower:]')" ;;
  esac
  arch="$(uname -m)"
  case "$arch" in
    amd64|x86_64) arch="x86_64" ;;
    arm64|aarch64) arch="aarch64" ;;
  esac
  if [[ "$os" == "linux" ]]; then
    if ls /lib/ld-musl-* >/dev/null 2>&1 || ldd --version 2>&1 | grep -qi musl; then
      libc="musl"
    else
      libc="glibc"
    fi
    if [[ "$arch" == "x86_64" && "$libc" == "glibc" ]]; then
      while IFS= read -r cuda_flavor; do
        [[ -n "$cuda_flavor" ]] && printf '%s-%s-%s\n' "$os" "$arch" "$cuda_flavor"
      done < <(detect_cuda_release_flavors)
    fi
    printf '%s-%s-%s\n' "$os" "$arch" "$libc"
    [[ "$arch" == "aarch64" ]] && printf '%s-arm64-%s\n' "$os" "$libc"
  else
    printf '%s-%s\n' "$os" "$arch"
    [[ "$arch" == "aarch64" ]] && printf '%s-arm64\n' "$os"
  fi
}

manifest_has_prebuilt() {
  local v
  v="$(json_file_field "$1" "prebuilt" "")"
  [[ -n "$v" && "$v" != "null" ]]
}

# Locate the bin/ dir inside an extracted prebuilt tarball (it may be at bin/, <name>/bin/, or root).
find_prebuilt_bindir() {
  local root="$1" d
  for d in "$root/bin" "$root"/*/bin "$root"; do
    [[ -x "$d/btxd" && -x "$d/btx-cli" ]] && { printf '%s\n' "$d"; return 0; }
  done
  return 1
}

install_prebuilt_release_tree() {
  local bin_dir="$1" version="$2" release_dir="$3" platform="$4" url="$5" commit="$6"
  mkdir -p "$release_dir/bin"
  cp "$bin_dir/btxd" "$release_dir/bin/btxd"
  cp "$bin_dir/btx-cli" "$release_dir/bin/btx-cli"
  [[ -x "$bin_dir/btx-wallet" ]] && cp "$bin_dir/btx-wallet" "$release_dir/bin/btx-wallet"
  # btx-util ships in the tree (and is symlinked on activate) so the NEXT cycle can verify PQ sigs.
  [[ -x "$bin_dir/btx-util" ]] && cp "$bin_dir/btx-util" "$release_dir/bin/btx-util"
  cat >"$release_dir/manifest.json" <<EOF
{
  "version": "${version}",
  "source": "prebuilt",
  "platform": "${platform}",
  "url": "${url}",
  "git_commit": "${commit}",
  "installed_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
}

# Try to install a signed prebuilt release matching this platform. Returns 0 on success (release_dir
# populated + binaries verified), 1 if no usable prebuilt was found/verified (caller source-builds).
# Trust is anchored by the SAME release-signature scheme as the manifest (PQ via btx-util, or
# classical via openssl), plus an optional sha256 from the signed manifest.
try_install_prebuilt() {
  local manifest_path="$1" version="$2" release_dir="$3" expected_commit="$4" release_pub_path="$5"
  [[ "${BTX_PREFER_PREBUILT:-1}" == "1" ]] || return 1
  command -v tar >/dev/null 2>&1 || return 1

  local key url sig_url sha256 tarball sig extract bindir
  for key in $(detect_platform_keys); do
    url="$(json_file_field "$manifest_path" "prebuilt.${key}.url" "")"
    [[ -n "$url" && "$url" != "null" ]] || continue
    sig_url="$(json_file_field "$manifest_path" "prebuilt.${key}.sig_url" "$(manifest_sig_url_default "$url")")"
    sha256="$(json_file_field "$manifest_path" "prebuilt.${key}.sha256" "")"
    note "Found prebuilt binary for platform $key"

    # Both artifact URLs must sit under the trusted origin, like every other fetched URL.
    require_trusted_url "$url" "prebuilt.${key}.url"
    require_trusted_url "$sig_url" "prebuilt.${key}.sig_url"

    tarball="$BTX_TMPDIR/prebuilt-${key}.tar.gz"
    sig="$BTX_TMPDIR/prebuilt-${key}.sig"
    curl -fsSL "$(with_telemetry_query "$url")" -o "$tarball" || { warn "prebuilt download failed ($key); will try next/source"; continue; }
    curl -fsSL "$(with_telemetry_query "$sig_url")" -o "$sig" || { warn "prebuilt signature download failed ($key)"; continue; }

    if [[ -n "$sha256" && "$sha256" != "null" ]] && ! verify_sha256 "$tarball" "$sha256"; then
      warn "prebuilt sha256 mismatch ($key); ignoring this artifact"
      continue
    fi
    if ! verify_artifact_signature "$tarball" "$sig" "$release_pub_path"; then
      warn "prebuilt signature verification failed ($key); ignoring this artifact"
      continue
    fi

    extract="$BTX_TMPDIR/prebuilt-extract-${key}"
    rm -rf "$extract"; mkdir -p "$extract"
    if ! tar -xzf "$tarball" -C "$extract" 2>/dev/null; then
      warn "prebuilt extract failed ($key)"; continue
    fi
    bindir="$(find_prebuilt_bindir "$extract")" || { warn "prebuilt archive missing btxd/btx-cli ($key)"; continue; }
    local verify_error
    if ! verify_error="$(check_binaries "$bindir")"; then
      warn "prebuilt binary verification failed ($key): ${verify_error}; will try next/source"
      status_event "prebuilt" "rejected" "$key: ${verify_error}"
      continue
    fi
    install_prebuilt_release_tree "$bindir" "$version" "$release_dir" "$key" "$url" "$expected_commit"
    status_event "prebuilt" "installed" "$key"
    note "Installed verified prebuilt release for $key"
    return 0
  done
  return 1
}

fetch_verified_manifest() {
  local manifest_url="$1"
  local manifest_path="$2"
  local sig_path="$3"
  local pub_path="$4"

  require_trusted_url "$manifest_url" "manifest_url"
  curl -fsSL "$(with_telemetry_query "$manifest_url")" -o "$manifest_path"

  local sig_url
  sig_url="${BTX_MANIFEST_SIG_URL:-$(json_file_field "$manifest_path" "sig_url" "$(manifest_sig_url_default "$manifest_url")")}"
  [[ -n "$sig_url" ]] || die "manifest signature URL could not be resolved"
  require_trusted_url "$sig_url" "sig_url"
  curl -fsSL "$(with_telemetry_query "$sig_url")" -o "$sig_path"

  verify_detached_signature "$manifest_path" "$sig_path" "$pub_path"
}

ref_exists_remote() {
  local repo_url="$1"
  local ref="$2"
  [[ -n "$ref" ]] || return 1
  if [[ "$ref" =~ ^[0-9a-fA-F]{40}$ ]]; then
    return 0
  fi
  git ls-remote --exit-code "$repo_url" "$ref" >/dev/null 2>&1
}

branch_exists_remote() {
  local repo_url="$1"
  local branch="$2"
  [[ -n "$branch" ]] || return 1
  git ls-remote --exit-code --heads "$repo_url" "$branch" >/dev/null 2>&1
}

pid_is_numeric() {
  [[ "$1" =~ ^[0-9]+$ ]] && (( "$1" > 0 ))
}

normalize_path() {
  python3 - "$1" <<'PY'
import os
import sys

print(os.path.realpath(os.path.expanduser(sys.argv[1])))
PY
}

paths_equal() {
  [[ "$(normalize_path "$1")" == "$(normalize_path "$2")" ]]
}

process_command() {
  local pid="$1"
  ps -ww -o command= -p "$pid" 2>/dev/null | sed -n '1p'
}

process_is_zombie() {
  local pid="$1"
  local state
  state="$(ps -o stat= -p "$pid" 2>/dev/null | tr -d '[:space:]' || true)"
  [[ "$state" == *Z* ]]
}

process_fingerprint() {
  local pid="$1"
  python3 - "$pid" <<'PY'
import os
import subprocess
import sys

pid = sys.argv[1]
try:
    os.kill(int(pid), 0)
except OSError:
    raise SystemExit(1)

proc_root = f"/proc/{pid}"
if os.path.exists(proc_root):
    try:
        stat = open(f"{proc_root}/stat", "r", encoding="utf8", errors="replace").read()
        fields = stat[stat.rfind(")") + 2:].split()
        start_time = fields[19] if len(fields) > 19 else ""
    except OSError:
        start_time = ""
    try:
        exe = os.readlink(f"{proc_root}/exe")
    except OSError:
        exe = ""
    try:
        raw = open(f"{proc_root}/cmdline", "rb").read()
        command = raw.replace(b"\0", b" ").decode("utf8", "replace").strip()
    except OSError:
        command = ""
    print(f"linux|{pid}|{start_time}|{exe}|{command}")
    raise SystemExit(0)

try:
    out = subprocess.check_output(
        ["ps", "-ww", "-o", "lstart=", "-o", "command=", "-p", pid],
        text=True,
        stderr=subprocess.DEVNULL,
    ).strip()
except subprocess.CalledProcessError:
    raise SystemExit(1)
if not out:
    raise SystemExit(1)
print(f"ps|{pid}|{out}")
PY
}

require_same_process() {
  local pid="$1"
  local expected="$2"
  local phase="$3"
  local actual
  actual="$(process_fingerprint "$pid")" || die "target process ${pid} disappeared before ${phase}"
  [[ "$actual" == "$expected" ]] || die "target process ${pid} changed before ${phase}; refusing to signal a possibly reused pid"
}

require_btxd_like_process() {
  local pid="$1"
  if [[ "$BTX_UPDATER_TEST_ALLOW_NON_BTXD_PID" == "1" ]]; then
    return 0
  fi

  local cmd
  cmd="$(process_command "$pid")"
  case "$cmd" in
    *btxd*) return 0 ;;
  esac
  printf '[btx-updater] error: target pid %s does not look like a btxd process\n' "$pid" >&2
  return 1
}

append_unique_pid() {
  local candidate="$1"
  local existing
  pid_is_numeric "$candidate" || return 0
  kill -0 "$candidate" >/dev/null 2>&1 || return 0
  if ((${#BTX_PID_CANDIDATES[@]})); then
    for existing in "${BTX_PID_CANDIDATES[@]}"; do
      [[ "$existing" == "$candidate" ]] && return 0
    done
  fi
  BTX_PID_CANDIDATES+=("$candidate")
}

detect_running_btxd() {
  local requested_datadir="${1:-}"

  if [[ -n "$BTX_AUTOUPDATE_PID" && -n "$BTX_TARGET_PID" && "$BTX_AUTOUPDATE_PID" != "$BTX_TARGET_PID" ]]; then
    printf '[btx-updater] error: BTX_AUTOUPDATE_PID and BTX_TARGET_PID disagree\n' >&2
    return 2
  fi
  [[ -n "$BTX_TARGET_PID" ]] || BTX_TARGET_PID="$BTX_AUTOUPDATE_PID"

  if [[ -n "$BTX_AUTOUPDATE_DATADIR" && -n "$BTX_TARGET_DATADIR" ]] && ! paths_equal "$BTX_AUTOUPDATE_DATADIR" "$BTX_TARGET_DATADIR"; then
    printf '[btx-updater] error: BTX_AUTOUPDATE_DATADIR and BTX_TARGET_DATADIR disagree\n' >&2
    return 2
  fi
  [[ -n "$BTX_TARGET_DATADIR" ]] || BTX_TARGET_DATADIR="$BTX_AUTOUPDATE_DATADIR"
  [[ -n "$requested_datadir" ]] || requested_datadir="$BTX_TARGET_DATADIR"

  if [[ "$BTX_AUTOUPDATE" == "1" && -z "$BTX_TARGET_PID" ]]; then
    printf '[btx-updater] error: BTX_AUTOUPDATE=1 requires BTX_AUTOUPDATE_PID so the installer never guesses which node to stop\n' >&2
    return 2
  fi

  if [[ -n "$BTX_TARGET_PID" ]]; then
    pid_is_numeric "$BTX_TARGET_PID" || {
      printf '[btx-updater] error: target pid must be a positive numeric pid\n' >&2
      return 2
    }
    kill -0 "$BTX_TARGET_PID" >/dev/null 2>&1 || {
      printf '[btx-updater] error: target pid is not running: %s\n' "$BTX_TARGET_PID" >&2
      return 2
    }
    require_btxd_like_process "$BTX_TARGET_PID" || return 2
    printf '%s\n' "$BTX_TARGET_PID"
    return 0
  fi

  command -v pgrep >/dev/null 2>&1 || return 1

  local -a BTX_PID_CANDIDATES=()
  local pid
  while IFS= read -r pid; do
    append_unique_pid "$pid"
  done < <(pgrep -x btxd 2>/dev/null || true)
  while IFS= read -r pid; do
    append_unique_pid "$pid"
  done < <(pgrep -f '(^|/)btxd([[:space:]]|$)' 2>/dev/null || true)

  local -a filtered=()
  if [[ -n "$requested_datadir" ]]; then
    local runtime_datadir
    if ((${#BTX_PID_CANDIDATES[@]})); then
      for pid in "${BTX_PID_CANDIDATES[@]}"; do
        runtime_datadir=""
        while IFS='=' read -r key value; do
          if [[ "$key" == "DATADIR" ]]; then
            runtime_datadir="$value"
            break
          fi
        done < <(extract_runtime_flags "$pid" 2>/dev/null || true)
        [[ -n "$runtime_datadir" ]] || runtime_datadir="$(default_datadir)"
        if paths_equal "$requested_datadir" "$runtime_datadir"; then
          filtered+=("$pid")
        fi
      done
    fi
  else
    if ((${#BTX_PID_CANDIDATES[@]})); then
      filtered=("${BTX_PID_CANDIDATES[@]}")
    fi
  fi

  case "${#filtered[@]}" in
    0) return 1 ;;
    1)
      require_btxd_like_process "${filtered[0]}" || return 2
      printf '%s\n' "${filtered[0]}"
      return 0
      ;;
    *)
      printf '[btx-updater] error: multiple running btxd processes match; set BTX_TARGET_PID/BTX_AUTOUPDATE_PID explicitly\n' >&2
      for pid in "${filtered[@]}"; do
        printf '  pid=%s command=%s\n' "$pid" "$(process_command "$pid")" >&2
      done
      return 2
      ;;
  esac
}

validate_target_datadir_match() {
  local pid="$1"
  local configured_datadir="$2"
  local runtime_datadir="$3"

  [[ -n "$pid" ]] || return 0
  [[ -n "$configured_datadir" ]] || return 0
  [[ -n "$runtime_datadir" ]] || return 0
  paths_equal "$configured_datadir" "$runtime_datadir" || \
    die "target pid ${pid} runtime datadir (${runtime_datadir}) does not match requested datadir (${configured_datadir})"
}

validate_target_process_before_stop() {
  local pid="$1"
  local fingerprint="$2"
  local datadir="$3"
  local runtime_datadir="$4"

  [[ -n "$pid" ]] || return 0
  require_same_process "$pid" "$fingerprint" "node stop"
  validate_target_datadir_match "$pid" "$datadir" "$runtime_datadir"
}

extract_flag_value_from_lines() {
  local key="$1"
  awk -F= -v want="$key" '$1 == want {print substr($0, length($1) + 2); exit}'
}

extract_wallet_args_from_lines() {
  awk -F= '$1 == "WALLET" && length($0) > length($1) + 1 {print "-wallet=" substr($0, length($1) + 2)}'
}

read_runtime_flags() {
  local pid="$1"
  local target_file="$2"
  extract_runtime_flags "$pid" >"$target_file"
}

load_runtime_value() {
  local file_path="$1"
  local key="$2"
  [[ -f "$file_path" ]] || return 0
  extract_flag_value_from_lines "$key" <"$file_path"
}

load_runtime_wallet_args() {
  local file_path="$1"
  [[ -f "$file_path" ]] || return 0
  extract_wallet_args_from_lines <"$file_path"
}

target_note_pid() {
  local pid="$1"
  if [[ -n "$pid" ]]; then
    note "Target process: $pid"
  fi
}

extract_runtime_flags() {
  local pid="$1"
  python3 - "$pid" <<'PY'
import shlex
import subprocess
import sys

pid = sys.argv[1]
cmd = subprocess.check_output(["ps", "-ww", "-o", "command=", "-p", pid], text=True).strip()
tokens = shlex.split(cmd)

def take_flag(name):
    for i, token in enumerate(tokens):
        if token == name and i + 1 < len(tokens):
            return tokens[i + 1]
        if token.startswith(name + "="):
            return token.split("=", 1)[1]
    return ""

chain_flag = ""
for candidate in ("-testnet4", "-testnet", "-signet", "-regtest"):
    if candidate in tokens:
        chain_flag = candidate
        break

wallets = []
for i, token in enumerate(tokens):
    if token == "-wallet" and i + 1 < len(tokens):
        wallets.append(tokens[i + 1])
    elif token.startswith("-wallet="):
        wallets.append(token.split("=", 1)[1])

print(f"DATADIR={take_flag('-datadir')}")
print(f"CONF={take_flag('-conf')}")
print(f"WALLETDIR={take_flag('-walletdir')}")
print(f"BLOCKSDIR={take_flag('-blocksdir')}")
print(f"PIDFILE={take_flag('-pid')}")
print(f"RPCPORT={take_flag('-rpcport')}")
print(f"RPCCONNECT={take_flag('-rpcconnect')}")
print(f"RPCCOOKIEFILE={take_flag('-rpccookiefile')}")
print(f"RPCUSER={take_flag('-rpcuser')}")
print(f"RPCPASSWORD={take_flag('-rpcpassword')}")
print(f"CHAIN_FLAG={chain_flag}")
for wallet in wallets:
    print(f"WALLET={wallet}")
PY
}

ensure_retain_index_setting() {
  local conf_path="$1"
  local dir
  dir="$(dirname "$conf_path")"
  mkdir -p "$dir"

  if [[ ! -f "$conf_path" ]]; then
    touch "$conf_path"
  fi

  if grep -Eq '^[[:space:]]*retainshieldedcommitmentindex=' "$conf_path"; then
    return 0
  fi

  cat >>"$conf_path" <<'EOF'

# Added by contrib/autoupdate/install.sh to preserve shielded commitment index
# state across source rebuilds and restarts.
retainshieldedcommitmentindex=1
EOF
}

clone_or_refresh_repo() {
  local repo_url="$1"
  local cache_repo="$2"
  if [[ -d "$cache_repo/.git" ]]; then
    note "Refreshing cached source repository"
    git -C "$cache_repo" fetch --force --tags origin
    if git -C "$cache_repo" symbolic-ref -q HEAD >/dev/null 2>&1; then
      local current_branch
      current_branch="$(git -C "$cache_repo" symbolic-ref --short HEAD)"
      if git -C "$cache_repo" show-ref --verify --quiet "refs/remotes/origin/${current_branch}"; then
        git -C "$cache_repo" reset --hard "origin/${current_branch}" >/dev/null
      fi
    fi
  else
    note "Cloning source repository"
    rm -rf "$cache_repo"
    # Blobless partial clone: fetch all commit/tree metadata (so any ref/commit resolves) but defer
    # blob download until checkout. Cuts initial clone bandwidth/time substantially on a fleet of
    # nodes. Fall back to a full clone on older gits that lack --filter.
    if ! git clone --filter=blob:none "$repo_url" "$cache_repo" 2>/dev/null; then
      warn "partial clone unsupported by this git; falling back to a full clone"
      rm -rf "$cache_repo"
      git clone "$repo_url" "$cache_repo"
    fi
  fi
}

resolved_commit_for_ref() {
  local cache_repo="$1"
  local source_ref="$2"
  git -C "$cache_repo" rev-parse "$source_ref"
}

materialize_worktree() {
  local cache_repo="$1"
  local source_ref="$2"
  local worktree_path="$3"
  local resolved_commit="$4"

  # Reuse a persistent worktree already checked out at the target commit: leaving the source files
  # (and their mtimes) untouched lets the persistent build dir do a true incremental rebuild instead
  # of recompiling from scratch. Only re-checkout when the commit differs or the tree is missing.
  if [[ -e "$worktree_path/.git" ]]; then
    local have=""
    have="$(git -C "$worktree_path" rev-parse HEAD 2>/dev/null || true)"
    if [[ -n "$resolved_commit" && "$have" == "$resolved_commit" ]]; then
      note "Reusing build worktree already at $resolved_commit"
      return 0
    fi
    note "Updating build worktree to $source_ref"
    if git -C "$worktree_path" checkout --detach --force "${resolved_commit:-$source_ref}" >/dev/null 2>&1 \
       && git -C "$worktree_path" reset --hard "${resolved_commit:-$source_ref}" >/dev/null 2>&1; then
      git -C "$worktree_path" clean -fdq >/dev/null 2>&1 || true
      return 0
    fi
    warn "could not update existing worktree in place; recreating it"
    git -C "$cache_repo" worktree remove --force "$worktree_path" >/dev/null 2>&1 || true
    rm -rf "$worktree_path"
  fi
  git -C "$cache_repo" worktree add --force --detach "$worktree_path" "${resolved_commit:-$source_ref}" >/dev/null
}

build_btx() {
  local source_dir="$1"
  local build_dir="$2"
  local jobs="$3"
  local -a cache_args=()

  # Use ccache when present: object-cache by content hash, so rebuilds of the same commit (e.g. a
  # re-fired update, or a release that only bumps a few files) reuse compiled objects across runs
  # even when the worktree was re-checked-out and mtimes changed. Persist the cache under
  # BTX_CACHE_ROOT so it survives release-tree pruning.
  if [[ "${BTX_USE_CCACHE:-1}" == "1" ]] && command -v ccache >/dev/null 2>&1; then
    export CCACHE_DIR="${CCACHE_DIR:-$BTX_CACHE_ROOT/ccache}"
    mkdir -p "$CCACHE_DIR"
    cache_args+=(-DCMAKE_C_COMPILER_LAUNCHER=ccache -DCMAKE_CXX_COMPILER_LAUNCHER=ccache)
    note "Using ccache at $CCACHE_DIR"
  fi

  cmake -S "$source_dir" -B "$build_dir" \
    -DBUILD_TESTS=OFF \
    -DBUILD_GUI=OFF \
    -DBUILD_UTIL=ON \
    -DBUILD_DAEMON=ON \
    -DBUILD_CLI=ON \
    ${cache_args[@]+"${cache_args[@]}"}
  cmake --build "$build_dir" -j"$jobs"
}

check_binaries() {
  local bin_dir="$1"
  [[ -x "$bin_dir/btxd" ]] || { printf 'built btxd not found in %s\n' "$bin_dir"; return 1; }
  [[ -x "$bin_dir/btx-cli" ]] || { printf 'built btx-cli not found in %s\n' "$bin_dir"; return 1; }
  "$bin_dir/btxd" --version >/dev/null 2>&1 || { printf 'built btxd failed version check\n'; return 1; }
  "$bin_dir/btx-cli" --version >/dev/null 2>&1 || { printf 'built btx-cli failed version check\n'; return 1; }
}

verify_binaries() {
  local bin_dir="$1"
  local verify_error
  if ! verify_error="$(check_binaries "$bin_dir")"; then
    die "$verify_error"
  fi
}

release_tree_valid() {
  local release_dir="$1"
  [[ -x "$release_dir/bin/btxd" ]] || return 1
  [[ -x "$release_dir/bin/btx-cli" ]] || return 1
  [[ -f "$release_dir/manifest.json" ]] || return 1
}

swap_symlink() {
  local target_path="$1"
  local link_path="$2"
  mkdir -p "$(dirname "$link_path")"
  python3 - "$target_path" "$link_path" <<'PY'
import os
import sys

target, link = sys.argv[1], sys.argv[2]
tmp = f"{link}.tmp.{os.getpid()}"
try:
    os.unlink(tmp)
except FileNotFoundError:
    pass
os.symlink(target, tmp)
os.replace(tmp, link)
PY
}

install_release_tree() {
  local source_dir="$1"
  local bin_dir="$2"
  local version="$3"
  local release_dir="$4"
  local repo_url="$5"
  local source_ref="$6"
  mkdir -p "$release_dir/bin"

  cp "$bin_dir/btxd" "$release_dir/bin/btxd"
  cp "$bin_dir/btx-cli" "$release_dir/bin/btx-cli"
  if [[ -x "$bin_dir/btx-wallet" ]]; then
    cp "$bin_dir/btx-wallet" "$release_dir/bin/btx-wallet"
  fi
  # Ship btx-util so the next auto-update cycle can verify post-quantum release signatures
  # (btx-util verifyupdatesig) instead of falling back to classical openssl.
  if [[ -x "$bin_dir/btx-util" ]]; then
    cp "$bin_dir/btx-util" "$release_dir/bin/btx-util"
  fi

  cat >"$release_dir/manifest.json" <<EOF
{
  "version": "${version}",
  "repo_url": "${repo_url}",
  "source_ref": "${source_ref}",
  "git_commit": "$(git -C "$source_dir" rev-parse HEAD)",
  "installed_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
}
EOF
}

activate_release_tree() {
  local release_dir="$1"
  local target_root="$2"
  local link_dir="$3"

  mkdir -p "$target_root" "$link_dir"
  swap_symlink "$release_dir" "$target_root/current"
  swap_symlink "$target_root/current/bin/btxd" "$link_dir/btxd"
  swap_symlink "$target_root/current/bin/btx-cli" "$link_dir/btx-cli"
  if [[ -x "$target_root/current/bin/btx-wallet" ]]; then
    swap_symlink "$target_root/current/bin/btx-wallet" "$link_dir/btx-wallet"
  fi
  # Link btx-util too so the next update cycle can find the post-quantum verifier on PATH / in the
  # link dir on every platform (not just via Linux /proc).
  if [[ -x "$target_root/current/bin/btx-util" ]]; then
    swap_symlink "$target_root/current/bin/btx-util" "$link_dir/btx-util"
  fi
}

current_release_commit() {
  local target_root="$1"
  json_file_field "$target_root/current/manifest.json" "git_commit" ""
}

stop_running_node() {
  local cli_bin="$1"
  local pid="$2"
  local fingerprint="$3"
  local datadir="$4"
  local conf_path="$5"
  local walletdir="$6"
  local rpcport="$7"
  local rpcconnect="$8"
  local rpccookiefile="$9"
  local rpcuser="${10}"
  local rpcpassword="${11}"
  local -a cli_args

  cli_args=()
  [[ -n "$datadir" ]] && cli_args+=("-datadir=$datadir")
  [[ -n "$conf_path" ]] && cli_args+=("-conf=$conf_path")
  [[ -n "$walletdir" ]] && cli_args+=("-walletdir=$walletdir")
  [[ -n "$rpcport" ]] && cli_args+=("-rpcport=$rpcport")
  [[ -n "$rpcconnect" ]] && cli_args+=("-rpcconnect=$rpcconnect")
  [[ -n "$rpccookiefile" ]] && cli_args+=("-rpccookiefile=$rpccookiefile")
  [[ -n "$rpcuser" ]] && cli_args+=("-rpcuser=$rpcuser")
  [[ -n "$rpcpassword" ]] && cli_args+=("-rpcpassword=$rpcpassword")

  note "Stopping running BTX node (pid $pid)"
  require_same_process "$pid" "$fingerprint" "RPC stop"
  if ! "$cli_bin" ${cli_args[@]+"${cli_args[@]}"} stop >/dev/null 2>&1; then
    warn "RPC stop failed, sending TERM to pid $pid"
    require_same_process "$pid" "$fingerprint" "TERM fallback"
    kill "$pid" >/dev/null 2>&1 || true
  fi

  local deadline=$((SECONDS + BTX_STOP_TIMEOUT_SECONDS))
  while kill -0 "$pid" >/dev/null 2>&1; do
    if process_is_zombie "$pid"; then
      break
    fi
    if (( SECONDS >= deadline )); then
      warn "Node did not stop in time, sending KILL"
      require_same_process "$pid" "$fingerprint" "KILL fallback"
      kill -9 "$pid" >/dev/null 2>&1 || true
      break
    fi
    sleep 1
  done
}

restart_node() {
  local daemon_bin="$1"
  local datadir="$2"
  local conf_path="$3"
  local walletdir="$4"
  local chain_flag="$5"
  local blocksdir="$6"
  local pidfile="$7"
  local log_dir="$8"
  local -a args

  shift 8
  args=()
  [[ -n "$chain_flag" ]] && args+=("$chain_flag")
  [[ -n "$datadir" ]] && args+=("-datadir=$datadir")
  [[ -n "$conf_path" ]] && args+=("-conf=$conf_path")
  [[ -n "$walletdir" ]] && args+=("-walletdir=$walletdir")
  [[ -n "$blocksdir" ]] && args+=("-blocksdir=$blocksdir")
  [[ -n "$pidfile" ]] && args+=("-pid=$pidfile")
  if (( $# > 0 )); then
    args+=("$@")
  fi

  mkdir -p "$log_dir"
  note "Restarting BTX node with preserved data directory"
  nohup "$daemon_bin" ${args[@]+"${args[@]}"} >>"$log_dir/restart.log" 2>&1 &
  local restarted_pid=$!
  sleep 3
  if ! kill -0 "$restarted_pid" >/dev/null 2>&1; then
    die "updated btxd exited immediately after restart; inspect $log_dir/restart.log"
  fi
}

# Confirm a (re)started node is genuinely healthy (RPC reachable), not just briefly alive then
# crash-looping. Returns 0 if the node answers an RPC within BTX_HEALTH_TIMEOUT_SECONDS, else 1.
health_probe() {
  local cli="$1" datadir="$2" conf="$3" chain_flag="$4"
  shift 4
  local -a a=()
  [[ -n "$chain_flag" ]] && a+=("$chain_flag")
  [[ -n "$datadir" ]] && a+=("-datadir=$datadir")
  [[ -n "$conf" ]] && a+=("-conf=$conf")
  if (( $# > 0 )); then a+=("$@"); fi
  local timeout="${BTX_HEALTH_TIMEOUT_SECONDS:-60}"
  "$cli" ${a[@]+"${a[@]}"} -rpcwait -rpcwaittimeout="$timeout" uptime >/dev/null 2>&1
}

# Re-activate and restart the previous release after a failed update, so a bad build/commit cannot
# leave the fleet down. Best-effort: logs and dies with a clear message either way.
rollback_release() {
  local previous_current="$1" datadir="$2" conf_path="$3" walletdir="$4" chain_flag="$5"
  local blocksdir="$6" pidfile="$7" failed_label="$8"
  shift 8
  if [[ -z "$previous_current" || ! -d "$previous_current" ]]; then
    die "updated node failed its health probe and there is no previous release to roll back to ($failed_label)"
  fi
  warn "updated node ($failed_label) failed its health probe; rolling back to $previous_current"
  status_event "rollback" "begin" "from $failed_label to $(basename "$previous_current")"
  activate_release_tree "$previous_current" "$BTX_INSTALL_ROOT" "$BTX_LINK_DIR"
  restart_node "$BTX_LINK_DIR/btxd" "$datadir" "$conf_path" "$walletdir" "$chain_flag" "$blocksdir" "$pidfile" "$BTX_INSTALL_ROOT/logs" "$@"
  if ! health_probe "$BTX_LINK_DIR/btx-cli" "$datadir" "$conf_path" "$chain_flag"; then
    die "rollback restart of the previous release also failed its health probe; manual intervention required"
  fi
  die "update to ${failed_label} failed its health probe and was rolled back to the previous release"
}

main() {
  validate_home_roots
  stage "preflight"
  require_cmd curl
  require_cmd git
  require_cmd cmake
  require_cmd openssl
  require_cmd python3

  if ! command -v c++ >/dev/null 2>&1 && ! command -v clang++ >/dev/null 2>&1 && ! command -v g++ >/dev/null 2>&1; then
    die "missing C++ compiler (install Xcode Command Line Tools or build-essential)"
  fi

  BTX_TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/btx-updater.XXXXXX")"

  local manifest_path="$BTX_TMPDIR/version.txt"
  local manifest_sig_path="$BTX_TMPDIR/version.txt.sig"
  local release_pub_path
  release_pub_path="$(resolve_release_pub_path)"
  stage "verify-manifest"
  fetch_verified_manifest "$BTX_MANIFEST_URL" "$manifest_path" "$manifest_sig_path" "$release_pub_path"

  local manifest_json
  manifest_json="$(cat "$manifest_path")"
  local version repo_url script_url release_tag git_ref source_ref expected_commit expected_commit_sig_url

  version="$(printf '%s' "$manifest_json" | json_field version)"
  repo_url="$(printf '%s' "$manifest_json" | json_field repo_url)"
  script_url="$(printf '%s' "$manifest_json" | json_field script_url)"
  release_tag="$(printf '%s' "$manifest_json" | json_field release_tag)"
  git_ref="$(printf '%s' "$manifest_json" | json_field git_ref)"
  expected_commit="$(printf '%s' "$manifest_json" | json_field git_commit)"
  expected_commit_sig_url="$(printf '%s' "$manifest_json" | json_field git_commit_sig_url)"

  [[ -n "$BTX_VERSION" ]] && version="$BTX_VERSION"
  [[ -n "$BTX_REPO_URL" ]] && repo_url="$BTX_REPO_URL"
  [[ -n "$BTX_RELEASE_TAG" ]] && release_tag="$BTX_RELEASE_TAG"

  [[ -n "$version" ]] || die "manifest did not contain a version"
  [[ -n "$repo_url" ]] || die "manifest did not contain repo_url"
  [[ -n "$script_url" ]] || die "manifest did not contain script_url"
  BTX_STATUS_VERSION="$version"

  source_ref="${BTX_GIT_REF:-}"
  if [[ -z "$source_ref" && -n "$release_tag" ]] && ref_exists_remote "$repo_url" "$release_tag"; then
    source_ref="$release_tag"
  fi
  if [[ -z "$source_ref" && -n "$git_ref" && "$BTX_ALLOW_GIT_REF_FALLBACK" == "1" ]]; then
    if branch_exists_remote "$repo_url" "$git_ref"; then
      source_ref="origin/$git_ref"
    else
      source_ref="$git_ref"
    fi
  fi
  if [[ -z "$source_ref" ]] && ref_exists_remote "$repo_url" "v$version"; then
    source_ref="v$version"
  fi
  [[ -n "$source_ref" ]] || die "unable to resolve a git ref for version $version"

  local jobs
  jobs="$(default_jobs)"

  [[ -n "$BTX_TARGET_DATADIR" ]] || BTX_TARGET_DATADIR="$BTX_AUTOUPDATE_DATADIR"

  local detected_pid="" datadir="$BTX_TARGET_DATADIR" conf_path="$BTX_TARGET_CONF" walletdir="$BTX_TARGET_WALLETDIR" blocksdir="$BTX_TARGET_BLOCKSDIR" pidfile="$BTX_TARGET_PIDFILE" chain_flag="$BTX_TARGET_CHAIN_FLAG"
  local runtime_flags_file="$BTX_TMPDIR/runtime-flags.env"
  local runtime_datadir="" target_fingerprint="" rpcport="" rpcconnect="" rpccookiefile="" rpcuser="" rpcpassword=""
  local -a wallet_args=()
  local detect_status=0
  set +e
  detected_pid="$(detect_running_btxd "$datadir")"
  detect_status=$?
  set -e
  if (( detect_status == 2 )); then
    die "unable to select the running BTX node safely"
  elif (( detect_status != 0 && detect_status != 1 )); then
    die "unexpected process-detection failure (${detect_status})"
  fi

  if [[ -n "$detected_pid" ]]; then
    target_fingerprint="$(process_fingerprint "$detected_pid")" || die "unable to fingerprint target pid ${detected_pid}"
    read_runtime_flags "$detected_pid" "$runtime_flags_file"
    runtime_datadir="$(load_runtime_value "$runtime_flags_file" DATADIR)"
    [[ -n "$conf_path" ]] || conf_path="$(load_runtime_value "$runtime_flags_file" CONF)"
    [[ -n "$walletdir" ]] || walletdir="$(load_runtime_value "$runtime_flags_file" WALLETDIR)"
    [[ -n "$blocksdir" ]] || blocksdir="$(load_runtime_value "$runtime_flags_file" BLOCKSDIR)"
    [[ -n "$pidfile" ]] || pidfile="$(load_runtime_value "$runtime_flags_file" PIDFILE)"
    [[ -n "$chain_flag" ]] || chain_flag="$(load_runtime_value "$runtime_flags_file" CHAIN_FLAG)"
    rpcport="$(load_runtime_value "$runtime_flags_file" RPCPORT)"
    rpcconnect="$(load_runtime_value "$runtime_flags_file" RPCCONNECT)"
    rpccookiefile="$(load_runtime_value "$runtime_flags_file" RPCCOOKIEFILE)"
    rpcuser="$(load_runtime_value "$runtime_flags_file" RPCUSER)"
    rpcpassword="$(load_runtime_value "$runtime_flags_file" RPCPASSWORD)"
    while IFS= read -r wallet_arg; do
      [[ -n "$wallet_arg" ]] && wallet_args+=("$wallet_arg")
    done < <(load_runtime_wallet_args "$runtime_flags_file")
  fi

  [[ -n "$datadir" ]] || datadir="$runtime_datadir"
  [[ -n "$datadir" ]] || datadir="$(default_datadir)"
  validate_target_datadir_match "$detected_pid" "$datadir" "$runtime_datadir"
  [[ -n "$conf_path" ]] || conf_path="$(default_conf_path "$datadir")"

  mkdir -p "$BTX_INSTALL_ROOT" "$BTX_CACHE_ROOT"

  local cache_repo="$BTX_CACHE_ROOT/source"
  local worktree_root="$BTX_CACHE_ROOT/worktrees"
  local build_root="$BTX_CACHE_ROOT/build"
  local release_root="$BTX_INSTALL_ROOT/releases"

  BTX_CLEANUP_CACHE_REPO="$cache_repo"
  trap cleanup_worktree EXIT

  # Serialize updater runs for this install root, and refuse to start a build we cannot finish for
  # lack of disk -- both checks happen BEFORE the running node is ever stopped.
  acquire_lock
  require_free_space "$BTX_INSTALL_ROOT"

  local resolved_commit="" resolved_short_sha="" release_dir="" current_commit="" prepared_bin_dir=""
  local cache_key="" worktree_path="" build_dir="" used_prebuilt=0

  # Fast path: a signed prebuilt binary matching this platform, pinned to the signed manifest commit.
  # Skips the clone + source build entirely. Trust is anchored by the SAME release-signature scheme
  # as the manifest (PQ via btx-util, classical via openssl). Falls through to a source build if no
  # usable prebuilt is found/verified. Disable with BTX_PREFER_PREBUILT=0.
  if [[ "${BTX_PREFER_PREBUILT:-1}" == "1" && -n "$expected_commit" ]] && manifest_has_prebuilt "$manifest_path"; then
    resolved_commit="$expected_commit"
    resolved_short_sha="${expected_commit:0:12}"
    release_dir="$release_root/${version}-${resolved_short_sha}"
    current_commit="$(current_release_commit "$BTX_INSTALL_ROOT")"
    BTX_STATUS_COMMIT="$resolved_commit"
    mkdir -p "$release_root"

    bold "BTX prebuilt updater"
    note "Version: $version"
    note "Pinned commit: $resolved_commit"
    note "Data directory: $datadir"
    target_note_pid "$detected_pid"

    if release_tree_valid "$release_dir"; then
      stage "reuse-release"
      note "Reusing existing installed release tree at $release_dir"
      prepared_bin_dir="$release_dir/bin"
      verify_binaries "$prepared_bin_dir"
      used_prebuilt=1
    else
      stage "prebuilt"
      if try_install_prebuilt "$manifest_path" "$version" "$release_dir" "$expected_commit" "$release_pub_path"; then
        prepared_bin_dir="$release_dir/bin"
        used_prebuilt=1
      else
        note "No usable signed prebuilt for this platform; falling back to a source build"
      fi
    fi
  fi

  if [[ "$used_prebuilt" != "1" ]]; then
    stage "fetch-source"
    clone_or_refresh_repo "$repo_url" "$cache_repo"
    resolved_commit="$(resolved_commit_for_ref "$cache_repo" "$source_ref")"
    resolved_short_sha="$(git -C "$cache_repo" rev-parse --short "$resolved_commit")"
    release_dir="$release_root/${version}-${resolved_short_sha}"
    current_commit="$(current_release_commit "$BTX_INSTALL_ROOT")"
    prepared_bin_dir=""
    BTX_STATUS_COMMIT="$resolved_commit"

    # Persistent, content-keyed worktree + build dir so re-firing the same release reuses the checkout
    # and compiled objects (with ccache as a second layer). Keyed by version+sha so different commits
    # never share a build dir; old ones are pruned by retention after a successful run.
    cache_key="${version}-${resolved_short_sha}"
    worktree_path="$worktree_root/${cache_key}"
    build_dir="$build_root/${cache_key}"

    bold "BTX source updater"
    note "Manifest: $BTX_MANIFEST_URL"
    note "Version: $version"
    note "Source repo: $repo_url"
    note "Selected ref: $source_ref"
    note "Resolved commit: $resolved_commit"
    note "Script URL: $script_url"
    note "Data directory: $datadir"
    target_note_pid "$detected_pid"

    if [[ -n "$expected_commit" ]]; then
      [[ "$resolved_commit" == "$expected_commit" ]] || die "resolved commit ${resolved_commit} does not match signed manifest commit ${expected_commit}"
    fi

    if [[ -n "$expected_commit_sig_url" ]]; then
      [[ -n "$expected_commit" ]] || die "git_commit_sig_url was provided without git_commit"
      require_trusted_url "$expected_commit_sig_url" "git_commit_sig_url"
      local expected_commit_path="$BTX_TMPDIR/git-commit.txt"
      local expected_commit_sig_path="$BTX_TMPDIR/git-commit.txt.sig"
      printf '%s\n' "$expected_commit" >"$expected_commit_path"
      curl -fsSL "$expected_commit_sig_url" -o "$expected_commit_sig_path"
      verify_detached_signature "$expected_commit_path" "$expected_commit_sig_path" "$release_pub_path"
    fi

    if release_tree_valid "$release_dir"; then
      stage "reuse-release"
      note "Reusing existing installed release tree at $release_dir"
      prepared_bin_dir="$release_dir/bin"
      verify_binaries "$prepared_bin_dir"
    else
      stage "build"
      mkdir -p "$worktree_root" "$build_root" "$release_root"
      materialize_worktree "$cache_repo" "$source_ref" "$worktree_path" "$resolved_commit"
      build_btx "$worktree_path" "$build_dir" "$jobs"
      stage "verify-binaries"
      verify_binaries "$build_dir/bin"
      install_release_tree "$worktree_path" "$build_dir/bin" "$version" "$release_dir" "$repo_url" "$source_ref"
      prepared_bin_dir="$build_dir/bin"
    fi
  fi

  if [[ "$BTX_ENSURE_RETAIN_INDEX" == "1" ]]; then
    ensure_retain_index_setting "$conf_path"
  fi

  if [[ "$current_commit" == "$resolved_commit" && -n "$detected_pid" ]]; then
    activate_release_tree "$release_dir" "$BTX_INSTALL_ROOT" "$BTX_LINK_DIR"
    status_event "complete" "already-current"
    note "Requested version is already active; skipping rebuild and restart"
    note "Update complete"
    note "Active btxd: $BTX_LINK_DIR/btxd"
    note "Active btx-cli: $BTX_LINK_DIR/btx-cli"
    note "Current release root: $BTX_INSTALL_ROOT/current"
    return 0
  fi

  # Remember the release the running node was using, so a failed update can be rolled back to it.
  local previous_current=""
  previous_current="$(readlink "$BTX_INSTALL_ROOT/current" 2>/dev/null || true)"

  if [[ -n "$detected_pid" ]]; then
    stage "stop-node"
    validate_target_process_before_stop "$detected_pid" "$target_fingerprint" "$datadir" "$runtime_datadir"
    stop_running_node "$prepared_bin_dir/btx-cli" "$detected_pid" "$target_fingerprint" "$datadir" "$conf_path" "$walletdir" "$rpcport" "$rpcconnect" "$rpccookiefile" "$rpcuser" "$rpcpassword"
  fi

  stage "activate"
  activate_release_tree "$release_dir" "$BTX_INSTALL_ROOT" "$BTX_LINK_DIR"

  if [[ -n "$detected_pid" && "$BTX_AUTO_RESTART" == "1" ]]; then
    stage "restart"
    restart_node "$BTX_LINK_DIR/btxd" "$datadir" "$conf_path" "$walletdir" "$chain_flag" "$blocksdir" "$pidfile" "$BTX_INSTALL_ROOT/logs" ${wallet_args[@]+"${wallet_args[@]}"}
    # The node was running before; verify the new binary is actually healthy (RPC reachable) and
    # roll back to the previous release if it crash-loops, so a bad release cannot down the fleet.
    if [[ "${BTX_HEALTH_PROBE:-1}" == "1" ]]; then
      stage "health-probe"
      if ! health_probe "$BTX_LINK_DIR/btx-cli" "$datadir" "$conf_path" "$chain_flag"; then
        rollback_release "$previous_current" "$datadir" "$conf_path" "$walletdir" "$chain_flag" "$blocksdir" "$pidfile" "${version}-${resolved_short_sha}" ${wallet_args[@]+"${wallet_args[@]}"}
      fi
      status_event "health-probe" "healthy"
    fi
  elif [[ -z "$detected_pid" && "$BTX_START_IF_STOPPED" == "1" ]]; then
    restart_node "$BTX_LINK_DIR/btxd" "$datadir" "$conf_path" "$walletdir" "$chain_flag" "$blocksdir" "$pidfile" "$BTX_INSTALL_ROOT/logs" ${wallet_args[@]+"${wallet_args[@]}"}
  else
    note "No running BTX node needed a restart"
  fi

  # Bound disk use across many updates: keep current + the most recent N release trees, and the most
  # recent N build worktrees/dirs (preserving the one we just used for fast incremental rebuilds).
  prune_old_releases "$release_root"
  prune_build_cache "$cache_repo" "$worktree_root" "$build_root" "$cache_key"

  status_event "complete" "ok"
  note "Update complete"
  note "Active btxd: $BTX_LINK_DIR/btxd"
  note "Active btx-cli: $BTX_LINK_DIR/btx-cli"
  note "Current release root: $BTX_INSTALL_ROOT/current"
}

main "$@"

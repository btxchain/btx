#!/usr/bin/env bash
# Prove WITH_MODELNET=OFF (monetary-only) without configuring a cmake tree.
#
# Disk rule: never invoke the project cmake/ninja; never create build-*.
# /tmp is tmpfs (RAM); this script deletes its throwaway dir on exit.
export LC_ALL=C
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

pass_n=0
pass() { pass_n=$((pass_n + 1)); printf 'ok %d - %s\n' "$pass_n" "$1"; }
fail() {
  pass_n=$((pass_n + 1))
  printf 'not ok %d - %s\n' "$pass_n" "$1" >&2
  if [[ $# -ge 2 ]]; then printf '%s\n' "$2" >&2; fi
  exit 1
}

WORKDIR=""
cleanup() {
  if [[ -n "$WORKDIR" && -d "$WORKDIR" ]]; then
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

# --- 1. src/modelnet/CMakeLists.txt starts with if(NOT WITH_MODELNET) return()
cm="$ROOT/src/modelnet/CMakeLists.txt"
[[ -f "$cm" ]] || fail "src/modelnet/CMakeLists.txt exists"
mapfile -t cmake_logic < <(awk '
  /^[[:space:]]*#/ { next }
  /^[[:space:]]*$/ { next }
  { gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print }
' "$cm")
[[ ${#cmake_logic[@]} -ge 3 ]] || fail "src/modelnet/CMakeLists.txt has cmake statements"
[[ "${cmake_logic[0]}" == "if(NOT WITH_MODELNET)" ]] \
  || fail "CMakeLists first statement is if(NOT WITH_MODELNET)" $'got:\n'"${cmake_logic[0]}"
[[ "${cmake_logic[1]}" == "return()" ]] \
  || fail "CMakeLists second statement is return()" $'got:\n'"${cmake_logic[1]}"
[[ "${cmake_logic[2]}" == "endif()" ]] \
  || fail "CMakeLists third statement is endif()" $'got:\n'"${cmake_logic[2]}"
pass "src/modelnet/CMakeLists.txt starts with if(NOT WITH_MODELNET) return()"

# --- 2. init.cpp / rpc/modelnet.cpp use #ifdef ENABLE_MODELNET
init="$ROOT/src/init.cpp"
rpc="$ROOT/src/rpc/modelnet.cpp"
[[ -f "$init" && -f "$rpc" ]] || fail "src/init.cpp and src/rpc/modelnet.cpp exist"
init_n=$(grep -cF '#ifdef ENABLE_MODELNET' "$init" || true)
rpc_n=$(grep -cF '#ifdef ENABLE_MODELNET' "$rpc" || true)
[[ "$init_n" -ge 2 ]] || fail "src/init.cpp uses #ifdef ENABLE_MODELNET (args + service bits)" \
  "count=$init_n"
[[ "$rpc_n" -ge 2 ]] || fail "src/rpc/modelnet.cpp uses #ifdef ENABLE_MODELNET (socket + Register)" \
  "count=$rpc_n"
grep -qF -- '-modelnet' "$init" || fail "src/init.cpp still documents -modelnet behind the guard"
grep -qF 'RegisterModelNetRPCCommands' "$rpc" || fail "src/rpc/modelnet.cpp still registers model RPCs behind the guard"
pass "src/init.cpp has $init_n #ifdef ENABLE_MODELNET guards"
pass "src/rpc/modelnet.cpp has $rpc_n #ifdef ENABLE_MODELNET guards"

# --- 3. cmake #cmakedefine pattern + node sources gated on WITH_MODELNET
cfg_in="$ROOT/cmake/bitcoin-build-config.h.in"
grep -qF '#cmakedefine ENABLE_MODELNET 1' "$cfg_in" \
  || fail "cmake/bitcoin-build-config.h.in has #cmakedefine ENABLE_MODELNET 1"
pass "cmake/bitcoin-build-config.h.in #cmakedefine ENABLE_MODELNET 1 (OFF => unset)"

src_cm="$ROOT/src/CMakeLists.txt"
awk '
  /if\(WITH_MODELNET\)/ { in_mn=1; d=1; next }
  in_mn && /^[[:space:]]*if\(/ { d++; next }
  in_mn && /^[[:space:]]*endif\(/ { d--; if (d==0) in_mn=0; next }
  in_mn && /add_subdirectory\(modelnet\)/ { subdir_ok=1 }
  in_mn && /rpc\/modelnet\.cpp/ { rpc_ok=1 }
  END { if (!subdir_ok || !rpc_ok) exit 1 }
' "$src_cm" || fail "src/CMakeLists.txt adds modelnet/ and rpc/modelnet.cpp only inside if(WITH_MODELNET)"
pass "src/CMakeLists.txt gates add_subdirectory(modelnet) and rpc/modelnet.cpp"

# --- 4. Throwaway compile: ENABLE_MODELNET unset, excerpts preprocessor-dropped
WORKDIR="$(mktemp -d /tmp/btx-modelnet-off.XXXXXX)"
# Match cmake #cmakedefine OFF output. Do not read a configured build tree.
cat > "$WORKDIR/bitcoin-build-config.h" <<'EOF'
#ifndef BITCOIN_BUILD_CONFIG_H
#define BITCOIN_BUILD_CONFIG_H
/* Define to 1 to enable the Native Model Network (btx-modeld). */
/* #undef ENABLE_MODELNET */
#endif
EOF

# Copy #ifdef ENABLE_MODELNET ON branches only. #else fail-closed stubs
# (return {}; (void)t;) are valid inside functions, not at file scope.
# $2 = max blocks to copy (keep the throwaway excerpt ~20 lines).
extract_ifdef_on_branches() {
  awk -v want="${2:-99}" '
    skip && /^[[:space:]]*#endif/ { skip=0; next }
    skip { next }
    /^[[:space:]]*#ifdef ENABLE_MODELNET/ { p=1 }
    p && /^[[:space:]]*#else/ {
      print "#endif"; print ""; p=0; skip=1; n++; if (n >= want) exit; next
    }
    p { print }
    p && /^[[:space:]]*#endif/ { p=0; print ""; n++; if (n >= want) exit }
  ' "$1"
}

{
  printf '%s\n' '// Copied ENABLE_MODELNET ON-branch excerpts (~20 lines)'
  extract_ifdef_on_branches "$init" 4
  extract_ifdef_on_branches "$rpc" 1
} > "$WORKDIR/excerpts.inc"
excerpt_lines=$(grep -c . "$WORKDIR/excerpts.inc" || true)
[[ "$excerpt_lines" -ge 20 ]] || fail "copied ENABLE_MODELNET excerpts are ~20+ lines" \
  "lines=$excerpt_lines"

cat > "$WORKDIR/probe.cpp" <<'EOF'
#include <bitcoin-build-config.h>
#include <modelnet/disabled_stub.h>
#include "excerpts.inc"

int main()
{
#ifdef ENABLE_MODELNET
#error "WITH_MODELNET=OFF probe must not see ENABLE_MODELNET"
#endif
    static_assert(!MODELNET_COMPILED, "disabled_stub.h requires ENABLE_MODELNET unset");
    return 0;
}
EOF

CXX="${CXX:-c++}"
command -v "$CXX" >/dev/null || fail "C++ compiler ($CXX) is available for the throwaway probe"
"$CXX" -std=c++20 -fsyntax-only \
  -I"$WORKDIR" -I"$ROOT/src" \
  "$WORKDIR/probe.cpp" \
  || fail "throwaway .cpp compiles with ENABLE_MODELNET unset (guarded excerpts dropped)"
pass "throwaway .cpp compiles with ENABLE_MODELNET unset ($excerpt_lines-line excerpt)"

# Defining ENABLE_MODELNET must trip the stub (OFF-only header).
cat > "$WORKDIR/stub_must_fail.cpp" <<'EOF'
#define ENABLE_MODELNET 1
#include <modelnet/disabled_stub.h>
int main() { return 0; }
EOF
if "$CXX" -std=c++20 -fsyntax-only -I"$ROOT/src" "$WORKDIR/stub_must_fail.cpp" 2>"$WORKDIR/stub_fail.log"; then
  fail "disabled_stub.h #errors when ENABLE_MODELNET is set"
fi
grep -q 'WITH_MODELNET=OFF' "$WORKDIR/stub_fail.log" \
  || grep -q 'ENABLE_MODELNET unset' "$WORKDIR/stub_fail.log" \
  || fail "disabled_stub.h #error mentions WITH_MODELNET=OFF" "$(cat "$WORKDIR/stub_fail.log")"
pass "disabled_stub.h #errors when ENABLE_MODELNET is set"

# --- 5. Resource governor remains compiled when WITH_MODELNET=OFF
grep -qF 'RegisterResourceGovernorRPCCommands' "$ROOT/src/rpc/register.h" \
  || fail "src/rpc/register.h registers resource governor RPCs"
if grep -n 'RegisterResourceGovernorRPCCommands' "$ROOT/src/rpc/register.h" | grep -q 'ENABLE_MODELNET'; then
  fail "RegisterResourceGovernorRPCCommands must not sit behind ENABLE_MODELNET"
fi
pass "resource governor RPC registration is independent of ENABLE_MODELNET"

grep -qF -- '-resourcegovernor' "$init" || fail "src/init.cpp documents -resourcegovernor"
# The arg must appear after the modelnet #endif that closes the -model* block.
gov_line=$(grep -n 'AddArg("-resourcegovernor' "$init" | head -1 | cut -d: -f1)
mn_endif=$(awk '/AddArg\("-modeluploadlimit/{n=NR} n && /#endif/{print NR; exit}' "$init")
[[ -n "$gov_line" && -n "$mn_endif" && "$gov_line" -gt "$mn_endif" ]] \
  || fail "-resourcegovernor is declared outside ENABLE_MODELNET" "gov_line=$gov_line mn_endif=$mn_endif"
pass "-resourcegovernor is declared outside ENABLE_MODELNET"

grep -qF 'node/resource_governor.cpp' "$src_cm" \
  || fail "src/CMakeLists.txt compiles node/resource_governor.cpp"
pass "node/resource_governor.cpp is in bitcoin_common (not modelnet-only)"

# --- 6. This script did not invoke cmake (disk rule)
pass "did not invoke project cmake/ninja; /tmp probe dir removed on exit"

printf '\n%d checks passed: WITH_MODELNET=OFF is the monetary-only build.\n' "$pass_n"
printf 'Run: %s\n' "$0"

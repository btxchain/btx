#!/usr/bin/env bash
# Fail-fast in-tree 0.34.7 model-hosting suite. First failing command exits.
# Does not start granite, does not touch production btxd, does not cmake.
#
# Usage (coordinator, after build-gcc13):
#   contrib/modelnet/e2e-all.sh
export LC_ALL=C
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
die() { printf 'E2E_ALL FAIL: %s\n' "$*" >&2; exit 1; }
step() { printf '\n== %s ==\n' "$*"; }
# Inherited BIN may be a binary (btx-hcpd). Only honor a directory that contains btxd.
if [[ -n "${BIN:-}" && -d "${BIN}" && -x "${BIN}/btxd" ]]; then
  :
elif [[ -n "${BIN_DIR:-}" && -d "${BIN_DIR}" && -x "${BIN_DIR}/btxd" ]]; then
  BIN="$BIN_DIR"
else
  BIN="$ROOT/build-gcc13/bin"
fi
export MODELD="${MODELD:-$BIN/btx-modeld}"

[[ -x "$BIN/btxd" ]] || die "missing $BIN/btxd"
[[ -x "$BIN/btx-cli" ]] || die "missing $BIN/btx-cli"
[[ -x "$BIN/btx-modeld" ]] || die "missing $BIN/btx-modeld"
[[ -x "$BIN/test_btx" ]] || die "missing $BIN/test_btx"

step "1/12 modelnet unit tests"
"$BIN/test_btx" --run_test=modelnet_* || die "test_btx modelnet_*"

step "2/12 reference codecs"
( cd "$ROOT/contrib/modelnet/reference" && python3 -m unittest -v test_v11 ) || die "reference unittest"

step "3/12 DOC examples"
BIN_DIR="$BIN" "$ROOT/contrib/modelnet/validate-doc-examples.sh" || die "validate-doc-examples"

step "4/12 two-helper loopback (no seedmodel)"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-two-helper-pq1.sh" || die "e2e-two-helper-pq1"

step "5/12 local helper"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-local-helper.sh" || die "e2e-local-helper"

step "6/12 resolve 8/4"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-resolve-8-4.sh" || die "e2e-resolve-8-4"

step "7/12 NAT congested + resume"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-nat-congested.sh" || die "e2e-nat-congested"

step "8/12 DISC-04/05 introducer death failover"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-disc-failure.sh" || die "e2e-disc-failure"

step "9/12 §12.3 32 MiB bench"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-bench-12-3.sh" || die "e2e-bench-12-3"

step "10/12 OpenSSL 3.5.8 second-process"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-openssl-358.sh" || die "e2e-openssl-358"

step "11/12 TLS max_send_fragment=512"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-tls-fragment.sh" || die "e2e-tls-fragment"

step "12/12 GUI URI source + OS handler"
"$ROOT/contrib/modelnet/e2e-gui-uri.sh" || die "e2e-gui-uri"

step "13/16 default peer-follow (no getmodel)"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-peer-follow.sh" || die "e2e-peer-follow"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-preserve-rare.sh" || die "e2e-preserve-rare"

step "14/16 default hosting START-01..03"
BIN="$BIN" "$ROOT/contrib/modelnet/e2e-hosting-default.sh" || die "e2e-hosting-default"

step "14/15 helper lifecycle START-06/08/09/14/15"
BIN="$BIN" "$ROOT/contrib/modelnet/e2e-hosting-lifecycle.sh" || die "e2e-hosting-lifecycle"

step "15/15 disjoint piece reconstruct"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-shard-disjoint.sh" || die "e2e-shard-disjoint"

step "16/17 swarm three-peer RPC"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-swarm-three-peer.sh" || die "e2e-swarm-three-peer"

step "17/17 connectivity lab (loopback + IPv6; netns optional)"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-connectivity-lab.sh" || die "e2e-connectivity-lab"

step "search directory"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-search-directory.sh" || die "e2e-search-directory"

step "search live PQ1 fanout + slow-peer timeout"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-search-net.sh" || die "e2e-search-net"

step "search release campaign RPC"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-search-release.sh" || die "e2e-search-release"

step "search chaos"
BTX_SEARCH_CHAOS=1 MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-search-chaos.sh" || die "e2e-search-chaos"

step "combined swarm+connectivity 20-step"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-combined-20.sh" || die "e2e-combined-20"

step "governor concurrent retrieve"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-gov-retrieve.sh" || die "e2e-gov-retrieve"

step "WITH_MODELNET=OFF + governor"
"$ROOT/contrib/modelnet/check-with-modelnet-off.sh" || die "check-with-modelnet-off"

step "CONN-NAT-01 PCP/NAT-PMP mapped"
MODELD="$MODELD" TEST_BTX="$BIN/test_btx" "$ROOT/contrib/modelnet/e2e-conn-nat-pcp.sh" || die "e2e-conn-nat-pcp"

step "governor NVIDIA / Apple / timeline"
TEST_BTX="$BIN/test_btx" "$ROOT/contrib/modelnet/e2e-governor-nvidia.sh" || die "e2e-governor-nvidia"
TEST_BTX="$BIN/test_btx" "$ROOT/contrib/modelnet/e2e-governor-apple.sh" || die "e2e-governor-apple"
TEST_BTX="$BIN/test_btx" "$ROOT/contrib/modelnet/e2e-governor-timeline.sh" || die "e2e-governor-timeline"

step "search creator + GUI gates + ExactReplay isolation"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-search-creator.sh" || die "e2e-search-creator"
"$ROOT/contrib/modelnet/e2e-gui-gates.sh" || die "e2e-gui-gates"
TEST_BTX="$BIN/test_btx" "$ROOT/contrib/modelnet/e2e-search-exactreplay.sh" || die "e2e-search-exactreplay"

step "economy search / feed / release discovery"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-economy-search.sh" || die "e2e-economy-search"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-network-feed.sh" || die "e2e-network-feed"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-release-discovery.sh" || die "e2e-release-discovery"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-release-transition.sh" || die "e2e-release-transition"
"$ROOT/contrib/modelnet/e2e-economy-gui.sh" || die "e2e-economy-gui"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-economy-three-host.sh" || die "e2e-economy-three-host"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-economy-four-host.sh" || die "e2e-economy-four-host"
MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-encrypted-cache.sh" || die "e2e-encrypted-cache"
BIN="$BIN" "$ROOT/contrib/modelnet/e2e-economy-regtest.sh" || die "e2e-economy-regtest"

step "bounty E2E A–J (spec §20)"
BIN="$BIN" MODELD="$MODELD" "$ROOT/contrib/modelnet/e2e-bounty-all.sh" || die "e2e-bounty-all"

step "QUIC deferred + Apple pkg recipe"
MODELD="$MODELD" TEST_BTX="$BIN/test_btx" "$ROOT/contrib/modelnet/e2e-quic-absent.sh" || die "e2e-quic-absent"
"$ROOT/contrib/modelnet/e2e-apple-pkg-recipe.sh" || die "e2e-apple-pkg-recipe"

if [[ -x /usr/bin/google-chrome ]]; then
  step "optional web bridge"
  "$ROOT/contrib/modelnet/e2e-bridge-optional.sh" || die "e2e-bridge-optional"
else
  echo "skip e2e-bridge-optional (no google-chrome)"
fi
step "bridge matrix BRIDGE-01..12"
"$ROOT/contrib/modelnet/e2e-bridge-matrix.sh" || die "e2e-bridge-matrix"
step "os handler"
"$ROOT/contrib/modelnet/e2e-os-handler.sh" || die "e2e-os-handler"
step "webpki tls"
"$ROOT/contrib/modelnet/e2e-webpki-tls.sh" || die "e2e-webpki-tls"

echo
echo "E2E_ALL PASS (local sequential). Prefer concurrent:"
echo "  contrib/modelnet/e2e-parallel-a.sh && contrib/modelnet/e2e-parallel-b.sh"
echo "Two-host: contrib/modelnet/e2e-regtest-two-host.sh"
echo "Three-host: contrib/modelnet/e2e-regtest-three-host.sh"
echo "Cross-host inspect: contrib/modelnet/e2e-cross-host-inspect.sh"
echo "CUDA on a dedicated workstation: CUDA_HOST=... contrib/modelnet/cuda-isolated-e2e.sh"
echo "13.8 GiB (opt-in, disk-backed): BTX_SHARD19=1 contrib/modelnet/e2e-shard19.sh"
echo "Search scale: BTX_SEARCH_SCALE_RUN=1 contrib/modelnet/e2e-search-scale.sh"
exit 0

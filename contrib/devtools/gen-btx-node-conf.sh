#!/usr/bin/env bash
set -euo pipefail

PROFILE="${1:-fast}"
BOOTSTRAP_MODE="${2:-discover}"
MANAGED_NODE_NAME="${3:-}"

case "${PROFILE}" in
  fast|archival|discovery)
    ;;
  *)
    echo "usage: $0 [fast|archival|discovery] [discover|strict-connect|managed-direct] [local|fra|nyc|sfo]" >&2
    exit 1
    ;;
esac

case "${BOOTSTRAP_MODE}" in
  discover|strict-connect|managed-direct)
    ;;
  *)
    echo "usage: $0 [fast|archival] [discover|strict-connect|managed-direct] [local|fra|nyc|sfo]" >&2
    exit 1
    ;;
esac

# RFC 5737 TEST-NET-1 examples. Substitute your own private archival
# peers. Do not commit live operator addresses.
managed_direct_peers() {
  case "${1}" in
    local)
      cat <<'EOF'
addnode=192.0.2.10:19335
addnode=192.0.2.11:19335
addnode=192.0.2.12:19335
EOF
      ;;
    fra)
      cat <<'EOF'
addnode=192.0.2.10:19335
addnode=192.0.2.11:19335
EOF
      ;;
    nyc)
      cat <<'EOF'
addnode=192.0.2.12:19335
addnode=192.0.2.11:19335
EOF
      ;;
    sfo)
      cat <<'EOF'
addnode=192.0.2.12:19335
addnode=192.0.2.10:19335
EOF
      ;;
    *)
      return 1
      ;;
  esac
}

cat <<'EOF'
# BTX mainnet baseline
server=1
listen=1
port=19335

# Local-only RPC
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=19334

# Allow young-chain bootstrap
minimumchainwork=0

# Keep shielded commitment lookups on disk so restart and snapshot recovery stay fast.
retainshieldedcommitmentindex=1

# Runtime defaults
dbcache=4096
maxmempool=300
EOF

if [[ "${PROFILE}" == "discovery" ]]; then
  cat <<'EOF'

# 0.34 public discovery relay: ADDR introduction only. Not MatMul
# authority, not a chain-tip oracle, not GETMMATTEST. Archives follow
# GPU attestors via the pin; this host only points at other nodes.
# Do not put GPU attestor IPs in addnode/DNS. See
# doc/design/0.34-discovery-relay.md.
matmulvalidation=relay
disablewallet=1
EOF
else
  cat <<'EOF'

# Published mainnet ExactReplay attestors (public keys only).
# GPU attestors and following archives return this from
# getmatmultrustedstatus / getfinalityinfo after you join the seed mesh.
# P2P addnode/DNS does not push keys. Do not load a signer WIF here.
# Live pin is 1-of-2 (telemetry on consensus miners). 0.34 trusted mainnet
# archives refuse M<2 unless -allowsinglekeytrustedmirror=1; raise this to 2
# only after both attestors sign every height. See
# doc/design/0.34-operator-safeguards.md.
matmultrustedpubkey=03d90c148db37da28ce47ce15bade88a177728d663da4bc9ba765943b7d4e4f0aa
matmultrustedpubkey=0224e80df33697385b54b3c69bae1f097f533c0c43e93c29f73ee97319d4a5e04c
matmultrustedthreshold=1
EOF
fi

if [[ "${BOOTSTRAP_MODE}" == "discover" ]]; then
  cat <<'EOF'

# Scalable bootstrap (recommended): seed with public BTX nodes, keep peer discovery on.
dnsseed=1
fixedseeds=1
addnode=node.btx.dev:19335
addnode=node.btxchain.org:19335
addnode=node.btx.tools:19335
addnode=146.190.179.86:19335
addnode=164.90.246.229:19335
EOF
elif [[ "${BOOTSTRAP_MODE}" == "strict-connect" ]]; then
  cat <<'EOF'

# Strict deterministic troubleshooting mode:
# pins outbound peers and disables automatic peer discovery.
dnsseed=0
fixedseeds=0
connect=node.btx.dev:19335
connect=node.btxchain.org:19335
connect=node.btx.tools:19335
connect=146.190.179.86:19335
connect=164.90.246.229:19335
EOF
else
  if [[ -z "${MANAGED_NODE_NAME}" ]]; then
    echo "managed-direct requires a managed node name: local|fra|nyc|sfo" >&2
    exit 1
  fi
  if ! MANAGED_PEERS="$(managed_direct_peers "${MANAGED_NODE_NAME}")"; then
    echo "unknown managed node name for managed-direct: ${MANAGED_NODE_NAME}" >&2
    exit 1
  fi
  cat <<EOF

# Private-set direct-peer mode:
# disables public seed discovery and pins example RFC 5737 archival
# peers. Substitute your own addresses; do not commit live operator IPs.
dnsseed=0
fixedseeds=0
${MANAGED_PEERS}
EOF
fi

if [[ "${PROFILE}" == "fast" ]]; then
  cat <<'EOF'

# Fast node profile (recommended for most operators)
prune=4096
EOF
elif [[ "${PROFILE}" == "archival" ]]; then
  cat <<'EOF'

# Archival profile (full historical block bodies)
prune=0
EOF
else
  cat <<'EOF'

# Discovery relay: not a block source. Prune is unused for IBD serving
# (NODE_NETWORK is withheld); keep a small datadir.
prune=550
EOF
fi

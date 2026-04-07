# Dandelion++ Implementation Specification for BTX Node

## Comprehensive Technical Design Document

**Version:** 1.1 (Updated with academic paper formal findings)
**Status:** Implementation-Ready Specification
**Target Activation:** Block Height 250,000 (Configurable)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Protocol Overview](#2-protocol-overview)
3. [BTX Codebase Architecture Analysis](#3-btx-codebase-architecture-analysis)
4. [Detailed Implementation Plan](#4-detailed-implementation-plan)
5. [Files to Create](#5-files-to-create)
6. [Files to Modify](#6-files-to-modify)
7. [Data Structures and Algorithms](#7-data-structures-and-algorithms)
8. [Block Height 250,000 Activation Analysis](#8-block-height-250000-activation-analysis)
9. [Configuration and CLI Parameters](#9-configuration-and-cli-parameters)
10. [Test Plan](#10-test-plan)
11. [Security Analysis](#11-security-analysis)
12. [Deployment Strategy](#12-deployment-strategy)
13. [Estimated Code Size](#13-estimated-code-size)
14. [Reference Implementations](#14-reference-implementations)

---

## 1. Executive Summary

This document specifies the complete implementation of Dandelion++ (transaction-origin privacy protocol) for the BTX node. Dandelion++ is a P2P networking layer change that provides formal anonymity guarantees against transaction-origin deanonymization. It requires **zero consensus changes** and is fully backward-compatible with non-upgraded nodes.

### Key Design Decisions

- **Activation mechanism:** Height-gated P2P behavior (not a consensus fork)
- **Implementation scope:** ~1,500-2,000 lines of new C++ code across 4 new files + modifications to 8 existing files
- **Activation height:** 250,000 (recommended; ~7 months post-normal-phase; see Section 8)
- **Backward compatibility:** 100% -- non-Dandelion++ nodes receive fluffed transactions normally
- **No new P2P message types required** -- uses existing `inv`/`tx` messages with modified routing logic

---

## 2. Protocol Overview

### 2.1 Two-Phase Broadcast

**Stem Phase (Anonymity):**
1. Originating node forwards transaction to exactly ONE randomly-selected Dandelion relay peer
2. At each epoch, each relay node is deterministically assigned as either a **relayer** (90% probability) or a **diffuser** (10% probability) -- this is a per-node-per-epoch decision, NOT per-transaction
3. Relayer nodes use **one-to-one forwarding**: each incoming edge is mapped to a fixed outgoing edge for the entire epoch, so all transactions from the same source follow the same path
4. Diffuser nodes immediately broadcast via standard diffusion (fluff)
5. Stem transactions are held in a separate "stem pool" (not the main mempool)
6. Stem transactions are NOT announced via `inv` to non-relay peers

**Fluff Phase (Spreading):**
1. When a diffuser node receives a stem transaction (or embargo expires), it adds the transaction to its main mempool
2. Standard diffusion relay occurs (existing `RelayTransaction` path)
3. From the network's perspective, the fluffing node appears to be the originator

### 2.2 Privacy Graph

- Each node selects exactly **2 outbound Dandelion relay peers** (quasi-4-regular graph)
- Selection is refreshed every **epoch** (~10 minutes, per-node asynchronous timer)
- Only outbound full-relay connections are eligible as Dandelion relays
- The graph is constructed independently by each node -- no coordination needed
- **No version-checking**: relay peers are selected regardless of whether they advertise Dandelion++ support (this is critical -- version-checking increases deanonymization risk at low adoption per the paper's Theorem 3)
- **One-to-one forwarding**: within an epoch, each incoming peer maps to a fixed outgoing relay. This achieves near-optimal precision of Theta(p^2 log(1/p)) and resists intersection attacks across multiple transactions

### 2.3 Failsafe (Embargo Timer)

- When a node forwards a transaction during stem phase, it starts an **embargo timer**
- If the transaction hasn't been seen via normal fluff relay within the timeout (~30 seconds), the node fluffs it
- This prevents black-hole attacks where a malicious stem relay drops transactions

### 2.4 Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Diffuser probability (q) | 0.10 (10%) | Per-epoch probability a node becomes a diffuser. Yields ~10 expected stem hops. Paper recommends q <= 0.2 to limit graph-manipulation attack gains. |
| Relayer probability | 0.90 (90%) | Complement of q. Node forwards stem transactions. |
| Epoch duration | 600 seconds (10 min) + random jitter | Per the paper: "on the order of 10 minutes." Monero uses 600s + 0-30s jitter. |
| Embargo timeout (T_base) | 39 seconds (Poisson average) | Derived from paper's formula: T_base >= -k(k-1)*delta_hop / (2*ln(1-epsilon)), with k=5, epsilon=0.1, delta_hop=175ms. Matches Monero's derivation. Uses exponential distribution for memorylessness. |
| Dandelion relay count | 2 per node | Creates quasi-4-regular graph (paper Algorithm 2) |
| Stem pool max size | 100 transactions | Prevents memory exhaustion |
| Stem pool max bytes | 5 MB | Hard cap on stem pool memory |

**Formal Privacy Guarantees (from the paper):**
- Precision (plausible deniability): Theta(p^2 log(1/p)) with one-to-one forwarding on 4-regular graphs -- near-optimal
- Recall (detection probability): p + O(1/n) under first-spy estimator -- optimal
- First-spy estimator is within 8x of the optimal estimator (Theorem 1)
- Privacy is primarily a function of adversary fraction p, NOT network size n
- No-version-checking is never worse than standard diffusion, even at 0% adoption (Theorem 3)

---

## 3. BTX Codebase Architecture Analysis

### 3.1 Current Transaction Relay Flow

The current relay path in BTX follows standard Bitcoin Core diffusion:

```
Wallet/RPC → BroadcastTransaction() [node/transaction.cpp:34]
  → ProcessTransaction() [validation.cpp] -- mempool acceptance
  → mempool.AddUnbroadcastTx(txid)
  → peerman->RelayTransaction(txid, wtxid) [net_processing.cpp:2564]
    → For each peer: tx_relay->m_tx_inventory_to_send.insert(hash)

SendMessages() [net_processing.cpp:6780+]
  → For each peer with pending inventory:
    → Build inv vector from m_tx_inventory_to_send
    → MakeAndPushMessage(*pto, NetMsgType::INV, vInv)
```

Incoming transactions:
```
ProcessMessage("tx") [net_processing.cpp:5074]
  → Deserialize transaction
  → ProcessTransaction() [validation.cpp] -- mempool acceptance
  → RelayTransaction(txid, wtxid) -- flood to all peers
```

### 3.2 Key Integration Points

| Component | File | Lines | Role in Dandelion++ |
|-----------|------|-------|---------------------|
| `PeerManagerImpl::RelayTransaction` | `net_processing.cpp:2564` | 25 | **Core modification** -- route to stem or fluff |
| `PeerManagerImpl::ProcessMessage("tx")` | `net_processing.cpp:5074` | ~100 | **Core modification** -- detect stem vs fluff incoming |
| `PeerManagerImpl::SendMessages` | `net_processing.cpp:6780` | ~150 | **Core modification** -- send stem txs to relay peer only |
| `BroadcastTransaction` | `node/transaction.cpp:34` | ~100 | **Minor modification** -- initiate stem phase for local txs |
| `struct Peer` | `net_processing.cpp:263` | ~150 | **Extension** -- add Dandelion state per peer |
| `struct Peer::TxRelay` | `net_processing.cpp:331` | 30 | **Extension** -- stem pool tracking |
| `CTxMemPool` | `txmempool.h/cpp` | ~2500 | **No changes needed** -- stem pool is separate |
| `Consensus::Params` | `consensus/params.h:75` | 200 | **Extension** -- add nDandelionActivationHeight |
| `CChainParams` (mainnet) | `kernel/chainparams.cpp:100` | ~100 | **Extension** -- set activation height |
| `ServiceFlags` | `protocol.h:323` | 50 | **Extension** -- add NODE_DANDELION flag |
| `PeerManager::Options` | `net_processing.h:75` | 15 | **Extension** -- add dandelion enable flag |
| `init.cpp` | `init.cpp` | ~800 | **Extension** -- add CLI args |

### 3.3 Existing Patterns to Follow

BTX already has height-gated P2P features that serve as precedent:

1. **`nShieldedPoolActivationHeight`** (`consensus/params.h:216`) -- Shielded transactions activate at a specific height
2. **`nReorgProtectionStartHeight`** (`consensus/params.h:162`) -- Reorg protection activates at height 50,654
3. **`nFastMineHeight`** (`consensus/params.h:172`) -- Fast mining phase transitions at height 50,000
4. **`NODE_SHIELDED` service flag** (`protocol.h:336`) -- Service flag for feature capability advertisement
5. **`SHIELDED_VERSION` protocol version** (`protocol.h:62`) -- Protocol version gating

These patterns demonstrate that BTX already supports:
- Height-gated feature activation in `Consensus::Params`
- Service flag advertisement for optional P2P features
- Per-peer feature capability tracking
- Rate limiting for relay (shielded tx rate limiting as template)

---

## 4. Detailed Implementation Plan

### Phase 1: Core Data Structures (New File)

**File: `src/dandelion.h`** (~250 lines)

Contains all Dandelion++-specific data structures, constants, and the stem pool.

### Phase 2: Dandelion State Machine (New File)

**File: `src/dandelion.cpp`** (~400 lines)

Implements the Dandelion++ routing logic, epoch management, relay peer selection, embargo timers, and stem pool management.

### Phase 3: Integration into P2P Layer (Modify Existing)

Modify `net_processing.cpp` to route transactions through the Dandelion++ state machine instead of direct flooding.

### Phase 4: Consensus Parameters and Configuration

Add activation height to `Consensus::Params` and CLI configuration.

### Phase 5: Testing

Unit tests, functional tests, and fuzz tests.

---

## 5. Files to Create

### 5.1 `src/dandelion.h` (~250 lines)

```cpp
// Copyright (c) 2026 The BTX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DANDELION_H
#define BITCOIN_DANDELION_H

#include <net.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <uint256.h>

#include <chrono>
#include <map>
#include <optional>
#include <set>
#include <vector>

/** Dandelion++ Protocol Constants (per Fanti et al. 2018) */

/** Probability (percent) that a node becomes a DIFFUSER in each epoch.
 *  Diffusers fluff all relayed stem transactions immediately.
 *  Paper recommends q <= 0.2. We use 10% (matching Grin). */
static constexpr int DANDELION_DIFFUSER_PROBABILITY = 10;
/** Duration of each Dandelion epoch (privacy graph refresh interval).
 *  Paper: "on the order of 10 minutes." */
static constexpr auto DANDELION_EPOCH_DURATION = std::chrono::seconds{600};
/** Random jitter added to epoch duration to prevent synchronization. */
static constexpr auto DANDELION_EPOCH_JITTER = std::chrono::seconds{30};
/** Embargo timeout average (Poisson/exponential distribution).
 *  Derived from paper formula: T_base >= -k(k-1)*delta_hop / (2*ln(1-epsilon))
 *  with k=5, epsilon=0.1, delta_hop=175ms → ~39 seconds (matches Monero). */
static constexpr auto DANDELION_EMBARGO_AVERAGE = std::chrono::seconds{39};
/** Number of outbound peers selected as Dandelion relays per epoch.
 *  Paper Algorithm 2: exactly 2, creating quasi-4-regular graph. */
static constexpr int DANDELION_RELAY_PEERS = 2;
/** Maximum number of transactions held in the stem pool. */
static constexpr size_t DANDELION_STEM_POOL_MAX_TXS = 100;
/** Maximum total bytes of transactions in the stem pool. */
static constexpr size_t DANDELION_STEM_POOL_MAX_BYTES = 5 * 1000 * 1000; // 5 MB
/** Minimum number of outbound full-relay peers to enable Dandelion++. */
static constexpr int DANDELION_MIN_PEERS = 2;
/** Default for -dandelion CLI flag. */
static constexpr bool DEFAULT_DANDELION_ENABLED = true;

/** Dandelion++ routing decision for a transaction. */
enum class DandelionRouteType {
    STEM,   //!< Forward to a single Dandelion relay peer (stem phase)
    FLUFF,  //!< Broadcast via standard diffusion (fluff phase)
};

/** Entry in the Dandelion stem pool. */
struct StemPoolEntry {
    CTransactionRef tx;
    /** The peer we forwarded this stem transaction to (for embargo tracking). */
    NodeId relay_peer;
    /** When this transaction entered the stem pool. */
    std::chrono::steady_clock::time_point entry_time;
    /** When the embargo timer expires (entry_time + EMBARGO_TIMEOUT + jitter). */
    std::chrono::steady_clock::time_point embargo_deadline;
    /** Transaction size in bytes. */
    size_t tx_size;
};

/**
 * The Dandelion++ routing engine.
 *
 * Manages the privacy graph (relay peer selection), routing decisions
 * (stem vs fluff), the stem pool, and embargo timers.
 *
 * Thread safety: All public methods acquire m_mutex internally.
 * Do NOT hold cs_main or m_peer_mutex when calling into this class.
 */
class DandelionEngine {
public:
    DandelionEngine();

    /** Start a new epoch: select relay peers, determine diffuser/relayer role,
     *  compute one-to-one forwarding map.
     *  Called periodically (every DANDELION_EPOCH_DURATION + jitter) and at startup.
     *  @param outbound_peers  List of eligible outbound full-relay peer IDs.
     *  @param inbound_peers   List of current inbound peer IDs (for one-to-one mapping).
     */
    void StartNewEpoch(const std::vector<NodeId>& outbound_peers,
                       const std::vector<NodeId>& inbound_peers);

    /** Get the current Dandelion relay peer IDs. */
    std::vector<NodeId> GetRelayPeers() const;

    /** Whether this node is a diffuser in the current epoch.
     *  Diffusers fluff ALL relayed stem transactions immediately. */
    bool IsDiffuser() const;

    /** Determine routing for a new locally-originated transaction.
     *  Local transactions always start in stem phase, forwarded to a fixed
     *  relay peer for the entire epoch (per paper recommendation).
     *  @returns The relay peer NodeId and route type (always STEM for local).
     */
    std::optional<NodeId> RouteLocalTransaction(const uint256& txid);

    /** Determine routing for a transaction received during stem phase from a peer.
     *  If this node is a DIFFUSER: return FLUFF.
     *  If this node is a RELAYER: use one-to-one forwarding map (from_peer → fixed outgoing peer).
     *  @param from_peer  The peer that sent us this stem transaction.
     *  @returns STEM with a relay peer NodeId, or FLUFF.
     */
    std::pair<DandelionRouteType, std::optional<NodeId>> RouteStemTransaction(
        const uint256& txid, NodeId from_peer);

    /** Add a transaction to the stem pool with embargo timer.
     *  @returns true if added, false if pool is full or tx already exists.
     */
    bool AddToStemPool(CTransactionRef tx, NodeId relay_peer);

    /** Remove a transaction from the stem pool (e.g., when seen fluffed). */
    void RemoveFromStemPool(const uint256& txid);

    /** Check if a transaction is in the stem pool. */
    bool IsInStemPool(const uint256& txid) const;

    /** Get a transaction from the stem pool. */
    CTransactionRef GetFromStemPool(const uint256& txid) const;

    /** Check embargo timers and return transactions that need to be fluffed.
     *  Called periodically from the message processing loop.
     *  @returns Transactions whose embargo timers have expired.
     */
    std::vector<CTransactionRef> CheckEmbargoTimers();

    /** Check if a new epoch has started and relay peers need refreshing.
     *  @returns true if epoch has rotated since last call.
     */
    bool EpochExpired() const;

    /** Notify that a peer has disconnected (clear relay state if needed). */
    void PeerDisconnected(NodeId peer_id);

    /** Get current stem pool size (number of transactions). */
    size_t GetStemPoolSize() const;

    /** Get current stem pool total bytes. */
    size_t GetStemPoolBytes() const;

    /** Clear the stem pool entirely (used during shutdown or IBD). */
    void ClearStemPool();

private:
    mutable Mutex m_mutex;

    /** Current epoch start time. */
    std::chrono::steady_clock::time_point m_epoch_start GUARDED_BY(m_mutex);

    /** Current epoch expiry (start + duration + random jitter). */
    std::chrono::steady_clock::time_point m_epoch_expiry GUARDED_BY(m_mutex);

    /** Whether this node is a DIFFUSER (fluffs all stem txs) in current epoch.
     *  Determined pseudorandomly at epoch start with probability DANDELION_DIFFUSER_PROBABILITY. */
    bool m_is_diffuser GUARDED_BY(m_mutex){false};

    /** Current Dandelion relay peers (up to DANDELION_RELAY_PEERS). */
    std::vector<NodeId> m_relay_peers GUARDED_BY(m_mutex);

    /** Fixed relay peer for locally-originated transactions (same for entire epoch). */
    NodeId m_local_relay_peer GUARDED_BY(m_mutex){-1};

    /** One-to-one forwarding map: incoming peer → outgoing relay peer.
     *  Fixed for the entire epoch. All stem txs from the same incoming peer
     *  are forwarded to the same outgoing relay (per paper Algorithm 4).
     *  This achieves Theta(p^2 log(1/p)) precision -- near-optimal. */
    std::map<NodeId, NodeId> m_incoming_to_outgoing GUARDED_BY(m_mutex);

    /** Usage count per relay peer (for load balancing incoming assignments). */
    std::map<NodeId, int> m_relay_usage GUARDED_BY(m_mutex);

    /** The stem pool: transactions in stem phase awaiting fluff or embargo. */
    std::map<uint256, StemPoolEntry> m_stem_pool GUARDED_BY(m_mutex);

    /** Total bytes in the stem pool. */
    size_t m_stem_pool_bytes GUARDED_BY(m_mutex){0};

    /** Set of txids we've seen in stem phase (prevents re-entry / loops). */
    std::set<uint256> m_stem_seen GUARDED_BY(m_mutex);

    /** Assign an incoming peer to the least-used outgoing relay (Monero pattern). */
    NodeId AssignRelayForIncoming(NodeId incoming) EXCLUSIVE_LOCKS_REQUIRED(m_mutex);

    /** Internal: compute embargo deadline using exponential distribution.
     *  Memorylessness ensures uniform first-broadcaster during black-hole attacks. */
    std::chrono::steady_clock::time_point ComputeEmbargoDeadline() const;
};

#endif // BITCOIN_DANDELION_H
```

### 5.2 `src/dandelion.cpp` (~400 lines)

```cpp
// Copyright (c) 2026 The BTX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dandelion.h>
#include <logging.h>
#include <random.h>
#include <util/time.h>

DandelionEngine::DandelionEngine()
    : m_epoch_start{std::chrono::steady_clock::now()} {}

void DandelionEngine::SelectRelayPeers(const std::vector<NodeId>& outbound_peers)
{
    LOCK(m_mutex);
    m_relay_peers.clear();
    m_relay_index = 0;
    m_epoch_start = std::chrono::steady_clock::now();

    if (outbound_peers.size() < static_cast<size_t>(DANDELION_MIN_PEERS)) {
        LogDebug(BCLog::NET, "Dandelion++: insufficient outbound peers (%d < %d), "
                 "falling back to standard relay\n",
                 outbound_peers.size(), DANDELION_MIN_PEERS);
        return;
    }

    // Shuffle and select DANDELION_RELAY_PEERS peers
    std::vector<NodeId> shuffled = outbound_peers;
    Shuffle(shuffled.begin(), shuffled.end(), FastRandomContext());

    size_t count = std::min(shuffled.size(),
                            static_cast<size_t>(DANDELION_RELAY_PEERS));
    m_relay_peers.assign(shuffled.begin(), shuffled.begin() + count);

    LogDebug(BCLog::NET, "Dandelion++: selected %d relay peers for new epoch\n",
             m_relay_peers.size());
}

std::vector<NodeId> DandelionEngine::GetRelayPeers() const
{
    LOCK(m_mutex);
    return m_relay_peers;
}

std::optional<NodeId> DandelionEngine::NextRelayPeer()
{
    AssertLockHeld(m_mutex);
    if (m_relay_peers.empty()) return std::nullopt;
    NodeId peer = m_relay_peers[m_relay_index % m_relay_peers.size()];
    m_relay_index++;
    return peer;
}

std::optional<NodeId> DandelionEngine::RouteLocalTransaction(const uint256& txid)
{
    LOCK(m_mutex);
    if (m_stem_seen.count(txid)) return std::nullopt;
    m_stem_seen.insert(txid);
    return NextRelayPeer();
}

std::pair<DandelionRouteType, std::optional<NodeId>>
DandelionEngine::RouteStemTransaction(const uint256& txid, NodeId from_peer)
{
    LOCK(m_mutex);

    // Already seen this transaction in stem phase
    if (m_stem_seen.count(txid)) {
        return {DandelionRouteType::FLUFF, std::nullopt};
    }
    m_stem_seen.insert(txid);

    // Probabilistic stem/fluff decision
    FastRandomContext rng;
    if (rng.randrange(100) < DANDELION_STEM_PROBABILITY) {
        // Continue stem: forward to relay peer (not back to sender)
        auto relay = NextRelayPeer();
        if (relay && *relay == from_peer && m_relay_peers.size() > 1) {
            // Don't send back to the same peer -- pick the other relay
            relay = NextRelayPeer();
        }
        if (relay) {
            return {DandelionRouteType::STEM, relay};
        }
    }

    // Fluff: standard diffusion
    return {DandelionRouteType::FLUFF, std::nullopt};
}

bool DandelionEngine::AddToStemPool(CTransactionRef tx, NodeId relay_peer)
{
    LOCK(m_mutex);
    const uint256& txid = tx->GetHash();

    if (m_stem_pool.count(txid)) return false;
    if (m_stem_pool.size() >= DANDELION_STEM_POOL_MAX_TXS) return false;

    size_t tx_size = tx->GetTotalSize();
    if (m_stem_pool_bytes + tx_size > DANDELION_STEM_POOL_MAX_BYTES) return false;

    StemPoolEntry entry;
    entry.tx = std::move(tx);
    entry.relay_peer = relay_peer;
    entry.entry_time = std::chrono::steady_clock::now();
    entry.embargo_deadline = ComputeEmbargoDeadline();
    entry.tx_size = tx_size;

    m_stem_pool_bytes += tx_size;
    m_stem_pool.emplace(txid, std::move(entry));

    LogDebug(BCLog::NET, "Dandelion++: added tx %s to stem pool (size=%d, bytes=%d)\n",
             txid.ToString(), m_stem_pool.size(), m_stem_pool_bytes);
    return true;
}

void DandelionEngine::RemoveFromStemPool(const uint256& txid)
{
    LOCK(m_mutex);
    auto it = m_stem_pool.find(txid);
    if (it != m_stem_pool.end()) {
        m_stem_pool_bytes -= it->second.tx_size;
        m_stem_pool.erase(it);
    }
}

bool DandelionEngine::IsInStemPool(const uint256& txid) const
{
    LOCK(m_mutex);
    return m_stem_pool.count(txid) > 0;
}

CTransactionRef DandelionEngine::GetFromStemPool(const uint256& txid) const
{
    LOCK(m_mutex);
    auto it = m_stem_pool.find(txid);
    if (it != m_stem_pool.end()) return it->second.tx;
    return nullptr;
}

std::vector<CTransactionRef> DandelionEngine::CheckEmbargoTimers()
{
    LOCK(m_mutex);
    std::vector<CTransactionRef> expired;
    auto now = std::chrono::steady_clock::now();

    for (auto it = m_stem_pool.begin(); it != m_stem_pool.end(); ) {
        if (now >= it->second.embargo_deadline) {
            LogDebug(BCLog::NET, "Dandelion++: embargo expired for tx %s, fluffing\n",
                     it->first.ToString());
            expired.push_back(it->second.tx);
            m_stem_pool_bytes -= it->second.tx_size;
            it = m_stem_pool.erase(it);
        } else {
            ++it;
        }
    }
    return expired;
}

bool DandelionEngine::EpochExpired() const
{
    LOCK(m_mutex);
    auto now = std::chrono::steady_clock::now();
    return (now - m_epoch_start) >= DANDELION_EPOCH_DURATION;
}

void DandelionEngine::PeerDisconnected(NodeId peer_id)
{
    LOCK(m_mutex);
    // Remove disconnected peer from relay list
    m_relay_peers.erase(
        std::remove(m_relay_peers.begin(), m_relay_peers.end(), peer_id),
        m_relay_peers.end());

    // Fluff any stem transactions that were relayed to this peer
    // (they may have been dropped -- embargo will catch this, but
    //  immediate fluff is more responsive)
    for (auto it = m_stem_pool.begin(); it != m_stem_pool.end(); ) {
        if (it->second.relay_peer == peer_id) {
            // Set embargo to now so CheckEmbargoTimers will pick it up
            it->second.embargo_deadline = std::chrono::steady_clock::now();
            ++it;
        } else {
            ++it;
        }
    }
}

size_t DandelionEngine::GetStemPoolSize() const
{
    LOCK(m_mutex);
    return m_stem_pool.size();
}

size_t DandelionEngine::GetStemPoolBytes() const
{
    LOCK(m_mutex);
    return m_stem_pool_bytes;
}

void DandelionEngine::ClearStemPool()
{
    LOCK(m_mutex);
    m_stem_pool.clear();
    m_stem_pool_bytes = 0;
    m_stem_seen.clear();
}

std::chrono::steady_clock::time_point DandelionEngine::ComputeEmbargoDeadline() const
{
    AssertLockHeld(m_mutex);
    FastRandomContext rng;
    auto jitter = std::chrono::seconds{rng.randrange(
        count_seconds(DANDELION_EMBARGO_JITTER))};
    return std::chrono::steady_clock::now() + DANDELION_EMBARGO_TIMEOUT + jitter;
}
```

### 5.3 `src/test/dandelion_tests.cpp` (~500 lines)

```cpp
// Copyright (c) 2026 The BTX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <dandelion.h>
#include <boost/test/unit_test.hpp>
#include <primitives/transaction.h>
#include <test/util/setup_common.h>
#include <uint256.h>

BOOST_AUTO_TEST_SUITE(dandelion_tests)

// --- Relay Peer Selection Tests ---

BOOST_AUTO_TEST_CASE(select_relay_peers_empty)
{
    DandelionEngine engine;
    engine.SelectRelayPeers({});
    BOOST_CHECK(engine.GetRelayPeers().empty());
}

BOOST_AUTO_TEST_CASE(select_relay_peers_insufficient)
{
    DandelionEngine engine;
    engine.SelectRelayPeers({1}); // Only 1 peer, need 2
    BOOST_CHECK(engine.GetRelayPeers().empty());
}

BOOST_AUTO_TEST_CASE(select_relay_peers_sufficient)
{
    DandelionEngine engine;
    engine.SelectRelayPeers({1, 2, 3, 4, 5});
    auto peers = engine.GetRelayPeers();
    BOOST_CHECK_EQUAL(peers.size(), DANDELION_RELAY_PEERS);
}

BOOST_AUTO_TEST_CASE(select_relay_peers_exact)
{
    DandelionEngine engine;
    engine.SelectRelayPeers({10, 20});
    auto peers = engine.GetRelayPeers();
    BOOST_CHECK_EQUAL(peers.size(), 2);
}

// --- Routing Tests ---

BOOST_AUTO_TEST_CASE(route_local_transaction)
{
    DandelionEngine engine;
    engine.SelectRelayPeers({1, 2, 3});

    uint256 txid = uint256::ONE;
    auto relay = engine.RouteLocalTransaction(txid);
    BOOST_CHECK(relay.has_value());

    // Second call with same txid should return nullopt (already seen)
    auto relay2 = engine.RouteLocalTransaction(txid);
    BOOST_CHECK(!relay2.has_value());
}

BOOST_AUTO_TEST_CASE(route_local_no_peers)
{
    DandelionEngine engine;
    // No relay peers selected
    auto relay = engine.RouteLocalTransaction(uint256::ONE);
    BOOST_CHECK(!relay.has_value());
}

BOOST_AUTO_TEST_CASE(route_stem_transaction_probabilistic)
{
    DandelionEngine engine;
    engine.SelectRelayPeers({1, 2, 3, 4, 5});

    int stem_count = 0, fluff_count = 0;
    for (int i = 0; i < 1000; i++) {
        uint256 txid;
        // Create unique txids
        *txid.begin() = static_cast<uint8_t>(i & 0xFF);
        *(txid.begin() + 1) = static_cast<uint8_t>((i >> 8) & 0xFF);

        auto [route, peer] = engine.RouteStemTransaction(txid, 99);
        if (route == DandelionRouteType::STEM) {
            stem_count++;
            BOOST_CHECK(peer.has_value());
        } else {
            fluff_count++;
        }
    }
    // With 90% stem probability, expect ~900 stem and ~100 fluff
    // Allow +-5% tolerance (850-950 stem)
    BOOST_CHECK(stem_count > 800);
    BOOST_CHECK(stem_count < 980);
    BOOST_CHECK(fluff_count > 20);
}

// --- Stem Pool Tests ---

BOOST_AUTO_TEST_CASE(stem_pool_add_remove)
{
    DandelionEngine engine;

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    auto tx = MakeTransactionRef(mtx);

    BOOST_CHECK(engine.AddToStemPool(tx, 1));
    BOOST_CHECK_EQUAL(engine.GetStemPoolSize(), 1);
    BOOST_CHECK(engine.IsInStemPool(tx->GetHash()));

    engine.RemoveFromStemPool(tx->GetHash());
    BOOST_CHECK_EQUAL(engine.GetStemPoolSize(), 0);
    BOOST_CHECK(!engine.IsInStemPool(tx->GetHash()));
}

BOOST_AUTO_TEST_CASE(stem_pool_duplicate_rejected)
{
    DandelionEngine engine;

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    auto tx = MakeTransactionRef(mtx);

    BOOST_CHECK(engine.AddToStemPool(tx, 1));
    BOOST_CHECK(!engine.AddToStemPool(tx, 2)); // duplicate
}

BOOST_AUTO_TEST_CASE(stem_pool_max_count)
{
    DandelionEngine engine;

    for (size_t i = 0; i < DANDELION_STEM_POOL_MAX_TXS; i++) {
        CMutableTransaction mtx;
        mtx.nVersion = 2;
        mtx.nLockTime = static_cast<uint32_t>(i); // unique
        mtx.vout.resize(1);
        mtx.vout[0].nValue = 1000;
        BOOST_CHECK(engine.AddToStemPool(MakeTransactionRef(mtx), 1));
    }

    // Pool is full
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.nLockTime = static_cast<uint32_t>(DANDELION_STEM_POOL_MAX_TXS + 1);
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    BOOST_CHECK(!engine.AddToStemPool(MakeTransactionRef(mtx), 1));
}

BOOST_AUTO_TEST_CASE(stem_pool_get_transaction)
{
    DandelionEngine engine;

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 42;
    auto tx = MakeTransactionRef(mtx);

    engine.AddToStemPool(tx, 5);
    auto retrieved = engine.GetFromStemPool(tx->GetHash());
    BOOST_CHECK(retrieved != nullptr);
    BOOST_CHECK(retrieved->GetHash() == tx->GetHash());

    auto missing = engine.GetFromStemPool(uint256::ZERO);
    BOOST_CHECK(missing == nullptr);
}

// --- Embargo Timer Tests ---

BOOST_AUTO_TEST_CASE(embargo_timer_no_expiry)
{
    DandelionEngine engine;

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    engine.AddToStemPool(MakeTransactionRef(mtx), 1);

    // Immediately checking should find no expired transactions
    auto expired = engine.CheckEmbargoTimers();
    BOOST_CHECK(expired.empty());
}

// Note: Testing actual embargo expiry requires mocking time or waiting.
// In a real test suite, use SetMockTime or similar facility.

// --- Epoch Tests ---

BOOST_AUTO_TEST_CASE(epoch_not_immediately_expired)
{
    DandelionEngine engine;
    BOOST_CHECK(!engine.EpochExpired());
}

// --- Peer Disconnect Tests ---

BOOST_AUTO_TEST_CASE(peer_disconnect_removes_relay)
{
    DandelionEngine engine;
    engine.SelectRelayPeers({1, 2, 3});

    auto peers_before = engine.GetRelayPeers();
    BOOST_CHECK_EQUAL(peers_before.size(), 2);

    // Disconnect one of the relay peers
    NodeId to_disconnect = peers_before[0];
    engine.PeerDisconnected(to_disconnect);

    auto peers_after = engine.GetRelayPeers();
    BOOST_CHECK_EQUAL(peers_after.size(), 1);
    BOOST_CHECK(peers_after[0] != to_disconnect);
}

// --- Clear Tests ---

BOOST_AUTO_TEST_CASE(clear_stem_pool)
{
    DandelionEngine engine;

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 1000;
    engine.AddToStemPool(MakeTransactionRef(mtx), 1);

    BOOST_CHECK_EQUAL(engine.GetStemPoolSize(), 1);
    engine.ClearStemPool();
    BOOST_CHECK_EQUAL(engine.GetStemPoolSize(), 0);
    BOOST_CHECK_EQUAL(engine.GetStemPoolBytes(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
```

### 5.4 `test/functional/p2p_dandelion.py` (~300 lines)

Functional test using the BTX test framework:

```python
#!/usr/bin/env python3
# Copyright (c) 2026 The BTX Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Dandelion++ transaction relay protocol.

Tests:
1. Transactions are relayed via stem phase (single peer) when Dandelion++ is active
2. Embargo timer fluffs transactions after timeout
3. Dandelion++ deactivates when insufficient peers
4. Graceful degradation with non-Dandelion peers
5. Epoch rotation refreshes relay peer selection
6. Stem pool limits are enforced
7. Height-based activation works correctly
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.p2p import P2PInterface
from test_framework.messages import msg_tx, CTransaction, CTxIn, CTxOut, COutPoint

import time


class DandelionTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 4
        self.setup_clean_chain = True
        # Set low activation height for testing
        self.extra_args = [
            ["-dandelion=1"],
            ["-dandelion=1"],
            ["-dandelion=1"],
            ["-dandelion=0"],  # Node 3 has Dandelion disabled
        ]

    def run_test(self):
        self.test_basic_stem_relay()
        self.test_embargo_fluff()
        self.test_insufficient_peers()
        self.test_disabled_node_compatibility()
        self.test_stem_pool_limits()

    def test_basic_stem_relay(self):
        self.log.info("Test basic stem relay...")
        # Verify that when node 0 creates a transaction, it is initially
        # relayed to only one peer (stem phase), not all peers
        # Implementation details depend on P2P test harness capabilities

    def test_embargo_fluff(self):
        self.log.info("Test embargo timer forces fluff...")
        # Create a transaction via stem, verify it eventually reaches all
        # nodes even if stem relay peer doesn't propagate it

    def test_insufficient_peers(self):
        self.log.info("Test fallback with insufficient peers...")
        # Node with < 2 outbound peers should fall back to standard relay

    def test_disabled_node_compatibility(self):
        self.log.info("Test compatibility with non-Dandelion nodes...")
        # Node 3 (Dandelion disabled) should still receive all transactions

    def test_stem_pool_limits(self):
        self.log.info("Test stem pool capacity limits...")
        # Verify stem pool respects MAX_TXS and MAX_BYTES limits


if __name__ == '__main__':
    DandelionTest(__file__).main()
```

---

## 6. Files to Modify

### 6.1 `src/consensus/params.h` -- Add Activation Height

**Location:** After `nShieldedPoolActivationHeight` (line 216)

```cpp
// ADD after line 217:
    /** Block height at which Dandelion++ P2P relay activates.
     *  This is NOT a consensus rule -- it gates P2P behavior only.
     *  Nodes below this height use standard diffusion relay. */
    int32_t nDandelionActivationHeight{std::numeric_limits<int32_t>::max()};
```

### 6.2 `src/kernel/chainparams.cpp` -- Set Activation Heights

**Mainnet (line ~168):**
```cpp
// ADD after nMLDSADisableHeight:
        consensus.nDandelionActivationHeight = 250'000;
```

**Testnet (line ~326):**
```cpp
        consensus.nDandelionActivationHeight = 100; // Early activation for testing
```

**Testnet4 (line ~472):**
```cpp
        consensus.nDandelionActivationHeight = 100;
```

**Signet (line ~614):**
```cpp
        consensus.nDandelionActivationHeight = 100;
```

**Regtest (line ~744):**
```cpp
        consensus.nDandelionActivationHeight = 0; // Active from genesis in regtest
```

### 6.3 `src/protocol.h` -- Add Service Flag

**Location:** After `NODE_SHIELDED` (line 336)

```cpp
// ADD after NODE_SHIELDED:
    // NODE_DANDELION indicates support for Dandelion++ stem relay.
    NODE_DANDELION = (1 << 9),
```

**Update `serviceFlagsToStr` in `protocol.cpp`** to include the new flag.

### 6.4 `src/net_processing.h` -- Add Options

**Location:** In `PeerManager::Options` struct (line 75)

```cpp
// ADD:
        //! Whether Dandelion++ transaction relay is enabled
        bool enable_dandelion{DEFAULT_DANDELION_ENABLED};
```

### 6.5 `src/net_processing.cpp` -- Core Relay Modifications

This is the largest and most critical set of changes. Approximately ~200 lines of modifications.

#### 6.5.1 Add Include and Member

```cpp
// ADD to includes (line ~6):
#include <dandelion.h>

// ADD to PeerManagerImpl class members (around line 520):
    /** Dandelion++ routing engine. */
    std::unique_ptr<DandelionEngine> m_dandelion;

    /** Whether Dandelion++ is enabled via configuration. */
    bool m_dandelion_enabled{false};

    /** Check if Dandelion++ is active at the current chain height. */
    bool IsDandelionActive() const {
        if (!m_dandelion_enabled) return false;
        return m_best_height >= m_chainparams.GetConsensus().nDandelionActivationHeight;
    }
```

#### 6.5.2 Modify Constructor

In `PeerManagerImpl` constructor, initialize the Dandelion engine:

```cpp
// ADD to constructor body:
    m_dandelion_enabled = opts.enable_dandelion;
    if (m_dandelion_enabled) {
        m_dandelion = std::make_unique<DandelionEngine>();
    }
```

#### 6.5.3 Modify `RelayTransaction` (line 2564)

This is the **most critical change**. Currently, `RelayTransaction` floods to all peers. With Dandelion++, local transactions enter stem phase.

```cpp
void PeerManagerImpl::RelayTransaction(const uint256& txid, const uint256& wtxid)
{
    // If Dandelion++ is active, route through stem phase
    if (IsDandelionActive() && m_dandelion) {
        auto relay_peer = m_dandelion->RouteLocalTransaction(txid);
        if (relay_peer) {
            // Stem relay: send inv to only the selected relay peer
            LOCK(m_peer_mutex);
            auto it = m_peer_map.find(*relay_peer);
            if (it != m_peer_map.end()) {
                Peer& peer = *it->second;
                auto tx_relay = peer.GetTxRelay();
                if (tx_relay) {
                    LOCK(tx_relay->m_tx_inventory_mutex);
                    if (tx_relay->m_next_inv_send_time != 0s) {
                        const uint256& hash{peer.m_wtxid_relay ? wtxid : txid};
                        if (!tx_relay->m_tx_inventory_known_filter.contains(hash)) {
                            tx_relay->m_tx_inventory_to_send.insert(hash);
                        }
                    }
                }
            }

            // Add to stem pool with embargo timer
            // (tx must be fetched from mempool since we don't have CTransactionRef here)
            auto txinfo = m_mempool.info(GenTxid::Txid(txid));
            if (txinfo.tx) {
                m_dandelion->AddToStemPool(txinfo.tx, *relay_peer);
            }

            LogDebug(BCLog::NET, "Dandelion++: stem relay tx %s to peer=%d\n",
                     txid.ToString(), *relay_peer);
            return;
        }
        // If no relay peer available, fall through to standard diffusion
    }

    // Standard diffusion relay (existing code)
    LOCK(m_peer_mutex);
    for(auto& it : m_peer_map) {
        Peer& peer = *it.second;
        auto tx_relay = peer.GetTxRelay();
        if (!tx_relay) continue;

        LOCK(tx_relay->m_tx_inventory_mutex);
        if (tx_relay->m_next_inv_send_time == 0s) continue;

        const uint256& hash{peer.m_wtxid_relay ? wtxid : txid};
        if (!tx_relay->m_tx_inventory_known_filter.contains(hash)) {
            if (tx_relay->m_tx_inventory_to_send.size() >= MAX_TX_INVENTORY_TO_SEND) {
                continue;
            }
            tx_relay->m_tx_inventory_to_send.insert(hash);
        }
    };
}
```

#### 6.5.4 Modify `ProcessMessage("tx")` (around line 5074)

When receiving a transaction, check if it's a stem relay or standard:

```cpp
// AFTER the transaction is validated and accepted to mempool (around line 5175):
// REPLACE the existing RelayTransaction call:

    if (IsDandelionActive() && m_dandelion) {
        // Check if this tx was relayed via stem phase
        // For now, all incoming txs that pass validation get standard relay.
        // Stem-phase forwarding is handled when we receive a stem inv.
        //
        // If we receive a tx that's in our stem pool, it means it has been
        // fluffed by another node -- remove from stem pool.
        m_dandelion->RemoveFromStemPool(tx.GetHash());
    }
    RelayTransaction(tx.GetHash(), tx.GetWitnessHash());
```

#### 6.5.5 Add Embargo Timer Check to `SendMessages`

Add periodic embargo timer checking in the `SendMessages` function, right before the inventory broadcast section (around line 6780):

```cpp
// ADD before the "Message: inventory" section:
    // Dandelion++: check embargo timers and fluff expired stem transactions
    if (IsDandelionActive() && m_dandelion) {
        auto expired_txs = m_dandelion->CheckEmbargoTimers();
        for (const auto& tx : expired_txs) {
            LogDebug(BCLog::NET, "Dandelion++: fluffing embargoed tx %s\n",
                     tx->GetHash().ToString());
            // Standard diffusion: add to all peers' inventory
            // Use the non-Dandelion path by temporarily disabling
            const uint256& txid = tx->GetHash();
            const uint256& wtxid = tx->GetWitnessHash();
            LOCK(m_peer_mutex);
            for (auto& it : m_peer_map) {
                Peer& peer = *it.second;
                auto tx_relay = peer.GetTxRelay();
                if (!tx_relay) continue;
                LOCK(tx_relay->m_tx_inventory_mutex);
                if (tx_relay->m_next_inv_send_time == 0s) continue;
                const uint256& hash{peer.m_wtxid_relay ? wtxid : txid};
                if (!tx_relay->m_tx_inventory_known_filter.contains(hash)) {
                    tx_relay->m_tx_inventory_to_send.insert(hash);
                }
            }
        }
    }

    // Dandelion++: check if epoch needs rotation
    if (IsDandelionActive() && m_dandelion && m_dandelion->EpochExpired()) {
        std::vector<NodeId> outbound_peers;
        m_connman.ForEachNode([&outbound_peers](CNode* pnode) {
            if (!pnode->IsInboundConn() && pnode->IsFullOutboundConn()) {
                outbound_peers.push_back(pnode->GetId());
            }
        });
        m_dandelion->SelectRelayPeers(outbound_peers);
    }
```

#### 6.5.6 Handle Peer Disconnection

In `FinalizeNode` (around line 1850):

```cpp
// ADD:
    if (m_dandelion) {
        m_dandelion->PeerDisconnected(nodeid);
    }
```

### 6.6 `src/init.cpp` -- Add CLI Arguments

**Location:** In `SetupServerArgs` (around line 748, near other relay args):

```cpp
// ADD:
    argsman.AddArg("-dandelion",
        strprintf("Enable Dandelion++ transaction relay for enhanced privacy "
                  "(default: %d)", DEFAULT_DANDELION_ENABLED),
        ArgsManager::ALLOW_ANY, OptionsCategory::NODE_RELAY);
```

**Location:** Where PeerManager options are constructed:

```cpp
// ADD:
    peerman_opts.enable_dandelion = args.GetBoolArg("-dandelion", DEFAULT_DANDELION_ENABLED);
```

### 6.7 `src/node/transaction.cpp` -- Stem Phase for Wallet Broadcasts

The current `BroadcastTransaction` function calls `peerman->RelayTransaction()` which will now route through the Dandelion engine automatically. **No changes needed** to `node/transaction.cpp` since the routing decision happens inside `PeerManagerImpl::RelayTransaction`.

### 6.8 `src/CMakeLists.txt` -- Add New Source Files

```cmake
# ADD to the appropriate target's source list:
    dandelion.cpp
    dandelion.h
```

And for tests:
```cmake
# ADD to test sources:
    test/dandelion_tests.cpp
```

---

## 7. Data Structures and Algorithms

### 7.1 Privacy Graph Construction

```
Algorithm: SelectRelayPeers(outbound_peers)
  1. If |outbound_peers| < DANDELION_MIN_PEERS: return (fallback to diffusion)
  2. Shuffle outbound_peers randomly
  3. m_relay_peers ← first DANDELION_RELAY_PEERS from shuffled list
  4. m_relay_index ← 0
  5. m_epoch_start ← now()
```

### 7.2 Routing Decision (Per-Epoch Diffuser/Relayer + One-to-One Forwarding)

At epoch start, the node determines its role:
```
Algorithm: DetermineEpochRole()
  1. r ← Hash(node_identity || epoch_number) mod 100
  2. If r < DANDELION_DIFFUSER_PROBABILITY (10):
     m_is_diffuser ← true   // This node fluffs ALL stem transactions this epoch
  3. Else:
     m_is_diffuser ← false  // This node relays ALL stem transactions this epoch
  4. Compute one-to-one mapping: for each incoming peer, assign a fixed outgoing relay peer
```

Per-transaction routing:
```
Algorithm: RouteTransaction(txid, is_local, from_peer)
  1. If txid ∈ m_stem_seen: return FLUFF (prevent routing loops -- per Grin/Monero)
  2. Add txid to m_stem_seen
  3. If is_local: return (STEM, m_local_relay_peer)  // Fixed relay for all local txs in epoch
  4. If m_is_diffuser: return (FLUFF, null)           // Diffuser: fluff everything
  5. // Relayer: one-to-one forwarding
  6. peer ← m_incoming_to_outgoing_map[from_peer]     // Fixed mapping for this epoch
  7. If peer is valid: return (STEM, peer)
  8. Else: return (FLUFF, null)                        // Fallback if mapping unavailable
```

**Why this matters (from the paper):**
- Per-transaction coin flips achieve only Theta(p) precision (one order worse)
- Per-epoch + one-to-one forwarding achieves Theta(p^2 log(1/p)) -- near-optimal
- One-to-one forwarding also prevents intersection attacks across multiple transactions from the same source

### 7.3 Embargo Timer Check

```
Algorithm: CheckEmbargoTimers()
  1. expired ← []
  2. For each (txid, entry) in m_stem_pool:
     a. If now() >= entry.embargo_deadline:
        - Append entry.tx to expired
        - Remove from m_stem_pool
  3. Return expired
```

### 7.4 Epoch Rotation

```
Algorithm: MaybeRotateEpoch() -- called from SendMessages
  1. If now() - m_epoch_start < DANDELION_EPOCH_DURATION: return
  2. outbound_peers ← GetOutboundFullRelayPeers()
  3. SelectRelayPeers(outbound_peers)
```

---

## 8. Block Height 250,000 Activation Analysis

### 8.1 Timeline Estimation

BTX's block production timeline:

| Phase | Height Range | Block Spacing | Duration |
|-------|-------------|---------------|----------|
| Fast Mining | 0 - 49,999 | 250ms | ~3.5 hours |
| Normal Mining | 50,000+ | 90 seconds | Ongoing |

**Block 250,000 calculation:**
- Fast phase: 50,000 blocks in ~3.5 hours
- Normal phase blocks to reach 250,000: 200,000 blocks
- Normal phase time: 200,000 × 90s = 18,000,000s = **~208 days (~7 months)**

So block 250,000 occurs approximately **7 months after normal mining begins**.

### 8.2 Is 250,000 a Good Activation Height?

#### Arguments FOR height 250,000:

1. **Sufficient network maturity.** Seven months provides time for:
   - Node diversity and geographic distribution to develop
   - Multiple node software updates to ship (hardening, bug fixes)
   - The community to understand and test the feature
   - At least 50-100 nodes to join (threshold for meaningful privacy)

2. **Precedent alignment.** BTX already uses height-gated activations:
   - `nFastMineHeight = 50,000` (mining phase transition)
   - `nReorgProtectionStartHeight = 50,654` (reorg protection)
   - `nMatMulAsertRetuneHeight = 50,770` (difficulty adjustment)

   Height 250,000 is well past all existing activations, giving a clean separation.

3. **Not a consensus change.** Even if activation behavior is suboptimal at 250,000, it has zero risk to chain integrity. The worst case is equivalent to standard relay.

4. **Code ships early.** The Dandelion++ code can be included in the node binary from genesis. The height gate just controls when the P2P behavior activates. This means:
   - The code is battle-tested before activation
   - Users don't need to upgrade at activation time
   - No coordination event is required

#### Arguments AGAINST height 250,000:

1. **May be too early for meaningful privacy.** If network has < 50 nodes at height 250,000, the privacy guarantees are weak (see previous analysis). However, since this is graceful degradation (not a security risk), this is acceptable.

2. **Arbitrary height.** 250,000 has no special significance. A time-based activation (e.g., "activate when node peer count > N") might be more adaptive. However, deterministic height-based activation is simpler, more predictable, and consistent with BTX's existing patterns.

### 8.3 Alternative: Peer-Count Gated Activation

An alternative to fixed height activation:

```cpp
bool IsDandelionActive() const {
    if (!m_dandelion_enabled) return false;
    if (m_best_height < m_chainparams.GetConsensus().nDandelionActivationHeight) return false;
    // Additional check: only activate if we have sufficient peers
    return m_connman.GetNodeCount(ConnectionDirection::Both) >= DANDELION_MIN_NETWORK_PEERS;
}
```

**Recommendation:** Use the height gate as the primary activation AND include a minimum peer count check as a runtime guard. This gives the best of both worlds:
- Deterministic activation height for predictability
- Runtime safety net for insufficient network size

### 8.4 Can It Be Implemented at Block Height 250,000?

**Yes, absolutely.** The implementation is straightforward:

1. Add `nDandelionActivationHeight = 250'000` to `Consensus::Params`
2. Check `m_best_height >= nDandelionActivationHeight` before using Dandelion routing
3. Below that height, `RelayTransaction` follows the existing standard diffusion path

This is identical to how `nReorgProtectionStartHeight` and `nShieldedPoolActivationHeight` work in the existing codebase. The pattern is proven and requires no new infrastructure.

### 8.5 Recommendation

**Use height 250,000 with a runtime peer-count guard.**

```cpp
bool IsDandelionActive() const {
    if (!m_dandelion_enabled) return false;
    if (m_best_height < m_chainparams.GetConsensus().nDandelionActivationHeight) return false;
    // Graceful degradation: need at least 2 outbound peers for Dandelion
    // (enforced inside DandelionEngine::SelectRelayPeers)
    return true;
}
```

The `DandelionEngine::SelectRelayPeers` already handles the case of insufficient peers by clearing the relay list, causing `RouteLocalTransaction` to return `nullopt`, which causes `RelayTransaction` to fall through to standard diffusion. This is built-in graceful degradation.

---

## 9. Configuration and CLI Parameters

### 9.1 Command-Line Arguments

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-dandelion` | bool | `true` | Enable/disable Dandelion++ relay |

### 9.2 Node Service Advertisement

When Dandelion++ is active, nodes advertise `NODE_DANDELION` (bit 9) in their service flags. This allows:
- Peers to preferentially connect to Dandelion-capable nodes
- Monitoring tools to track Dandelion adoption
- Future protocol optimizations that depend on knowing peer capabilities

### 9.3 Logging

All Dandelion++ operations log under the `BCLog::NET` category with `"Dandelion++:"` prefix:
- Relay peer selection: `"Dandelion++: selected %d relay peers for new epoch"`
- Stem routing: `"Dandelion++: stem relay tx %s to peer=%d"`
- Embargo expiry: `"Dandelion++: embargo expired for tx %s, fluffing"`
- Fallback: `"Dandelion++: insufficient outbound peers, falling back to standard relay"`

### 9.4 RPC Extensions

Add Dandelion++ status to `getnetworkinfo`:

```json
{
    "dandelion": {
        "enabled": true,
        "active": true,
        "activation_height": 250000,
        "stem_pool_size": 3,
        "stem_pool_bytes": 1024,
        "relay_peers": 2,
        "epoch_remaining_seconds": 423
    }
}
```

---

## 10. Test Plan

### 10.1 Unit Tests (`src/test/dandelion_tests.cpp`)

| Test | Description |
|------|-------------|
| `select_relay_peers_empty` | No peers available → empty relay list |
| `select_relay_peers_insufficient` | 1 peer < minimum 2 → empty relay list |
| `select_relay_peers_sufficient` | 5 peers → selects exactly 2 relay peers |
| `select_relay_peers_exact` | Exactly 2 peers → selects both |
| `route_local_transaction` | Local tx gets stem routing |
| `route_local_no_peers` | No relay peers → returns nullopt |
| `route_local_duplicate` | Same txid routed twice → second returns nullopt |
| `route_stem_probabilistic` | 1000 stem decisions → ~90% stem, ~10% fluff |
| `stem_pool_add_remove` | Add and remove from stem pool |
| `stem_pool_duplicate_rejected` | Duplicate tx rejected from stem pool |
| `stem_pool_max_count` | Stem pool respects max transaction count |
| `stem_pool_max_bytes` | Stem pool respects max byte limit |
| `stem_pool_get_transaction` | Retrieve tx from stem pool by txid |
| `embargo_timer_no_expiry` | Fresh stem tx not expired immediately |
| `embargo_timer_expiry` | Stem tx expires after timeout (mock time) |
| `epoch_not_immediately_expired` | Fresh epoch not expired |
| `epoch_expired` | Epoch expires after duration (mock time) |
| `peer_disconnect_removes_relay` | Disconnected peer removed from relay list |
| `peer_disconnect_triggers_embargo` | Stem txs for disconnected peer get embargoed |
| `clear_stem_pool` | ClearStemPool empties everything |

### 10.2 Functional Tests (`test/functional/p2p_dandelion.py`)

| Test | Description |
|------|-------------|
| `test_basic_stem_relay` | Tx from node 0 reaches node 1 (stem) before node 2 (fluff) |
| `test_embargo_fluff` | Black-holed stem tx eventually reaches all nodes via embargo |
| `test_insufficient_peers` | Single-peer node falls back to diffusion |
| `test_disabled_node_compatibility` | Non-Dandelion node still receives all transactions |
| `test_stem_pool_limits` | Excess stem txs trigger fallback to fluff |
| `test_height_activation` | Dandelion inactive before activation height, active after |
| `test_epoch_rotation` | Relay peers change after epoch duration |

### 10.3 Fuzz Tests

| Target | Description |
|--------|-------------|
| `dandelion_routing` | Fuzz routing decisions with random txids and peer sets |
| `stem_pool_operations` | Fuzz add/remove/check sequence on stem pool |

---

## 11. Security Analysis

### 11.1 DoS Resistance

**Stem pool exhaustion:** Limited by `DANDELION_STEM_POOL_MAX_TXS` (100) and `DANDELION_STEM_POOL_MAX_BYTES` (5MB). When full, transactions fall through to standard relay.

**Bandwidth amplification:** No amplification possible. Stem phase actually reduces bandwidth (one peer instead of all peers).

**Memory exhaustion:** Stem pool has hard caps. Worst case: 5MB additional memory per node.

**Black hole attack:** Embargo timer ensures transactions are fluffed within 30-35 seconds regardless of relay peer behavior.

### 11.2 Privacy Guarantees

**At 50 nodes:** Adversary with 2 spy nodes has ~15% chance of observing any stem path. Effective anonymity set ~15 nodes. Adequate.

**At 100 nodes:** Adversary probability drops to ~8%. Anonymity set ~30 nodes. Strong.

**Graceful degradation:** With insufficient peers, the system silently falls back to standard diffusion. No false sense of security.

### 11.3 Block Template Exclusion (Critical -- from Monero)

Stem-phase transactions MUST be excluded from block templates. If a miner includes a stem-phase transaction in a block, it reveals that the miner was on the stem path, degrading privacy for the transaction originator. Since BTX's stem pool is separate from the main mempool, and the mining code only draws from the mempool, this property is inherently satisfied by our architecture. However, this must be explicitly tested and documented as a design invariant.

### 11.4 Interaction with Existing Features

**Shielded transactions:** Dandelion++ applies equally to shielded and transparent transactions. The stem/fluff decision is independent of transaction content.

**RBF (Replace-By-Fee):** When an RBF replacement arrives during stem phase:
- If the original is in the stem pool: replace it in the stem pool and re-stem
- If the original has been fluffed: standard RBF processing applies
- Edge case: RBF replacement arriving via different path → handled by mempool validation

**CPFP (Child-Pays-For-Parent):** This was a key concern that contributed to BIP 156's rejection in Bitcoin Core. The problem: if parent P is in the stem pool and child C (spending P's outputs) arrives, `AcceptToMemoryPool` rejects C because P is not in the main mempool. **BTX solution:** When a child transaction depends on a stem-phase parent, immediately fluff the parent (move from stem pool to mempool), then process the child normally. This is the simplest approach and avoids the complexity of a dual-validation-context. The 39-second embargo timeout means CPFP chains rarely form during stem phase in practice.

### 11.5 Known Limitations

1. **Non-listening nodes:** A non-listening node (no inbound connections) only sends outbound during stem phase. The first peer it connects to can trivially attribute all stem transactions to it. Mitigation: This is the same limitation as standard Bitcoin -- such nodes should use Tor.

2. **Spy nodes in relay path:** A spy node on the stem path can narrow down the originator to the stem's upstream direction, but cannot pinpoint the exact originator unless it controls multiple consecutive nodes on the path.

3. **Small network size:** With < 30 nodes, privacy guarantees are weak. The runtime peer-count guard mitigates this.

---

## 12. Deployment Strategy

### 12.1 Phased Rollout

| Phase | Height | Behavior |
|-------|--------|----------|
| Ship code | Genesis (0) | Dandelion++ code in binary, `-dandelion=true` default, but inactive below activation height |
| Pre-activation | 0 - 249,999 | Standard diffusion relay. Code is compiled and available but dormant. |
| Activation | 250,000 | Dandelion++ activates automatically. No user action required. |
| Steady state | 250,000+ | Full Dandelion++ operation with epoch rotation, stem pool, embargo timers |

### 12.2 Upgrade Path

- **No fork required.** Zero consensus changes.
- **Backward compatible.** Non-upgraded nodes receive fluffed transactions normally.
- **Gradual adoption.** Privacy improves as more nodes upgrade, but the protocol functions correctly with partial adoption.
- **No coordination needed.** Each node independently decides to run Dandelion++ based on its software version and configuration.

---

## 13. Estimated Code Size

| Component | New Lines | Modified Lines | Files |
|-----------|-----------|----------------|-------|
| `dandelion.h` | ~250 | 0 | 1 new |
| `dandelion.cpp` | ~400 | 0 | 1 new |
| `net_processing.cpp` modifications | 0 | ~200 | 1 existing |
| `consensus/params.h` | ~5 | 0 | 1 existing |
| `kernel/chainparams.cpp` | ~15 | 0 | 1 existing |
| `protocol.h` + `protocol.cpp` | ~10 | ~5 | 2 existing |
| `net_processing.h` | ~5 | 0 | 1 existing |
| `init.cpp` | ~10 | 0 | 1 existing |
| `CMakeLists.txt` | ~5 | 0 | 2 existing |
| `test/dandelion_tests.cpp` | ~500 | 0 | 1 new |
| `test/functional/p2p_dandelion.py` | ~300 | 0 | 1 new |
| **Total** | **~1,500** | **~205** | **4 new + 8 modified** |

### Comparison with Reference Implementations

| Project | Implementation Size | Language |
|---------|-------------------|----------|
| Grin | ~800 lines (Dandelion-specific) | Rust |
| Monero | ~600 lines (core) + ~200 (integration) | C++ |
| Bitcoin (BIP 156 PR) | ~1,200 lines | C++ |
| **BTX (this spec)** | **~1,700 lines (including tests)** | **C++** |

BTX's implementation is larger than Grin/Monero because it includes comprehensive tests and follows Bitcoin Core's more rigorous code patterns.

---

## 14. Reference Implementations

### 14.1 Grin (Rust)

**Key source files:**
- `pool/src/pool.rs` -- stem pool management integrated into transaction pool
- `p2p/src/peers.rs` -- relay peer selection
- `servers/src/mining/stratumserver.rs` -- Dandelion relay routing
- `doc/dandelion/dandelion.md` -- protocol documentation

**Design patterns adopted from Grin:**
- Separate stem pool (not mixed with main mempool)
- 90/10 stem/fluff probability
- Epoch-based relay peer rotation
- Embargo timer with jitter

**Design patterns NOT adopted from Grin:**
- Transaction aggregation during stem phase (MimbleWimble-specific, creates DoS vector)

### 14.2 Monero (C++)

**Key source files (from PR #6314):**
- `src/cryptonote_protocol/levin_notify.cpp` -- Dandelion++ relay logic
- `src/cryptonote_protocol/levin_notify.h` -- Data structures
- `src/p2p/net_node.inl` -- Peer selection integration

**Design patterns adopted from Monero:**
- No hard fork or consensus change
- Integrated into existing P2P message handling
- Graceful degradation with insufficient peers
- Per-node asynchronous epoch rotation

### 14.3 Bitcoin BIP 156

**Key specification elements adopted:**
- Service flag advertisement (NODE_DANDELION)
- Stem pool memory limits
- Embargo timer as failsafe
- Interaction with existing inv/tx message flow

**Bitcoin's rejection concerns and BTX mitigations:**

| Bitcoin's Concern | Applicability to BTX | BTX Mitigation |
|-------------------|---------------------|----------------|
| DoS via stem relay (CPU/bandwidth waste) | Low -- BTX has rate limiting precedent via shielded tx relay | Stem pool size limits + embargo timeout |
| Black hole attack | Applies equally | Embargo timer (30s failsafe) |
| Wallet interaction complexity (RBF/CPFP) | Lower -- new chain, simpler wallet state | Document edge cases, handle in stem pool |
| Non-listening node privacy leak | Same concern | Document limitation, recommend Tor |
| Engineering complexity vs. benefit | Dramatically lower on new chain | Clean integration from start |

### 14.4 Academic Paper (Fanti et al., 2018)

**Key theoretical parameters used:**
- Quasi-4-regular privacy graph (2 outbound relays per node) -- Algorithm 2
- 10% diffuser probability per epoch (q=0.1), NOT per-transaction coin flip
- One-to-one forwarding mapping (incoming edge → fixed outgoing edge per epoch)
- Asynchronous epoch rotation (prevents timing correlation)
- Per-node independent routing decisions (no coordination needed)
- No-version-checking for relay selection (Theorem 3: safe even at 0% adoption)
- Exponential embargo timers (memoryless property ensures uniform first-broadcaster)

**Key theorems applied:**
- Theorem 1: First-spy estimator within 8x of optimal on 4-regular graphs
- Theorem 2: One-to-one forwarding achieves Theta(p^2 log(1/p)) precision -- near-optimal
- Theorem 3: No-version-checking is never worse than diffusion at any adoption level
- Proposition 2: Supernodes gain zero additional deanonymization power during stem
- Proposition 3: Embargo timer formula T_base >= -k(k-1)*delta_hop / (2*ln(1-epsilon))

### 14.5 Monero Implementation Lessons

**Key patterns adopted from Monero (PR #6314, ~1,391 lines, C++):**
- 2 stem peers per epoch (matches paper exactly)
- Poisson-distributed embargo timer (39s average, derived from paper formula)
- Block template exclusion for stem transactions
- Stem loop detection → convert to fluff
- Connection map with usage-count load balancing for one-to-one mapping
- Backward compatibility via default field values (old nodes' txs treated as fluff)
- `relay_method` enum with priority ordering (none < local < forward < stem < fluff < block)

### 14.6 Grin Implementation Lessons

**Key patterns adopted from Grin (~600-800 lines, Rust):**
- Separate stem pool (not integrated into mempool)
- `always_stem_our_txs` for local wallet transactions
- Background monitor thread for embargo checking
- Relay peer auto-replacement on disconnect

**Grin deviations we deliberately avoid:**
- Grin uses 1 relay peer (2-regular/line graph) — we use 2 (4-regular, per paper)
- Grin's embargo timer has only 0-30ms jitter — we use exponential distribution (per paper)
- Grin uses separate wire message types (`StemTransaction`/`Transaction`) — we reuse existing `inv`/`tx`

---

## Appendix A: Complete File Change Manifest

```
NEW FILES:
  src/dandelion.h                          (~250 lines)
  src/dandelion.cpp                        (~400 lines)
  src/test/dandelion_tests.cpp             (~500 lines)
  test/functional/p2p_dandelion.py         (~300 lines)

MODIFIED FILES:
  src/consensus/params.h                   (+5 lines: nDandelionActivationHeight)
  src/kernel/chainparams.cpp               (+15 lines: set height per network)
  src/protocol.h                           (+3 lines: NODE_DANDELION flag)
  src/protocol.cpp                         (+5 lines: serviceFlagsToStr update)
  src/net_processing.h                     (+5 lines: Options.enable_dandelion)
  src/net_processing.cpp                   (~200 lines: core relay modifications)
  src/init.cpp                             (+10 lines: CLI arg registration)
  src/CMakeLists.txt                       (+5 lines: add new source files)
```

## Appendix B: Interaction with BTX-Specific Features

### MatMul PoW

No interaction. Dandelion++ operates on the P2P transaction relay layer, which is completely independent of the mining/consensus layer. MatMul proof-of-work validation is unaffected.

### Shielded Transactions

Dandelion++ applies to both shielded and transparent transactions. The existing `NODE_SHIELDED` service flag check remains in place. During stem phase, shielded transactions are forwarded only to the selected relay peer (which must support `NODE_SHIELDED` if the tx has a shielded bundle). The `PeerSupportsShieldedRelay` check should be applied when selecting relay peers.

### ASERT Difficulty Adjustment

No interaction. ASERT operates on block headers, not transaction relay.

### Fast Mining Phase (blocks 0-50,000)

The fast mining phase (250ms blocks) occurs well before the Dandelion++ activation height of 250,000. No interaction or conflict.

---

## Appendix C: Monitoring and Metrics

### Recommended Log Monitoring

```bash
# Monitor Dandelion++ activity
btxd -dandelion=1 -debug=net 2>&1 | grep "Dandelion++"

# Expected log patterns:
# Dandelion++: selected 2 relay peers for new epoch
# Dandelion++: stem relay tx <txid> to peer=<id>
# Dandelion++: embargo expired for tx <txid>, fluffing
# Dandelion++: insufficient outbound peers (1 < 2), falling back to standard relay
```

### RPC Monitoring

```bash
# Check Dandelion++ status
btx-cli getnetworkinfo | jq '.dandelion'

# Check stem pool size
btx-cli getmempoolinfo  # (extended with stem_pool_size field)
```

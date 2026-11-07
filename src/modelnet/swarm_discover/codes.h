// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DISCOVER_CODES_H
#define BITCOIN_MODELNET_SWARM_DISCOVER_CODES_H

namespace modelnet {

/** An empty peer, scope, or endpoint, or a grant of an unknown peer. Nothing is stored. */
inline constexpr char kSwarmDiscoverPeer[] = "PEER";

/** The scope is not one of the four names, or it does not match the offered scope. */
inline constexpr char kSwarmDiscoverScope[] = "SCOPE";

/** now_ms is greater than or equal to until_ms. Nothing is stored. */
inline constexpr char kSwarmDiscoverExpired[] = "EXPIRED";

/** This peer was already offered. The first offer stays. */
inline constexpr char kSwarmDiscoverReplay[] = "REPLAY";

/** The peer is unknown or not granted. connected() is not set. */
inline constexpr char kSwarmDiscoverNotAuthorized[] = "NOT_AUTHORIZED";

/** Scan is refused. Discovery is not a network scan. Nothing is stored. */
inline constexpr char kSwarmDiscoverNotScan[] = "NOT_SCAN";

/** The object id or the grant id is empty. Nothing is stored. */
inline constexpr char kSwarmDiscoverRoute[] = "ROUTE";

/** The rtt is negative, or a same-grant rtt is not strictly lower. The stored route stays. */
inline constexpr char kSwarmDiscoverRtt[] = "RTT";

/** Partition status when the caller reports the peer is not reachable. */
inline constexpr char kSwarmDiscoverPartition[] = "PARTITION";

/** Partition status when the caller reports the peer is reachable. */
inline constexpr char kSwarmDiscoverLocal[] = "LOCAL";

/** Scope name. */
inline constexpr char kSwarmDiscoverLan[] = "lan";

/** Scope name. */
inline constexpr char kSwarmDiscoverWan[] = "wan";

/** Scope name. */
inline constexpr char kSwarmDiscoverPrivate[] = "private";

/** Scope name. */
inline constexpr char kSwarmDiscoverPublic[] = "public";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DISCOVER_CODES_H

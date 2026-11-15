// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_READFENCE_CODES_H
#define BITCOIN_MODELNET_SWARM_READFENCE_CODES_H

namespace modelnet {

/** Empty page or family, or a read of a page that was not placed. Nothing is stored. */
inline constexpr char kSwarmReadPage[] = "PAGE";

/**
 * The engine is missing.
 * Probe of present false, or of a name outside the known set, leaves the
 * engine status unchanged. Prefetch while the status is not INSTALLED
 * records nothing.
 */
inline constexpr char kSwarmReadEngineAbsent[] = "ENGINE_ABSENT";

/** Engine status after Probe of a known name with present true. */
inline constexpr char kSwarmReadInstalled[] = "INSTALLED";

/** Empty member. Revoke stores nothing. Read records nothing. */
inline constexpr char kSwarmReadMember[] = "MEMBER";

/** Revoke of a member who is already revoked. The roster stays. */
inline constexpr char kSwarmReadReplay[] = "REPLAY";

/** Read by a revoked member. The read is not recorded. */
inline constexpr char kSwarmReadNotRead[] = "NOT_READ";

/** Accept size is not in (0, 33554432]. Nothing is stored. */
inline constexpr char kSwarmReadTruncated[] = "TRUNCATED";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_READFENCE_CODES_H

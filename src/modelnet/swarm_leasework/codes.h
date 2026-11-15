// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LEASEWORK_CODES_H
#define BITCOIN_MODELNET_SWARM_LEASEWORK_CODES_H

namespace modelnet {

/** Empty task or worker, or a task or worker that was never stored. */
inline constexpr char kLeaseWorkTask[] = "TASK";

/** now_ms or until_ms is below 0. Nothing is stored. */
inline constexpr char kLeaseWorkRange[] = "RANGE";

/** until_ms is before now_ms, or a worker's stored grants are all past the clock. */
inline constexpr char kLeaseWorkExpired[] = "EXPIRED";

/** The task, the hash, or the leader is already stored. The first value stays. */
inline constexpr char kLeaseWorkReplay[] = "REPLAY";

/** Commit epoch is not the current epoch. The hash is not stored. */
inline constexpr char kLeaseWorkStaleEpoch[] = "STALE_EPOCH";

/** Result hash is empty. Nothing is stored. */
inline constexpr char kLeaseWorkHash[] = "HASH";

/** Result hash differs from the hash already stored. The first hash stays. */
inline constexpr char kLeaseWorkConflict[] = "CONFLICT";

/** This epoch has no leader right to commit. The hash is not stored. */
inline constexpr char kLeaseWorkLeader[] = "LEADER";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LEASEWORK_CODES_H

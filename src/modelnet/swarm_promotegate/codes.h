// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PROMOTEGATE_CODES_H
#define BITCOIN_MODELNET_SWARM_PROMOTEGATE_CODES_H

namespace modelnet {

/** Empty candidate. The staged slot is left unchanged. */
inline constexpr char kSwarmPromoteHead[] = "HEAD";

/**
 * No staged promotion to mark, finish, or resume.
 * Interrupt stores nothing. Finish and resume do not adopt.
 */
inline constexpr char kSwarmPromoteStep[] = "STEP";

/**
 * The staged promotion is interrupted.
 * Finish and resume do not adopt and do not clear the staged id.
 */
inline constexpr char kSwarmPromoteInterrupted[] = "INTERRUPTED";

/** Rollback found no remembered previous id. The active id stays. */
inline constexpr char kSwarmPromoteRollback[] = "ROLLBACK";

/** Realm promotion is refused. The active id stays. */
inline constexpr char kSwarmPromoteRealm[] = "REALM";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PROMOTEGATE_CODES_H

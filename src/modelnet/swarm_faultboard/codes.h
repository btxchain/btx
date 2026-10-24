// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAULTBOARD_CODES_H
#define BITCOIN_MODELNET_SWARM_FAULTBOARD_CODES_H

namespace modelnet {

/** A claim or an earned row is still stored. Nothing is deleted. */
inline constexpr char kSwarmFaultDurable[] = "DURABLE";

/** No claim is stored, or neither a claim nor an earned row is stored. */
inline constexpr char kSwarmFaultLost[] = "LOST";

/** new_epoch is not greater than old_epoch. The stored epoch stays. */
inline constexpr char kSwarmFaultStaleEpoch[] = "STALE_EPOCH";

/** The resume epoch is below current. Nothing is committed. */
inline constexpr char kSwarmFaultStale[] = "STALE";

/** Checkpoint publication did not save. The stored checkpoint id stays. */
inline constexpr char kSwarmFaultSaveHeld[] = "SAVE_HELD";

/** The worker is disconnected. A stored result stays. Nothing is deleted. */
inline constexpr char kSwarmFaultDisconnected[] = "DISCONNECTED";

/** DuplicateReceipt repeated the stored receipt. The first receipt stays. */
inline constexpr char kSwarmFaultReplay[] = "REPLAY";

/** A second value disagrees with the stored one. The first stays. */
inline constexpr char kSwarmFaultConflict[] = "CONFLICT";

/** DuplicateReceipt names a task that has no stored result. */
inline constexpr char kSwarmFaultTask[] = "TASK";

/** The row or cache is held. Nothing is paid and no bytes move. */
inline constexpr char kSwarmFaultHeld[] = "HELD";

/** The cache is truncated. bytes_moved() stays 0. */
inline constexpr char kSwarmFaultIncomplete[] = "INCOMPLETE";

/** A piece is partial. bytes_moved() stays 0. */
inline constexpr char kSwarmFaultPiece[] = "PIECE";

/** Promotion did not graduate. The active head stays. */
inline constexpr char kSwarmFaultNotGraduated[] = "NOT_GRADUATED";

/** CanaryRegress was given an empty previous head. Nothing is rolled back. */
inline constexpr char kSwarmFaultNotStaged[] = "NOT_STAGED";

/** The active head was set back to previous and a rollback was appended. */
inline constexpr char kSwarmFaultRollback[] = "ROLLBACK";

/** Reports conflict. Nothing is averaged and qualified() stays false. */
inline constexpr char kSwarmFaultNotAveraged[] = "NOT_AVERAGED";

/** A mature refund must not broadcast. broadcast() stays false. */
inline constexpr char kSwarmFaultBroadcastForbidden[] = "BROADCAST_FORBIDDEN";

/** Reorg froze the plane. Earned rows stay. */
inline constexpr char kSwarmFaultFreeze[] = "FREEZE";

/** Reserve after Reorg. Nothing is stored. */
inline constexpr char kSwarmFaultFrozen[] = "FROZEN";

/** A reservation is already stored. A second one is not added. */
inline constexpr char kSwarmFaultCollateralReuse[] = "COLLATERAL_REUSE";

/** Collateral or reserve amount is below 1. Nothing is stored. */
inline constexpr char kSwarmFaultCollateral[] = "COLLATERAL";

/** A revoked read is refused. bytes_moved() stays 0. */
inline constexpr char kSwarmFaultNotRead[] = "NOT_READ";

/** The dataset is withdrawn. running() stays false. */
inline constexpr char kSwarmFaultDataset[] = "DATASET";

/** The family is not compatible. admitted() stays false. */
inline constexpr char kSwarmFaultFamilyNotCompat[] = "FAMILY_NOT_COMPAT";

/** KeepEarned atoms are below 0. Nothing is stored. */
inline constexpr char kSwarmFaultAtoms[] = "ATOMS";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAULTBOARD_CODES_H

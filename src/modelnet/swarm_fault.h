// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULT_H
#define BTX_MODELNET_SWARM_FAULT_H

#include <string>

namespace modelnet {

enum class SwarmFaultKind {
    CoordinatorGone,
    StaleEpoch,
    TruncatedCache,
    PartialPiece,
    CollateralReuse,
    RevokedCache,
    FalseCompatibility
};

/**
 * A code for one caller-supplied fault. recovered is a flag.
 * stale_committed stays false. bytes_moved stays false.
 * This function does not inject a fault and does not move bytes.
 */
struct SwarmFaultOutcome {
    bool recovered{false};
    bool stale_committed{false};
    bool bytes_moved{false};
    std::string code;
};

/**
 * stale_epoch, or kind StaleEpoch, is STALE_EPOCH. A stale leader commits nothing.
 * CoordinatorGone with a durable claim is DURABLE and clears err.
 * CoordinatorGone without a durable claim is LOST.
 * TruncatedCache is INCOMPLETE. PartialPiece is PIECE.
 * CollateralReuse is COLLATERAL_REUSE. RevokedCache is REVOKED.
 * FalseCompatibility is FAMILY_NOT_COMPAT.
 */
SwarmFaultOutcome SwarmRecoverFault(SwarmFaultKind kind, bool durable_claim, bool stale_epoch, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULT_H

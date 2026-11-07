// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOCOLLATERAL2_H
#define BTX_MODELNET_SWARM_NOTNOCOLLATERAL2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one collateral. reused marks the collateral as
 * already used. want_book asks this note to book it.
 *
 * Reused collateral is not booked again.
 * booked stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoCollateral2 {
    std::string collateral_id;
    bool reused{false};
    bool want_book{false};
};

/**
 * Outcome of noting collateral. booked stays false and atoms stays 0 on
 * every path: reused collateral is not booked again.
 */
struct SwarmNotNoCollateral2Result {
    std::string code;
    bool booked{false};
    int64_t atoms{0};
};

/**
 * Note collateral without booking it again.
 * Order, first match wins: an empty collateral_id is COLLATERAL.
 * If reused is true, the note is SAME_ATOMS even when want_book is false.
 * want_book is HELD. Otherwise the note is NOTED and err is cleared.
 * booked stays false and atoms stays 0 on every path. Reused collateral
 * is not booked again.
 */
SwarmNotNoCollateral2Result SwarmNoteNotNoCollateral2(const SwarmNotNoCollateral2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOCOLLATERAL2_H

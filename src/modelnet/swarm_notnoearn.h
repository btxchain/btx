// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOEARN_H
#define BTX_MODELNET_SWARM_NOTNOEARN_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one receipt. settled marks the receipt as settled.
 * want_earn asks this note to record earnings.
 *
 * Earnings are not recorded before settlement and nothing is paid.
 * earned stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoEarn {
    std::string receipt_id;
    bool settled{false};
    bool want_earn{false};
};

/**
 * Outcome of noting a receipt. earned stays false and atoms stays 0 on
 * every path. Earnings are not recorded before settlement and nothing is
 * paid.
 */
struct SwarmNotNoEarnResult {
    std::string code;
    bool earned{false};
    int64_t atoms{0};
};

/**
 * Note a receipt without recording earnings or paying. Order, first match
 * wins: an empty receipt_id is RECEIPT. If settled is false, the note is
 * BEFORE_SETTLEMENT, even when want_earn is false. want_earn is HELD.
 * Otherwise the note is NOTED and err is cleared. earned stays false and
 * atoms stays 0 on every path. Earnings are not recorded before settlement
 * and nothing is paid.
 */
SwarmNotNoEarnResult SwarmNoteNotNoEarn(const SwarmNotNoEarn& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOEARN_H

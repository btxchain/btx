// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PROFIT_H
#define BTX_MODELNET_SWARM_PROFIT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A note that a profit-share instrument was seen. Noting it does not move
 * atoms and does not broadcast.
 */
struct SwarmProfitShare {
    std::string instrument_id;
    int64_t atoms{0};
    bool profit_share{false};
};

/**
 * Outcome of noting a profit share. accepted is always false: this note
 * does not move atoms and does not broadcast.
 */
struct SwarmProfitShareResult {
    bool accepted{false};
    std::string code;
};

/**
 * Note a profit share without moving atoms.
 * An empty instrument_id or atoms < 0 yields INSTRUMENT.
 * A profit-share instrument yields PROFIT_REFUSED, even when atoms are positive.
 * Otherwise the note is NOTED and err is cleared.
 * accepted stays false on every return. This function does not move atoms
 * and does not broadcast.
 */
SwarmProfitShareResult SwarmNoteProfitShare(const SwarmProfitShare& share, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PROFIT_H

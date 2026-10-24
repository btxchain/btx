// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOPROFITREF2_H
#define BTX_MODELNET_SWARM_NOTNOPROFITREF2_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one share. want_share asks this note for a profit
 * share.
 *
 * Profit-share is refused. shared stays false and atoms stays 0 on
 * every path.
 */
struct SwarmNotNoProfitRef2 {
    std::string share_id;
    bool want_share{false};
};

/**
 * Outcome of noting a profit-share request. shared stays false and
 * atoms stays 0: this note shares nothing.
 */
struct SwarmNotNoProfitRef2Result {
    std::string code;
    bool shared{false};
    int64_t atoms{0};
};

/**
 * Note a profit-share request without sharing it.
 * Order, first match wins: an empty share_id is SHARE. want_share is
 * HELD. Otherwise the note is NOTED and err is cleared.
 * shared stays false and atoms stays 0 on every path. Profit-share is
 * refused.
 */
SwarmNotNoProfitRef2Result SwarmNoteNotNoProfitRef2(const SwarmNotNoProfitRef2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOPROFITREF2_H

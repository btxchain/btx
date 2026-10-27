// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOAUTOSPENT2_H
#define BTX_MODELNET_SWARM_NOTNOAUTOSPENT2_H

#include <cstdint>
#include <string>

namespace modelnet {

/** A local note. Automatic spend stays zero. */
struct SwarmNotNoAutoSpent2 {
    std::string spend_id;
    bool want_set{false};
};

/** Outcome of noting. armed stays false and atoms stays 0 on every path. */
struct SwarmNotNoAutoSpent2Result {
    std::string code;
    bool armed{false};
    int64_t atoms{0};
};

/**
 * Note without spending. Empty spend_id is SPEND. want_set is HELD.
 * Otherwise the note is NOTED and err is clear. armed stays false and
 * atoms stays 0 on every path. Automatic spend stays zero.
 */
SwarmNotNoAutoSpent2Result SwarmNoteNotNoAutoSpent2(const SwarmNotNoAutoSpent2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOAUTOSPENT2_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOWAN2_H
#define BTX_MODELNET_SWARM_NOTNOWAN2_H

#include <string>

namespace modelnet {

/**
 * A local note about one run. want_average asks this note to average
 * weights across a WAN.
 *
 * A WAN average request averages nothing and moves no bytes.
 * averaged stays false on every path. bytes_moved stays false on every path.
 */
struct SwarmNotNoWan2 {
    std::string run_id;
    bool want_average{false};
};

/**
 * Outcome of noting a WAN average request. averaged stays false and
 * bytes_moved stays false on every path: a WAN average request averages
 * nothing and moves no bytes.
 */
struct SwarmNotNoWan2Result {
    std::string code;
    bool averaged{false};
    bool bytes_moved{false};
};

/**
 * Note a WAN average request without averaging weights or moving bytes.
 * Order, first match wins: an empty run_id is RUN.
 * want_average is NOT_AVERAGED.
 * Otherwise the note is NOTED and err is clear.
 * averaged stays false and bytes_moved stays false on every path.
 */
SwarmNotNoWan2Result SwarmNoteNotNoWan2(const SwarmNotNoWan2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOWAN2_H

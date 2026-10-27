// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNONEG_H
#define BTX_MODELNET_SWARM_NOTNONEG_H

#include <string>

namespace modelnet {

/**
 * A local note about one result. negative marks a negative result.
 * want_drop asks this note to drop the result.
 *
 * dropped and bytes_moved stay false on every path. A negative result
 * stays and is not dropped.
 */
struct SwarmNotNoNeg {
    std::string result_id;
    bool negative{false};
    bool want_drop{false};
};

/**
 * Outcome of noting a result. dropped and bytes_moved stay false on
 * every path. A negative result stays and is not dropped.
 */
struct SwarmNotNoNegResult {
    std::string code;
    bool dropped{false};
    bool bytes_moved{false};
};

/**
 * Note a result without dropping it or moving bytes. Order, first match
 * wins: an empty result_id is RESULT. negative is KEPT even when
 * want_drop is false. want_drop is KEPT. Otherwise the note is NOTED
 * and err is cleared. dropped and bytes_moved stay false on every path.
 * A negative result stays and is not dropped.
 */
SwarmNotNoNegResult SwarmNoteNotNoNeg(const SwarmNotNoNeg& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNONEG_H

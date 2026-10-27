// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNONEGATIVE_H
#define BTX_MODELNET_SWARM_NOTNONEGATIVE_H

#include <string>

namespace modelnet {

/**
 * A local note about one result. negative marks a negative result.
 * want_drop asks this note to drop the result.
 *
 * dropped and trained stay false on every path. A negative result stays
 * on record and is not dropped.
 */
struct SwarmNotNoNegative {
    std::string result_id;
    bool negative{false};
    bool want_drop{false};
};

/**
 * Outcome of noting a result. dropped and trained stay false on every
 * path. A negative result stays on record and is not dropped.
 */
struct SwarmNotNoNegativeResult {
    std::string code;
    bool dropped{false};
    bool trained{false};
};

/**
 * Note a result without dropping or training it. Order, first match
 * wins: an empty result_id is RESULT. negative is KEPT even when
 * want_drop is false. want_drop is KEPT. Otherwise the note is NOTED
 * and err is clear. dropped and trained stay false on every path. A
 * negative result stays on record and is not dropped.
 */
SwarmNotNoNegativeResult SwarmNoteNotNoNegative(const SwarmNotNoNegative& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNONEGATIVE_H

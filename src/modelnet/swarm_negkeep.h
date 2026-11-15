// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NEGKEEP_H
#define BTX_MODELNET_SWARM_NEGKEEP_H

#include <string>

namespace modelnet {

/**
 * A negative-result record.
 *
 * A negative result stays recorded. This record does not hide it or start training.
 * hidden and training stay false on every path.
 */
struct SwarmNegKeep {
    std::string result_id;
    bool negative{false};
    bool want_hide{false};
    bool want_train{false};
};

/**
 * Outcome of keeping a negative result.
 * hidden and training stay false on every path.
 */
struct SwarmNegKeepResult {
    std::string code;
    bool hidden{false};
    bool training{false};
    bool kept{false};
};

/**
 * Keep a negative result without hiding it or starting training.
 * Order, first match wins: an empty result_id is RESULT and kept is false.
 * negative is KEPT and kept is true, even when want_hide is false.
 * want_hide or want_train is HELD and kept is true. Otherwise the record is
 * NOTED, err is cleared, and kept is true.
 * hidden and training stay false on every path.
 * A negative result stays recorded. This record does not hide it or start training.
 */
SwarmNegKeepResult SwarmKeepNegative(const SwarmNegKeep& result, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NEGKEEP_H

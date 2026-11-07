// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_HEADKEEP_H
#define BTX_MODELNET_SWARM_HEADKEEP_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A visible-head record.
 *
 * Visible heads stay visible. A majority vote does not hide or graduate one.
 * hidden and graduated stay false on every path.
 */
struct SwarmHeadKeep {
    std::string head_id;
    int64_t visible{0};
    bool majority{false};
    bool want_hide{false};
    bool want_graduate{false};
};

/**
 * Outcome of keeping a visible head.
 * hidden and graduated stay false on every path.
 */
struct SwarmHeadKeepResult {
    std::string code;
    bool hidden{false};
    bool graduated{false};
    int64_t visible{0};
};

/**
 * Keep a visible head without hiding it or graduating a model.
 * Order, first match wins: an empty head_id is HEAD with visible 0.
 * visible below 1 is EMPTY with visible 0. majority is NOT_HIDDEN and
 * copies visible, even when want_hide is false. want_hide or
 * want_graduate is HELD and copies visible. Otherwise the record is
 * NOTED, err is cleared, and visible is copied.
 * hidden and graduated stay false on every path.
 * Visible heads stay visible. A majority vote does not hide or graduate one.
 */
SwarmHeadKeepResult SwarmKeepHeads(const SwarmHeadKeep& head, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_HEADKEEP_H

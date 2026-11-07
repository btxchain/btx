// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_holdrot/gate.h>

#include <modelnet/swarm_holdrot/blank.h>
#include <modelnet/swarm_holdrot/codes.h>
#include <modelnet/swarm_holdrot/replay.h>

namespace modelnet {

SwarmHoldoutRotateDecision SwarmHoldoutRotateDecide(const SwarmHoldoutRotateBook& book, const std::string& holdout)
{
    std::string err;
    if (!SwarmHoldoutRotateBlank{}.accept(holdout, err)) {
        return SwarmHoldoutRotateDecision{err, false};
    }
    if (SwarmHoldoutRotateIsReplay(book, holdout)) {
        return SwarmHoldoutRotateDecision{std::string{kSwarmHoldoutRotateReplay}, false};
    }
    return SwarmHoldoutRotateDecision{{}, true};
}

} // namespace modelnet

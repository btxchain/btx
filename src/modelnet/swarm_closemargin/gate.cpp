// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_closemargin/gate.h>

#include <modelnet/swarm_closemargin/blank.h>
#include <modelnet/swarm_closemargin/codes.h>
#include <modelnet/swarm_closemargin/replay.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmCloseMarginHoldDecision SwarmCloseMarginHoldDecide(const SwarmCloseMarginHoldBook& book, int64_t blocks)
{
    std::string err;
    if (!SwarmCloseMarginHoldBlank{}.accept(blocks, err)) {
        return SwarmCloseMarginHoldDecision{err, false};
    }
    if (SwarmCloseMarginHoldIsReplay(book, blocks)) {
        return SwarmCloseMarginHoldDecision{std::string{kSwarmCloseMarginHoldReplay}, false};
    }
    return SwarmCloseMarginHoldDecision{{}, true};
}

} // namespace modelnet

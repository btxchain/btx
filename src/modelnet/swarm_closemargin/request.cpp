// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_closemargin/request.h>

#include <modelnet/swarm_closemargin/codes.h>
#include <modelnet/swarm_closemargin/gate.h>
#include <modelnet/swarm_closemargin/stay.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmCloseMarginHoldRequest::Apply(SwarmCloseMarginHoldBook& book, int64_t blocks, std::string& err) const
{
    const SwarmCloseMarginHoldDecision decision = SwarmCloseMarginHoldDecide(book, blocks);
    if (!decision.store) {
        err = decision.code;
        return false;
    }
    if (!book.store(blocks) || !book.contains(blocks)) {
        if (book.contains(blocks)) {
            err = kSwarmCloseMarginHoldReplay;
        } else {
            err = kSwarmCloseMarginHoldMargin;
        }
        return false;
    }
    err = SwarmCloseMarginHoldStay{}.refusal();
    return false;
}

} // namespace modelnet

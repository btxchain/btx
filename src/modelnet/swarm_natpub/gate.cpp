// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_natpub/gate.h>

#include <modelnet/swarm_natpub/blank.h>
#include <modelnet/swarm_natpub/codes.h>
#include <modelnet/swarm_natpub/replay.h>

namespace modelnet {

SwarmNatPubDecision SwarmNatPubDecide(const SwarmNatPubBook& book, const std::string& endpoint)
{
    std::string err;
    if (!SwarmNatPubBlank{}.accept(endpoint, err)) {
        return SwarmNatPubDecision{err, false};
    }
    if (SwarmNatPubIsReplay(book, endpoint)) {
        return SwarmNatPubDecision{std::string{kSwarmNatPubReplay}, false};
    }
    return SwarmNatPubDecision{{}, true};
}

} // namespace modelnet

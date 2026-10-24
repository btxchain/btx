// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_quotefiat/gate.h>

#include <modelnet/swarm_quotefiat/blank.h>
#include <modelnet/swarm_quotefiat/codes.h>
#include <modelnet/swarm_quotefiat/replay.h>

namespace modelnet {

SwarmQuoteFiatDecision SwarmQuoteFiatDecide(const SwarmQuoteFiatBook& book, const std::string& usd)
{
    std::string err;
    if (!SwarmQuoteFiatBlank{}.accept(usd, err)) {
        return SwarmQuoteFiatDecision{err, false};
    }
    if (SwarmQuoteFiatIsReplay(book, usd)) {
        return SwarmQuoteFiatDecision{std::string{kSwarmQuoteFiatReplay}, false};
    }
    return SwarmQuoteFiatDecision{std::string{kSwarmQuoteFiatNotBalance}, true};
}

} // namespace modelnet

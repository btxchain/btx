// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paylabel/gate.h>

#include <modelnet/swarm_paylabel/codes.h>
#include <modelnet/swarm_paylabel/profit.h>
#include <modelnet/swarm_paylabel/replay.h>
#include <modelnet/swarm_paylabel/work.h>

namespace modelnet {

std::string SwarmPayLabelRefusal(const SwarmPayLabelBook& book, const std::string& label)
{
    std::string err;
    if (!SwarmPayLabelProfit{}.accept(label, err)) return err;
    if (!SwarmPayLabelWork{}.accept(label, err)) return err;
    if (SwarmPayLabelIsReplay(book, label)) return std::string{kSwarmPayLabelReplay};
    return {};
}

} // namespace modelnet

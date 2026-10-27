// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paylabel/accept.h>

#include <modelnet/swarm_paylabel/codes.h>
#include <modelnet/swarm_paylabel/gate.h>
#include <modelnet/swarm_paylabel/limits.h>
#include <modelnet/swarm_paylabel/vocabulary.h>

namespace modelnet {

bool SwarmPayLabelAccept::Apply(SwarmPayLabelBook& book, const std::string& label, std::string& err) const
{
    const std::string refusal = SwarmPayLabelRefusal(book, label);
    if (!refusal.empty()) {
        err = refusal;
        return false;
    }
    if (!book.store(label)) {
        if (book.contains(kSwarmPayLabelWork)) {
            err = kSwarmPayLabelReplay;
        } else if (SwarmPayLabelIsProfit(label)) {
            err = kSwarmPayLabelRefused;
        } else {
            err = kSwarmPayLabelLabel;
        }
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet

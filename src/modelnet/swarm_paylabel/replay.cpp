// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_paylabel/replay.h>

#include <modelnet/swarm_paylabel/vocabulary.h>

namespace modelnet {

bool SwarmPayLabelIsReplay(const SwarmPayLabelBook& book, const std::string& label)
{
    if (!SwarmPayLabelIsWork(label)) return false;
    return book.contains(label);
}

} // namespace modelnet

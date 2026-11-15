// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_holdrot/replay.h>

namespace modelnet {

bool SwarmHoldoutRotateIsReplay(const SwarmHoldoutRotateBook& book, const std::string& holdout)
{
    if (holdout.empty()) return false;
    return book.contains(holdout);
}

} // namespace modelnet

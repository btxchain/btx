// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_holdrot/keep.h>

namespace modelnet {

std::string SwarmHoldoutRotateKeep::first(const SwarmHoldoutRotateBook& book, const std::string& holdout) const
{
    if (!book.contains(holdout)) return {};
    return book.holdout_of(holdout);
}

} // namespace modelnet

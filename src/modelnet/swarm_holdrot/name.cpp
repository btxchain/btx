// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_holdrot/name.h>

namespace modelnet {

std::string SwarmHoldoutRotateName::copy(const std::string& holdout) const
{
    if (holdout.empty()) return {};
    return holdout;
}

} // namespace modelnet

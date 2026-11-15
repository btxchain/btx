// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_quotefiat/atoms.h>

namespace modelnet {

int64_t SwarmQuoteFiatAtoms::reported(int64_t stored_sum) const
{
    // Each kept quote is built with zero atoms. Nothing is added here.
    return stored_sum;
}

} // namespace modelnet

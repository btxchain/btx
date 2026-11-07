// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_leasework/silence.h>

namespace modelnet {

int64_t LeaseWorkSilence::bytes_moved() const
{
    return 0;
}

bool LeaseWorkSilence::launched() const
{
    return false;
}

bool LeaseWorkSilence::broadcast() const
{
    return false;
}

} // namespace modelnet

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_reorghold/silence.h>

namespace modelnet {

bool ReorgHoldSilence::broadcast() const
{
    return false;
}

bool ReorgHoldSilence::mined() const
{
    return false;
}

int64_t ReorgHoldSilence::bytes_moved() const
{
    return 0;
}

} // namespace modelnet

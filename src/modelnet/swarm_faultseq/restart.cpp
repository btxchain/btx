// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultseq/restart.h>

namespace modelnet {

bool SwarmFaultSeqCanRestart(bool took_last, bool refused)
{
    return took_last || refused;
}

} // namespace modelnet

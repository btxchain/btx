// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_readfence/accept.h>

#include <modelnet/swarm_readfence/codes.h>

namespace modelnet {

bool SwarmReadAccept::Apply(SwarmReadSpan& span, int64_t size, std::string& err) const
{
    if (!span.Store(size)) {
        err = kSwarmReadTruncated;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet

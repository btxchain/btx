// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nodedefault/sign.h>

#include <modelnet/swarm_nodedefault/codes.h>

namespace modelnet {

bool SwarmNodeDefaultSign::Accept(bool operator_signed, bool research_key, bool scheduler, std::string& err) const
{
    if (research_key || scheduler || !operator_signed) {
        err = kSwarmNodeDefaultNotSigned;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet

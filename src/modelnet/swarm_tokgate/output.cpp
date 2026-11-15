// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tokgate/output.h>

#include <modelnet/swarm_tokgate/limits.h>

#include <cstdint>
#include <string>

namespace modelnet {

const std::string& SwarmTokenGateOutput::text() const
{
    return m_text;
}

int64_t SwarmTokenGateOutput::tokens() const
{
    return kSwarmTokenGateTokens;
}

} // namespace modelnet

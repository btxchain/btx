// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_decode/output.h>

#include <modelnet/swarm_decode/limits.h>

#include <cstdint>
#include <string>

namespace modelnet {

const std::string& SwarmDecodeOutput::text() const
{
    return m_text;
}

int64_t SwarmDecodeOutput::tokens() const
{
    return m_tokens;
}

bool SwarmDecodeOutput::append_byte(char byte)
{
    if (m_tokens < 0) return false;
    if (m_tokens >= kSwarmDecodeMemoryByteCap) return false;
    if (static_cast<uint64_t>(m_tokens) != static_cast<uint64_t>(m_text.size())) return false;
    m_text.push_back(byte);
    m_tokens += int64_t{1};
    return true;
}

} // namespace modelnet

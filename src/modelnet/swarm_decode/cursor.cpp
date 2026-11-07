// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_decode/cursor.h>

#include <modelnet/swarm_decode/limits.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmDecodeCursorKind SwarmDecodeClassifyCursor(const std::string& prompt, int64_t tokens)
{
    if (prompt.empty()) return SwarmDecodeCursorKind::Empty;
    if (tokens < 0) return SwarmDecodeCursorKind::Done;
    if (tokens >= kSwarmDecodeMemoryByteCap) return SwarmDecodeCursorKind::Done;
    if (static_cast<uint64_t>(tokens) >= static_cast<uint64_t>(prompt.size())) {
        return SwarmDecodeCursorKind::Done;
    }
    return SwarmDecodeCursorKind::Next;
}

} // namespace modelnet

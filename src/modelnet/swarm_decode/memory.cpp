// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_decode/memory.h>

#include <modelnet/swarm_decode/codes.h>
#include <modelnet/swarm_decode/cursor.h>
#include <modelnet/swarm_decode/output.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmDecodeMemoryPull(const std::string& prompt, SwarmDecodeOutput& output, std::string& err)
{
    const int64_t cursor = output.tokens();
    const SwarmDecodeCursorKind kind = SwarmDecodeClassifyCursor(prompt, cursor);
    if (kind == SwarmDecodeCursorKind::Empty) {
        err = kSwarmDecodePrompt;
        return false;
    }
    if (kind != SwarmDecodeCursorKind::Next) {
        err = kSwarmDecodeDone;
        return false;
    }
    if (cursor < 0) {
        err = kSwarmDecodeDone;
        return false;
    }
    const std::size_t index = static_cast<std::size_t>(cursor);
    if (index >= prompt.size()) {
        err = kSwarmDecodeDone;
        return false;
    }
    const char next = prompt[index];
    if (!output.append_byte(next)) {
        err = kSwarmDecodeDone;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet

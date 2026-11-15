// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cursorfence/hash.h>

namespace modelnet {

bool SwarmCursorFenceHashEmpty(const std::string& hash)
{
    return hash.empty();
}

SwarmCursorFenceHashKind SwarmCursorFenceClassifyHash(bool have_hash, const std::string& stored, const std::string& next)
{
    if (!have_hash) return SwarmCursorFenceHashKind::Store;
    if (stored == next) return SwarmCursorFenceHashKind::Replay;
    return SwarmCursorFenceHashKind::Conflict;
}

} // namespace modelnet

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_leasework/hash.h>

namespace modelnet {

LeaseWorkHashKind LeaseWorkClassifyHash(bool have_hash, const std::string& stored, const std::string& next)
{
    if (!have_hash) return LeaseWorkHashKind::Store;
    if (stored == next) return LeaseWorkHashKind::Replay;
    return LeaseWorkHashKind::Conflict;
}

} // namespace modelnet

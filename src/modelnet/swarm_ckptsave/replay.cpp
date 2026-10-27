// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckptsave/replay.h>

namespace modelnet {

bool SwarmCkptSaveIsReplay(const SwarmCkptSaveBook& book, const std::string& name)
{
    if (name.empty()) return false;
    return book.contains(name);
}

} // namespace modelnet

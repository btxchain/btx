// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckptsave/gate.h>

#include <modelnet/swarm_ckptsave/blank.h>
#include <modelnet/swarm_ckptsave/codes.h>
#include <modelnet/swarm_ckptsave/replay.h>

namespace modelnet {

SwarmCkptSaveDecision SwarmCkptSaveDecide(const SwarmCkptSaveBook& book, const std::string& name)
{
    std::string err;
    if (!SwarmCkptSaveBlank{}.accept(name, err)) {
        return SwarmCkptSaveDecision{err, false};
    }
    if (SwarmCkptSaveIsReplay(book, name)) {
        return SwarmCkptSaveDecision{std::string{kSwarmCkptSaveReplay}, false};
    }
    return SwarmCkptSaveDecision{{}, true};
}

} // namespace modelnet

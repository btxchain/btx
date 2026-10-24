// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckptsave/request.h>

#include <modelnet/swarm_ckptsave/codes.h>
#include <modelnet/swarm_ckptsave/gate.h>
#include <modelnet/swarm_ckptsave/stay.h>

namespace modelnet {

bool SwarmCkptSaveRequest::Apply(SwarmCkptSaveBook& book, const std::string& name, std::string& err) const
{
    const SwarmCkptSaveDecision decision = SwarmCkptSaveDecide(book, name);
    if (!decision.store) {
        err = decision.code;
        return false;
    }
    if (!book.store(name) || !book.contains(name)) {
        if (book.contains(name)) {
            err = kSwarmCkptSaveReplay;
        } else {
            err = kSwarmCkptSaveCheckpoint;
        }
        return false;
    }
    err = SwarmCkptSaveStay{}.refusal();
    return false;
}

} // namespace modelnet

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_reorghold/reorg.h>

#include <modelnet/swarm_reorghold/codes.h>
#include <modelnet/swarm_reorghold/snapshot.h>

#include <limits>

namespace modelnet {

bool ReorgHoldReorg(ReorgHoldBook& book, std::string& err)
{
    if (book.reorged()) {
        err = kReorgHoldReplay;
        return false;
    }
    if (book.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        err = kReorgHoldChannel;
        return false;
    }
    int64_t recorded = 0;
    if (!book.Sum(recorded) || recorded != book.earned()) {
        err = kReorgHoldAtoms;
        return false;
    }
    SwarmRecoverySnapshot exited;
    if (!ReorgHoldReorgMatches(book.earned(), static_cast<int>(book.size()), exited)) {
        err = exited.earned_atoms == book.earned() ? kReorgHoldOpen : kReorgHoldAtoms;
        return false;
    }
    if (!book.AcceptEarned(exited.earned_atoms)) {
        err = kReorgHoldAtoms;
        return false;
    }
    book.FreezeAll();
    err.clear();
    return true;
}

} // namespace modelnet

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_poolepoch.h>

#include <cstdint>

namespace modelnet {
namespace {

SwarmPoolEpochResult Refuse(const std::string& code, std::string& err)
{
    SwarmPoolEpochResult result;
    result.moved = false;
    result.code = code;
    err = code;
    return result;
}

SwarmPoolEpochResult Noted(std::string& err)
{
    SwarmPoolEpochResult result;
    result.moved = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace

SwarmPoolEpochResult SwarmNotePoolEpoch(const SwarmPoolEpoch& note, std::string& err)
{
    if (note.pool_id.empty() || note.stored_epoch < 1 || note.next_epoch < 1) {
        return Refuse("EPOCH", err);
    }
    // A next epoch at or below the stored epoch is stale, even when the
    // caller asks to move old obligations.
    if (note.next_epoch <= note.stored_epoch) {
        return Refuse("STALE", err);
    }
    // Raising the policy epoch does not move old obligations.
    if (note.want_move_obligations) {
        return Refuse("IMMUTABLE", err);
    }
    return Noted(err);
}

} // namespace modelnet

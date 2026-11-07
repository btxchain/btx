// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_staleepoch.h>

#include <cstdint>

namespace modelnet {
namespace {

SwarmStaleEpochResult Refuse(const std::string& code, std::string& err)
{
    SwarmStaleEpochResult result;
    result.committed = false;
    result.code = code;
    err = code;
    return result;
}

SwarmStaleEpochResult Noted(std::string& err)
{
    SwarmStaleEpochResult result;
    result.committed = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace

SwarmStaleEpochResult SwarmNoteStaleEpoch(const SwarmStaleEpoch& note, std::string& err)
{
    if (note.coordinator_id.empty() || note.stored_epoch < 1 || note.resume_epoch < 1) {
        return Refuse("EPOCH", err);
    }
    if (note.resume_epoch < note.stored_epoch) {
        return Refuse("STALE", err);
    }
    if (note.want_commit) {
        return Refuse("COMMIT_REFUSED", err);
    }
    return Noted(err);
}

} // namespace modelnet

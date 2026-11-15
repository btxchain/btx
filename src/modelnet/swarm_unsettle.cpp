// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_unsettle.h>

namespace modelnet {
namespace {

SwarmEarningResult Reject(const std::string& code, std::string& err)
{
    SwarmEarningResult result;
    result.recorded = false;
    result.settled = false;
    result.broadcast = false;
    result.atoms = 0;
    result.code = code;
    err = code;
    return result;
}

SwarmEarningResult Note(const std::string& code, int64_t atoms, std::string& err)
{
    SwarmEarningResult result;
    result.recorded = true;
    result.settled = false;
    result.broadcast = false;
    result.atoms = atoms;
    result.code = code;
    err.clear();
    return result;
}

} // namespace

SwarmEarningResult SwarmNoteEarning(const SwarmEarning& earning, std::string& err)
{
    if (earning.earning_id.empty() || earning.atoms <= 0) {
        return Reject("UNSETTLED", err);
    }
    if (earning.want_broadcast) {
        return Reject("BROADCAST_FORBIDDEN", err);
    }
    if (earning.crash_before_settlement) {
        return Note("HELD", earning.atoms, err);
    }
    return Note("RECORDED", earning.atoms, err);
}

} // namespace modelnet

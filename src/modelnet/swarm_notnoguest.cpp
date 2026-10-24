// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoguest.h>

namespace modelnet {

SwarmNotNoGuestResult SwarmNoteNotNoGuest(const SwarmNotNoGuest& note, std::string& err)
{
    SwarmNotNoGuestResult result;
    result.guest_agent = false;
    result.passed = false;
    if (note.host_id.empty()) {
        result.code = "HOST";
        result.guest_agent = false;
        result.passed = false;
        err = "HOST";
        return result;
    }
    // This note does not mark a guest agent present and does not mark Windows passed.
    if (note.want_agent) {
        result.code = "UNQUALIFIED";
        result.guest_agent = false;
        result.passed = false;
        err = "UNQUALIFIED";
        return result;
    }
    result.code = "NOTED";
    result.guest_agent = false;
    result.passed = false;
    err.clear();
    return result;
}

} // namespace modelnet

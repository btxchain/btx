// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocred.h>

#include <string>

namespace modelnet {

SwarmNotNoCredResult SwarmNoteNotNoCred(const SwarmNotNoCred& note, std::string& err)
{
    SwarmNotNoCredResult result;
    result.used = false;
    result.connected = false;
    // This note uses no credential and opens no connection.
    if (note.cred_id.empty()) {
        result.code = "CRED";
        result.used = false;
        result.connected = false;
        err = "CRED";
        return result;
    }
    if (note.want_use) {
        result.code = "REFUSED";
        result.used = false;
        result.connected = false;
        err = "REFUSED";
        return result;
    }
    result.code = "NOTED";
    result.used = false;
    result.connected = false;
    err.clear();
    return result;
}

} // namespace modelnet

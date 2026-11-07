// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoseal.h>

#include <string>

namespace modelnet {

SwarmNotNoSealResult SwarmNoteNotNoSeal(const SwarmNotNoSeal& note, std::string& err)
{
    SwarmNotNoSealResult result;
    result.sealed = false;
    result.bytes_moved = false;
    if (note.realm_id.empty()) {
        result.code = "REALM";
        result.sealed = false;
        result.bytes_moved = false;
        err = "REALM";
        return result;
    }
    // This note does not seal with AES-GCM and moves no bytes.
    if (note.want_seal) {
        result.code = "NOT_SEALED";
        result.sealed = false;
        result.bytes_moved = false;
        err = "NOT_SEALED";
        return result;
    }
    result.code = "NOTED";
    result.sealed = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet

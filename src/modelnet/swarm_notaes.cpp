// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notaes.h>

#include <string>

namespace modelnet {

SwarmNotAesResult SwarmNoteNotAes(const SwarmNotAes& note, std::string& err)
{
    SwarmNotAesResult result;
    result.sealed = false;
    if (note.realm_id.empty()) {
        result.code = "REALM";
        result.sealed = false;
        err = "REALM";
        return result;
    }
    // Realm AES-GCM has not sealed a payload.
    if (note.want_seal) {
        result.code = "NOT_SEALED";
        result.sealed = false;
        err = "NOT_SEALED";
        return result;
    }
    result.code = "NOTED";
    result.sealed = false;
    err.clear();
    return result;
}

} // namespace modelnet

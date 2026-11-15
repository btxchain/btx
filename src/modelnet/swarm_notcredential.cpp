// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcredential.h>

#include <string>

namespace modelnet {

SwarmNotCredentialResult SwarmNoteNotCredential(const SwarmNotCredential& note, std::string& err)
{
    SwarmNotCredentialResult result;
    result.admitted = false;
    result.stored = false;
    // A credential is not admitted and is not stored.
    if (note.item_id.empty()) {
        result.code = "ITEM";
        result.admitted = false;
        result.stored = false;
        err = "ITEM";
        return result;
    }
    if (note.is_credential || note.want_admit) {
        result.code = "CREDENTIAL";
        result.admitted = false;
        result.stored = false;
        err = "CREDENTIAL";
        return result;
    }
    result.code = "NOTED";
    result.admitted = false;
    result.stored = false;
    err.clear();
    return result;
}

} // namespace modelnet

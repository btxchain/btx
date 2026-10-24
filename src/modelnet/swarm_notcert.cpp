// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcert.h>

#include <string>

namespace modelnet {

SwarmNotCertResult SwarmNoteNotCert(const SwarmNotCert& note, std::string& err)
{
    SwarmNotCertResult result;
    result.issued = false;
    // No promotion certificate has been produced from a qualified real descendant.
    if (note.descendant_id.empty()) {
        result.code = "DESCENDANT";
        result.issued = false;
        err = "DESCENDANT";
        return result;
    }
    if (note.want_cert) {
        result.code = "NO_CERT";
        result.issued = false;
        err = "NO_CERT";
        return result;
    }
    result.code = "NOTED";
    result.issued = false;
    err.clear();
    return result;
}

} // namespace modelnet

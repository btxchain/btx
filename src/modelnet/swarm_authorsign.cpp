// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_authorsign.h>

namespace modelnet {

SwarmAuthorSignResult SwarmNoteAuthorSign(const SwarmAuthorSign& note, std::string& err)
{
    SwarmAuthorSignResult result;
    result.signed_report = false;
    if (note.report_id.empty() || note.author_id.empty() || note.signer_id.empty()) {
        result.code = "REPORT";
        err = "REPORT";
        return result;
    }
    // SELF wins even when want_sign is true.
    // An author cannot sign their own report.
    if (note.author_id == note.signer_id) {
        result.signed_report = false;
        result.code = "SELF";
        err = "SELF";
        return result;
    }
    if (note.want_sign) {
        result.signed_report = false;
        result.code = "HELD";
        err.clear();
        return result;
    }
    // Nothing is signed.
    result.signed_report = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoauthorrep2.h>

#include <string>

namespace modelnet {

SwarmNotNoAuthorRep2Result SwarmNoteNotNoAuthorRep2(const SwarmNotNoAuthorRep2& note, std::string& err)
{
    SwarmNotNoAuthorRep2Result result;
    result.signed_ok = false;
    // An author does not sign their own report.
    if (note.report_id.empty()) {
        result.code = "REPORT";
        result.signed_ok = false;
        err = "REPORT";
        return result;
    }
    // An author does not sign their own report, even when want_sign is false.
    if (note.same_author) {
        result.code = "NOT_SIGNED";
        result.signed_ok = false;
        err = "NOT_SIGNED";
        return result;
    }
    // This note signs nothing. An author does not sign their own report.
    if (note.want_sign) {
        result.code = "HELD";
        result.signed_ok = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.signed_ok = false;
    err.clear();
    return result;
}

} // namespace modelnet

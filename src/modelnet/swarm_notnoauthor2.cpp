// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoauthor2.h>

#include <string>

namespace modelnet {

SwarmNotNoAuthor2Result SwarmNoteNotNoAuthor2(const SwarmNotNoAuthor2& note, std::string& err)
{
    SwarmNotNoAuthor2Result result;
    result.signed_report = false;
    result.admitted = false;
    // An author does not sign their own report.
    if (note.report_id.empty()) {
        result.code = "REPORT";
        result.signed_report = false;
        result.admitted = false;
        err = "REPORT";
        return result;
    }
    // An author is NOT_SIGNER even when want_sign is false.
    if (note.author) {
        result.code = "NOT_SIGNER";
        result.signed_report = false;
        result.admitted = false;
        err = "NOT_SIGNER";
        return result;
    }
    // This note signs nothing. An author does not sign their own report.
    if (note.want_sign) {
        result.code = "HELD";
        result.signed_report = false;
        result.admitted = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.signed_report = false;
    result.admitted = false;
    err.clear();
    return result;
}

} // namespace modelnet

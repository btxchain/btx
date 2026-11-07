// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoauthor3.h>

#include <string>

namespace modelnet {

SwarmNotNoAuthor3Result SwarmNoteNotNoAuthor3(const SwarmNotNoAuthor3& note, std::string& err)
{
    SwarmNotNoAuthor3Result result;
    result.signed_report = false;
    // An author does not sign their own report.
    if (note.report_id.empty()) {
        result.code = "REPORT";
        result.signed_report = false;
        err = "REPORT";
        return result;
    }
    // A self-signed report is NOT_SIGNED even when want_sign is false.
    if (note.self_sign) {
        result.code = "NOT_SIGNED";
        result.signed_report = false;
        err = "NOT_SIGNED";
        return result;
    }
    // This note signs nothing. An author does not sign their own report.
    if (note.want_sign) {
        result.code = "HELD";
        result.signed_report = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.signed_report = false;
    err.clear();
    return result;
}

} // namespace modelnet

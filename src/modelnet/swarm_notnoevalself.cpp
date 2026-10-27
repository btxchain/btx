// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoevalself.h>

#include <string>

namespace modelnet {

SwarmNotNoEvalSelfResult SwarmNoteNotNoEvalSelf(const SwarmNotNoEvalSelf& note, std::string& err)
{
    SwarmNotNoEvalSelfResult result;
    result.scored = false;
    result.admitted = false;
    // An author does not score their own report.
    if (note.report_id.empty()) {
        result.code = "REPORT";
        result.scored = false;
        result.admitted = false;
        err = "REPORT";
        return result;
    }
    // An author is SELF even when want_score is false.
    if (note.author) {
        result.code = "SELF";
        result.scored = false;
        result.admitted = false;
        err = "SELF";
        return result;
    }
    // This note scores nothing. An author does not score their own report.
    if (note.want_score) {
        result.code = "HELD";
        result.scored = false;
        result.admitted = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.scored = false;
    result.admitted = false;
    err.clear();
    return result;
}

} // namespace modelnet

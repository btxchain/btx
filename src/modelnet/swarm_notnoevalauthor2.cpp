// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoevalauthor2.h>

#include <string>

namespace modelnet {

SwarmNotNoEvalAuthor2Result SwarmNoteNotNoEvalAuthor2(const SwarmNotNoEvalAuthor2& note, std::string& err)
{
    SwarmNotNoEvalAuthor2Result result;
    result.scored = false;
    // An author does not score their own report.
    if (note.report_id.empty()) {
        result.code = "REPORT";
        result.scored = false;
        err = "REPORT";
        return result;
    }
    // A self-author is NOT_SCORED even when want_score is false.
    if (note.self_author) {
        result.code = "NOT_SCORED";
        result.scored = false;
        err = "NOT_SCORED";
        return result;
    }
    // This note scores nothing. An author does not score their own report.
    if (note.want_score) {
        result.code = "HELD";
        result.scored = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.scored = false;
    err.clear();
    return result;
}

} // namespace modelnet

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoevalself2.h>

#include <string>

namespace modelnet {

SwarmNotNoEvalSelf2Result SwarmNoteNotNoEvalSelf2(const SwarmNotNoEvalSelf2& note, std::string& err)
{
    SwarmNotNoEvalSelf2Result result;
    result.scored = false;
    if (note.report_id.empty()) {
        result.code = "REPORT";
        result.scored = false;
        err = "REPORT";
        return result;
    }
    // An author does not evaluate their own report.
    if (note.same_author) {
        result.code = "NOT_SCORED";
        result.scored = false;
        err = "NOT_SCORED";
        return result;
    }
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

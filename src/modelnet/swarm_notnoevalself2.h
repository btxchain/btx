// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOEVALSELF2_H
#define BTX_MODELNET_SWARM_NOTNOEVALSELF2_H

#include <string>

namespace modelnet {

/**
 * A local note that an author might score their own report.
 * same_author means the author of the report is the one asking to score it.
 * want_score asks this note to score the report.
 *
 * An author does not evaluate their own report. scored stays false on every
 * path. Nothing broadcasts, spends, launches, mines, or moves bytes.
 */
struct SwarmNotNoEvalSelf2 {
    std::string report_id;
    bool same_author{false};
    bool want_score{false};
};

/**
 * Outcome of noting that an author does not evaluate their own report.
 * scored stays false on every path.
 */
struct SwarmNotNoEvalSelf2Result {
    std::string code;
    bool scored{false};
};

/**
 * Note that an author does not evaluate their own report.
 * Order, first match wins: an empty report_id is REPORT. same_author is
 * NOT_SCORED even when want_score is false. want_score is HELD. Otherwise
 * the note is NOTED and err is clear. scored stays false on every path.
 */
SwarmNotNoEvalSelf2Result SwarmNoteNotNoEvalSelf2(const SwarmNotNoEvalSelf2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOEVALSELF2_H

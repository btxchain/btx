// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOEVALAUTHOR2_H
#define BTX_MODELNET_SWARM_NOTNOEVALAUTHOR2_H

#include <string>

namespace modelnet {

/**
 * A local note that an author does not score their own report.
 * want_score asks this note to score the report.
 *
 * An author does not score their own report. This note scores
 * nothing. scored stays false on every path.
 */
struct SwarmNotNoEvalAuthor2 {
    std::string report_id;
    bool self_author{false};
    bool want_score{false};
};

/**
 * Outcome of noting that an author does not score their own report.
 * scored stays false on every path.
 */
struct SwarmNotNoEvalAuthor2Result {
    std::string code;
    bool scored{false};
};

/**
 * Note that an author does not score their own report. This note
 * scores nothing. Order, first match wins:
 * 1. An empty report_id is REPORT. scored stays false and err is
 *    REPORT.
 * 2. If self_author is true, the note is NOT_SCORED even when
 *    want_score is false. scored stays false and err is NOT_SCORED.
 * 3. want_score is HELD. scored stays false and err is HELD.
 * 4. Otherwise the note is NOTED and err is cleared. scored stays
 *    false.
 * scored stays false on every path. An author does not score their
 * own report.
 */
SwarmNotNoEvalAuthor2Result SwarmNoteNotNoEvalAuthor2(const SwarmNotNoEvalAuthor2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOEVALAUTHOR2_H

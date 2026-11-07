// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOEVALSELF_H
#define BTX_MODELNET_SWARM_NOTNOEVALSELF_H

#include <string>

namespace modelnet {

/**
 * A local note that an author does not score their own report.
 * want_score asks this note to score the report.
 *
 * An author does not score their own report. This note scores
 * nothing and admits nothing. scored and admitted stay false
 * on every path.
 */
struct SwarmNotNoEvalSelf {
    std::string report_id;
    bool author{false};
    bool want_score{false};
};

/**
 * Outcome of noting that an author does not score their own report.
 * scored and admitted stay false on every path.
 */
struct SwarmNotNoEvalSelfResult {
    std::string code;
    bool scored{false};
    bool admitted{false};
};

/**
 * Note that an author does not score their own report. This note
 * scores nothing and admits nothing. Order, first match wins:
 * 1. An empty report_id is REPORT. scored stays false, admitted
 *    stays false, and err is REPORT.
 * 2. If author is true, the note is SELF even when want_score is
 *    false. scored stays false, admitted stays false, and err is SELF.
 * 3. want_score is HELD. scored stays false, admitted stays false,
 *    and err is HELD.
 * 4. Otherwise the note is NOTED and err is cleared. scored stays
 *    false and admitted stays false.
 * scored and admitted stay false on every path. An author does not
 * score their own report.
 */
SwarmNotNoEvalSelfResult SwarmNoteNotNoEvalSelf(const SwarmNotNoEvalSelf& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOEVALSELF_H

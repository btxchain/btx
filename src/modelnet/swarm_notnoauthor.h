// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOAUTHOR_H
#define BTX_MODELNET_SWARM_NOTNOAUTHOR_H

#include <string>

namespace modelnet {

/**
 * A local note that an author does not sign their own report.
 * want_sign asks this note to sign the report.
 *
 * An author does not sign their own report. This note accepts
 * nothing and signs nothing. signed_report and accepted stay false
 * on every path.
 */
struct SwarmNotNoAuthor {
    std::string report_id;
    bool self_signed{false};
    bool want_sign{false};
};

/**
 * Outcome of noting that an author does not sign their own report.
 * signed_report and accepted stay false on every path.
 */
struct SwarmNotNoAuthorResult {
    std::string code;
    bool signed_report{false};
    bool accepted{false};
};

/**
 * Note that an author does not sign their own report. This note signs
 * nothing and accepts nothing. Order, first match wins:
 * 1. An empty report_id is REPORT. signed_report stays false, accepted
 *    stays false, and err is REPORT.
 * 2. If self_signed is true, the note is SAME_EVALUATOR even when
 *    want_sign is false. signed_report stays false, accepted stays
 *    false, and err is SAME_EVALUATOR.
 * 3. want_sign is NOT_ACCEPTED. signed_report stays false, accepted
 *    stays false, and err is NOT_ACCEPTED.
 * 4. Otherwise the note is NOTED and err is cleared. signed_report
 *    stays false and accepted stays false.
 * signed_report and accepted stay false on every path. An author does
 * not sign their own report.
 */
SwarmNotNoAuthorResult SwarmNoteNotNoAuthor(const SwarmNotNoAuthor& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOAUTHOR_H

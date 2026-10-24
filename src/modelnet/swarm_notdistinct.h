// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTDISTINCT_H
#define BTX_MODELNET_SWARM_NOTDISTINCT_H

#include <string>

namespace modelnet {

/**
 * A local note that an author does not sign their own report.
 * want_sign asks this note to sign the report.
 *
 * An author does not sign their own report. This note signs nothing.
 * signed_report and accepted stay false on every path.
 */
struct SwarmNotDistinct {
    std::string report_id;
    bool same_author{false};
    bool want_sign{false};
};

/**
 * Outcome of noting that an author does not sign their own report.
 * signed_report and accepted stay false on every path. This note signs
 * nothing.
 */
struct SwarmNotDistinctResult {
    std::string code;
    bool signed_report{false};
    bool accepted{false};
};

/**
 * Note that an author does not sign their own report. This note signs
 * nothing. Order, first match wins: an empty report_id is REPORT.
 * same_author is SAME_EVALUATOR, even when want_sign is false. want_sign
 * is NOT_ACCEPTED. Otherwise the note is NOTED and err is clear.
 * signed_report and accepted stay false on every path.
 */
SwarmNotDistinctResult SwarmNoteNotDistinct(const SwarmNotDistinct& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTDISTINCT_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOAUTHOR2_H
#define BTX_MODELNET_SWARM_NOTNOAUTHOR2_H

#include <string>

namespace modelnet {

/**
 * A local note that an author does not sign their own report.
 * want_sign asks this note to sign the report.
 *
 * An author does not sign their own report. This note signs nothing
 * and admits nothing. signed_report and admitted stay false on every
 * path.
 */
struct SwarmNotNoAuthor2 {
    std::string report_id;
    bool author{false};
    bool want_sign{false};
};

/**
 * Outcome of noting that an author does not sign their own report.
 * signed_report and admitted stay false on every path.
 */
struct SwarmNotNoAuthor2Result {
    std::string code;
    bool signed_report{false};
    bool admitted{false};
};

/**
 * Note that an author does not sign their own report. This note signs
 * nothing and admits nothing. Order, first match wins:
 * 1. An empty report_id is REPORT. signed_report stays false, admitted
 *    stays false, and err is REPORT.
 * 2. If author is true, the note is NOT_SIGNER even when want_sign is
 *    false. signed_report stays false, admitted stays false, and err is
 *    NOT_SIGNER.
 * 3. want_sign is HELD. signed_report stays false, admitted stays false,
 *    and err is HELD.
 * 4. Otherwise the note is NOTED and err is cleared. signed_report stays
 *    false and admitted stays false.
 * signed_report and admitted stay false on every path. An author does
 * not sign their own report.
 */
SwarmNotNoAuthor2Result SwarmNoteNotNoAuthor2(const SwarmNotNoAuthor2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOAUTHOR2_H

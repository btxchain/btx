// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOAUTHORREP2_H
#define BTX_MODELNET_SWARM_NOTNOAUTHORREP2_H

#include <string>

namespace modelnet {

/**
 * A local note that an author does not sign their own report.
 * want_sign asks this note to sign the report.
 *
 * An author does not sign their own report. This note signs nothing.
 * signed_ok stays false on every path.
 */
struct SwarmNotNoAuthorRep2 {
    std::string report_id;
    bool same_author{false};
    bool want_sign{false};
};

/**
 * Outcome of noting that an author does not sign their own report.
 * signed_ok stays false on every path.
 */
struct SwarmNotNoAuthorRep2Result {
    std::string code;
    bool signed_ok{false};
};

/**
 * Note that an author does not sign their own report. This note signs
 * nothing. Order, first match wins:
 * 1. An empty report_id is REPORT. signed_ok stays false and err
 *    is REPORT.
 * 2. If same_author is true, the note is NOT_SIGNED even when want_sign
 *    is false. signed_ok stays false and err is NOT_SIGNED.
 * 3. want_sign is HELD. signed_ok stays false and err is HELD.
 * 4. Otherwise the note is NOTED and err is cleared. signed_ok
 *    stays false.
 * signed_ok stays false on every path. An author does not sign
 * their own report.
 */
SwarmNotNoAuthorRep2Result SwarmNoteNotNoAuthorRep2(const SwarmNotNoAuthorRep2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOAUTHORREP2_H

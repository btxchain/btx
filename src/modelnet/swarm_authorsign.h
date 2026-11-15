// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_AUTHORSIGN_H
#define BTX_MODELNET_SWARM_AUTHORSIGN_H

#include <string>

namespace modelnet {

/**
 * A local note of a requested report signature.
 * report_id names the report. author_id names the author. signer_id names
 * the requested signer. want_sign asks this note to sign the report.
 *
 * signed_report stays false on every path. Nothing is signed. No hostnames
 * or IPs are used.
 */
struct SwarmAuthorSign {
    std::string report_id;
    std::string author_id;
    std::string signer_id;
    bool want_sign{false};
};

/**
 * Outcome of noting a report signature. signed_report stays false: nothing
 * is signed.
 */
struct SwarmAuthorSignResult {
    bool signed_report{false};
    std::string code;
};

/**
 * Note a report signature without signing it.
 * Order, first match wins:
 * an empty report_id, author_id, or signer_id is REPORT.
 * author_id equal to signer_id is SELF, including when want_sign is true.
 * An author cannot sign their own report.
 * want_sign is HELD and err is cleared. A different signer still does not
 * make this note sign the report.
 * Otherwise the note is NOTED and err is cleared.
 * signed_report stays false. Nothing is signed.
 */
SwarmAuthorSignResult SwarmNoteAuthorSign(const SwarmAuthorSign& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_AUTHORSIGN_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SELFSIGN_H
#define BTX_MODELNET_SWARM_SELFSIGN_H

#include <string>

namespace modelnet {

/**
 * A self-sign record. An author does not sign their own report.
 * report_id names the report. same_author records that the author is
 * the requested signer. want_sign asks this note to sign the report.
 */
struct SwarmSelfSign {
    std::string report_id;
    bool same_author{false};
    bool want_sign{false};
};

/**
 * Outcome of noting a self-sign record. signed_ok stays false on every
 * path.
 */
struct SwarmSelfSignResult {
    std::string code;
    bool signed_ok{false};
};

/**
 * Note a self-sign record without signing the report.
 * Order, first match wins:
 * an empty report_id is REPORT.
 * same_author is NOT_SIGNED, including when want_sign is false.
 * want_sign is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * signed_ok stays false. An author does not sign their own report.
 */
SwarmSelfSignResult SwarmNoteSelfSign(const SwarmSelfSign& report, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SELFSIGN_H

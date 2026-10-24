// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTCERT_H
#define BTX_MODELNET_SWARM_NOTCERT_H

#include <string>

namespace modelnet {

/**
 * A local note about one descendant. want_cert asks this note to issue a
 * promotion certificate from a qualified real descendant.
 *
 * No promotion certificate has been produced from a qualified real
 * descendant. issued stays false on every path.
 */
struct SwarmNotCert {
    std::string descendant_id;
    bool want_cert{false};
};

/**
 * Outcome of noting a promotion-certificate request. issued stays false on
 * every path: no promotion certificate has been produced from a qualified
 * real descendant.
 */
struct SwarmNotCertResult {
    std::string code;
    bool issued{false};
};

/**
 * Note a promotion-certificate request without issuing a certificate.
 * Order, first match wins: an empty descendant_id is DESCENDANT. want_cert
 * is NO_CERT. Otherwise the note is NOTED and err is clear.
 * issued stays false on every path.
 */
SwarmNotCertResult SwarmNoteNotCert(const SwarmNotCert& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTCERT_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FLAG09_H
#define BTX_MODELNET_SWARM_FLAG09_H

#include <string>

namespace modelnet {

/**
 * Flagship stage 9 graduate: a local note about a promotion certificate
 * from a qualified real descendant. descendant_id names that descendant.
 * qualified and real_run say the note may treat the descendant as
 * qualified and from a real run. want_cert asks for a certificate.
 * want_realm asks for realm promotion. want_pass asks to treat the
 * descendant as passed.
 *
 * Quality is not realm promotion and not ExactReplay admission.
 * issued, passed, and realm stay false on every path.
 */
struct SwarmFlag09 {
    std::string descendant_id;
    bool qualified{false};
    bool real_run{false};
    bool want_cert{false};
    bool want_realm{false};
    bool want_pass{false};
};

/**
 * Outcome of noting flagship stage 9 graduate. issued, realm,
 * replay_admitted, and passed stay false: quality is not realm
 * promotion and not ExactReplay admission.
 */
struct SwarmFlag09Result {
    std::string code;
    bool issued{false};
    bool realm{false};
    bool replay_admitted{false};
    bool passed{false};
};

/**
 * Note flagship stage 9 graduate. A promotion certificate from a
 * qualified real descendant is not issued. Quality is not realm
 * promotion and not ExactReplay admission.
 * Order, first match wins:
 * 1. An empty descendant_id is DESCENDANT. Every result bool stays
 *    false and err is DESCENDANT.
 * 2. Not qualified or not real_run is NO_CERT, even when want_cert is
 *    set. issued stays false and err is NO_CERT.
 * 3. want_realm is NOT_REALM. realm, replay_admitted, and issued stay
 *    false and err is NOT_REALM.
 * 4. want_cert is HELD. issued stays false and err is cleared.
 * 5. want_pass is UNQUALIFIED. issued and passed stay false and err is
 *    UNQUALIFIED.
 * 6. Otherwise the note is NOTED. issued, realm, replay_admitted, and
 *    passed stay false and err is cleared.
 * issued, realm, replay_admitted, and passed stay false on every path.
 */
SwarmFlag09Result SwarmStageGraduate(const SwarmFlag09& in, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FLAG09_H

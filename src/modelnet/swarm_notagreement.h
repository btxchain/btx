// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTAGREEMENT_H
#define BTX_MODELNET_SWARM_NOTAGREEMENT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one agreement. want_settle asks this note to settle
 * that agreement.
 *
 * Agreement is not settlement. settled stays false and atoms stays 0 on
 * every path.
 */
struct SwarmNotAgreement {
    std::string agreement_id;
    bool want_settle{false};
};

/**
 * Outcome of noting an agreement. settled stays false and atoms stays 0
 * on every path. Agreement is not settlement.
 */
struct SwarmNotAgreementResult {
    std::string code;
    bool settled{false};
    int64_t atoms{0};
};

/**
 * Note an agreement without settling it or moving atoms.
 * Order, first match wins: an empty agreement_id is AGREEMENT.
 * want_settle is NOT_SETTLEMENT.
 * Otherwise the note is NOTED and err is clear.
 * settled stays false and atoms stays 0 on every path.
 * Agreement is not settlement.
 */
SwarmNotAgreementResult SwarmNoteNotAgreement(const SwarmNotAgreement& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTAGREEMENT_H

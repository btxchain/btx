// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_AGREEMENT_H
#define BTX_MODELNET_SWARM_AGREEMENT_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one candidate. outcomes_agree records that the
 * recorded outcomes match. want_settle asks this note to settle.
 *
 * Agreement is not settlement. This note does not settle and does not
 * broadcast. settled stays false and atoms_moved stays 0 on every path.
 */
struct SwarmAgreement {
    std::string candidate_id;
    bool outcomes_agree{false};
    bool want_settle{false};
};

/**
 * Outcome of noting an agreement. settled stays false and atoms_moved
 * stays 0 on every path. Agreement is noted and does not settle.
 */
struct SwarmAgreementResult {
    std::string code;
    bool settled{false};
    int64_t atoms_moved{0};
};

/**
 * Note an agreement without settling.
 * Order, first match wins: an empty candidate_id is AGREE.
 * Disagreement is SPLIT, even when want_settle is also true.
 * want_settle is NOT_SETTLEMENT, even when outcomes_agree is also true.
 * Otherwise the note is NOTED and err is clear. settled stays false and
 * atoms_moved stays 0 on every path. Agreement is not settlement. This
 * note does not broadcast.
 */
SwarmAgreementResult SwarmNoteAgreement(const SwarmAgreement& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_AGREEMENT_H

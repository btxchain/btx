// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_promohalt.h>

namespace modelnet {
namespace {

SwarmPromotionHalt Note(const char* code, std::string& err, bool clear_err)
{
    SwarmPromotionHalt halt;
    halt.graduated = false;
    halt.code = code;
    if (clear_err) {
        err.clear();
    } else {
        err = code;
    }
    return halt;
}

} // namespace

SwarmPromotionHalt SwarmHaltPromotion(const SwarmPromotionAttempt& attempt, std::string& err)
{
    if (attempt.candidate_id.empty()) {
        return Note("PROMOTION", err, false);
    }
    if (!attempt.started) {
        return Note("NOT_STARTED", err, false);
    }
    if (attempt.interrupted) {
        return Note("INTERRUPTED", err, false);
    }
    return Note("HELD", err, true);
}

} // namespace modelnet

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flagship/record.h>

#include <modelnet/swarm_flagship/catalog.h>
#include <modelnet/swarm_flagship/codes.h>
#include <modelnet/swarm_flagship/decide.h>
#include <modelnet/swarm_flagship/ledger.h>

#include <cstddef>
#include <optional>
#include <string>

namespace modelnet {
namespace {

/**
 * commit refused to write. Derive the refusal from the book as it stands
 * so the first evidence id stays and err matches that book.
 */
bool RefuseUnstored(const SwarmFlagshipLedger& ledger,
                    const std::string& stage,
                    const std::string& evidence,
                    std::string& err)
{
    const std::optional<std::size_t> found = SwarmFlagshipCatalog::index(stage);
    if (!found.has_value()) {
        return SwarmFlagshipRefuse(err, kSwarmFlagshipStage);
    }
    if (evidence.empty()) {
        return SwarmFlagshipRefuse(err, kSwarmFlagshipEvidence);
    }
    if (ledger.recorded(*found)) {
        if (ledger.evidence(*found) == evidence) {
            return SwarmFlagshipRefuse(err, kSwarmFlagshipReplay);
        }
        return SwarmFlagshipRefuse(err, kSwarmFlagshipConflict);
    }
    return SwarmFlagshipRefuse(err, kSwarmFlagshipOrder);
}

} // namespace

bool SwarmFlagshipRecord::apply(SwarmFlagshipLedger& ledger,
                                const std::string& stage,
                                const std::string& evidence,
                                std::string& err) const
{
    const SwarmFlagshipDecision decision = SwarmFlagshipDecide(ledger, stage, evidence);
    switch (decision.outcome) {
    case SwarmFlagshipRecordOutcome::Stage:
        return SwarmFlagshipRefuse(err, kSwarmFlagshipStage);
    case SwarmFlagshipRecordOutcome::Evidence:
        return SwarmFlagshipRefuse(err, kSwarmFlagshipEvidence);
    case SwarmFlagshipRecordOutcome::Order:
        return SwarmFlagshipRefuse(err, kSwarmFlagshipOrder);
    case SwarmFlagshipRecordOutcome::Replay:
        return SwarmFlagshipRefuse(err, kSwarmFlagshipReplay);
    case SwarmFlagshipRecordOutcome::Conflict:
        return SwarmFlagshipRefuse(err, kSwarmFlagshipConflict);
    case SwarmFlagshipRecordOutcome::Store:
        if (!ledger.commit(decision.index, evidence)) {
            return RefuseUnstored(ledger, stage, evidence, err);
        }
        return SwarmFlagshipAccept(err);
    }
    return SwarmFlagshipRefuse(err, kSwarmFlagshipStage);
}

} // namespace modelnet

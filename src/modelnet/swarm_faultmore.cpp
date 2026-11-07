// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultmore.h>

namespace modelnet {
namespace {

SwarmLiveFaultOutcome Code(const char* code, bool recovered, bool clear_err, std::string& err)
{
    SwarmLiveFaultOutcome out;
    out.recovered = recovered;
    out.committed = false;
    out.bytes_moved = false;
    out.code = code;
    if (clear_err) {
        err.clear();
    } else {
        err = code;
    }
    return out;
}

} // namespace

SwarmLiveFaultOutcome SwarmLiveFaultCode(SwarmLiveFault kind, bool durable, std::string& err)
{
    switch (kind) {
    case SwarmLiveFault::ReplacementDuringExpiry:
        return Code("LEASE_EXPIRED", false, false, err);
    case SwarmLiveFault::GpuCrashPublish:
        // A checkpoint code. This does not claim a GPU ran.
        return Code("CHECKPOINT", false, false, err);
    case SwarmLiveFault::WorkerDisconnect:
        if (durable) return Code("DURABLE", true, true, err);
        return Code("LOST", false, false, err);
    case SwarmLiveFault::DuplicateReceipt:
        if (durable) return Code("REPLAY", true, true, err);
        return Code("REPLAY", false, false, err);
    case SwarmLiveFault::CacheOwnerGone:
        return Code("INCOMPLETE", false, false, err);
    case SwarmLiveFault::IncompatibleTransfer:
        return Code("PREFIX_MISMATCH", false, false, err);
    case SwarmLiveFault::PromotionInterrupted:
        return Code("GATE", false, false, err);
    case SwarmLiveFault::CanaryRegress:
        return Code("REGRESSION", false, false, err);
    case SwarmLiveFault::ConflictingEvaluators:
        return Code("QUORUM", false, false, err);
    case SwarmLiveFault::PaymentCrashAfterEarn:
        // Earned is a code. This does not spend.
        if (durable) return Code("EARNED", true, false, err);
        return Code("LOST", false, false, err);
    case SwarmLiveFault::RefundMature:
        return Code("REFUND", false, false, err);
    case SwarmLiveFault::MassExitReorg:
        return Code("REORG", false, false, err);
    case SwarmLiveFault::PermanentCoordinator:
        if (durable) return Code("DURABLE", true, true, err);
        return Code("LOST", false, false, err);
    }
    err.clear();
    return {};
}

} // namespace modelnet

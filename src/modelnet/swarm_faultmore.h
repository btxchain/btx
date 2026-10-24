// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FAULTMORE_H
#define BTX_MODELNET_SWARM_FAULTMORE_H

#include <string>

namespace modelnet {

enum class SwarmLiveFault {
    ReplacementDuringExpiry,
    GpuCrashPublish,
    WorkerDisconnect,
    DuplicateReceipt,
    CacheOwnerGone,
    IncompatibleTransfer,
    PromotionInterrupted,
    CanaryRegress,
    ConflictingEvaluators,
    PaymentCrashAfterEarn,
    RefundMature,
    MassExitReorg,
    PermanentCoordinator
};

/**
 * A code for one caller-supplied live fault. recovered is a flag.
 * committed stays false. bytes_moved stays false.
 * This function does not inject a fault, move bytes, spend, or claim a GPU ran.
 */
struct SwarmLiveFaultOutcome {
    bool recovered{false};
    bool committed{false};
    bool bytes_moved{false};
    std::string code;
};

/**
 * ReplacementDuringExpiry is LEASE_EXPIRED and does not recover.
 * GpuCrashPublish is CHECKPOINT and does not recover. It does not claim a GPU ran.
 * WorkerDisconnect with durable is DURABLE, sets recovered, and clears err.
 * WorkerDisconnect without durable is LOST.
 * DuplicateReceipt is REPLAY. recovered is set only when durable, and that path clears err.
 * CacheOwnerGone is INCOMPLETE. IncompatibleTransfer is PREFIX_MISMATCH.
 * PromotionInterrupted is GATE and does not recover.
 * CanaryRegress is REGRESSION and does not recover.
 * ConflictingEvaluators is QUORUM and does not recover.
 * PaymentCrashAfterEarn with durable is EARNED and sets recovered. It does not spend.
 * PaymentCrashAfterEarn without durable is LOST.
 * RefundMature is REFUND. MassExitReorg is REORG.
 * PermanentCoordinator with durable is DURABLE, sets recovered, and clears err.
 * PermanentCoordinator without durable is LOST.
 * err equals code except DURABLE and the durable DuplicateReceipt path.
 */
SwarmLiveFaultOutcome SwarmLiveFaultCode(SwarmLiveFault kind, bool durable, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FAULTMORE_H

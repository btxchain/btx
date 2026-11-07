// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultjournal.h>

#include <modelnet/swarm_cycle.h>
#include <modelnet/swarm_fault.h>
#include <modelnet/swarm_faultmore.h>
#include <modelnet/swarm_paymesh.h>

namespace modelnet {
namespace {

bool Keep(SwarmFaultJournal* /*self*/, int64_t before, int64_t after_earned, int64_t bytes, std::string& err)
{
    if (after_earned != before || bytes != 0) {
        err = "EARNED";
        return false;
    }
    return true;
}

} // namespace

void SwarmFaultJournal::Arm(int64_t earned_atoms, bool checkpoint, bool payment_plane, bool durable)
{
    m_earned = earned_atoms;
    m_checkpoint = checkpoint;
    m_payment_plane = payment_plane;
    m_durable = durable;
    m_bytes = 0;
    m_frozen = false;
    m_training = false;
    m_accepted = false;
    m_code.clear();
}

bool SwarmFaultJournal::Apply(int fault, std::string& err)
{
    const int64_t before = m_earned;
    m_bytes = 0;
    if (fault < 1 || fault > 20) {
        m_code = "FAULT";
        err = "FAULT";
        return false;
    }
    if (fault == 1) {
        SwarmRecoverySnapshot in;
        in.earned_atoms = m_earned;
        in.checkpoint_present = m_checkpoint;
        in.payment_plane_present = m_payment_plane;
        in.execution_plane_present = true;
        SwarmRecoverySnapshot out;
        const bool ok = SwarmCoordinatorLost(in, out, err);
        m_code = ok ? "DURABLE" : err;
        m_earned = out.earned_atoms;
        return ok && Keep(this, before, m_earned, m_bytes, err);
    }
    if (fault == 3) {
        const SwarmFaultOutcome out = SwarmRecoverFault(SwarmFaultKind::StaleEpoch, m_durable, true, err);
        m_code = out.code;
        m_bytes = out.bytes_moved ? 1 : 0;
        return out.recovered && !out.stale_committed && Keep(this, before, m_earned, m_bytes, err);
    }
    if (fault == 8) {
        const SwarmFaultOutcome out = SwarmRecoverFault(SwarmFaultKind::TruncatedCache, m_durable, false, err);
        m_code = out.code;
        m_bytes = out.bytes_moved ? 1 : 0;
        return out.recovered && Keep(this, before, m_earned, m_bytes, err);
    }
    if (fault == 9) {
        const SwarmFaultOutcome out = SwarmRecoverFault(SwarmFaultKind::PartialPiece, m_durable, false, err);
        m_code = out.code;
        m_bytes = out.bytes_moved ? 1 : 0;
        return out.recovered && Keep(this, before, m_earned, m_bytes, err);
    }
    if (fault == 12) {
        const bool ok = SwarmConflictingValidators(m_accepted, err);
        m_code = err;
        return ok && m_accepted && Keep(this, before, m_earned, m_bytes, err);
    }
    if (fault == 15) {
        SwarmRecoverySnapshot snap;
        snap.earned_atoms = m_earned;
        snap = SwarmReorgExit(snap);
        m_frozen = snap.frozen;
        m_earned = snap.earned_atoms;
        const SwarmLiveFaultOutcome out = SwarmLiveFaultCode(SwarmLiveFault::MassExitReorg, m_durable, err);
        m_code = out.code;
        m_bytes = out.bytes_moved ? 1 : 0;
        return out.recovered && m_frozen && Keep(this, before, m_earned, m_bytes, err);
    }
    if (fault == 16) {
        SwarmCollateralBook book;
        if (!SwarmSameCollateral(book, "pool-a", "pool-a", "out-1", err)) return false;
        const bool reused = SwarmSameCollateral(book, "pool-b", "pool-a", "out-1", err);
        m_code = err;
        return reused && Keep(this, before, m_earned, m_bytes, err);
    }
    if (fault == 17) {
        const SwarmFaultOutcome out = SwarmRecoverFault(SwarmFaultKind::RevokedCache, m_durable, false, err);
        m_code = out.code;
        m_bytes = out.bytes_moved ? 1 : 0;
        return out.recovered && Keep(this, before, m_earned, m_bytes, err);
    }
    if (fault == 18) {
        m_training = SwarmStartTraining(true, true, err);
        m_code = err;
        return m_training && Keep(this, before, m_earned, m_bytes, err);
    }
    if (fault == 19) {
        const SwarmFaultOutcome out = SwarmRecoverFault(SwarmFaultKind::FalseCompatibility, m_durable, false, err);
        m_code = out.code;
        m_bytes = out.bytes_moved ? 1 : 0;
        return out.recovered && Keep(this, before, m_earned, m_bytes, err);
    }

    SwarmLiveFault kind = SwarmLiveFault::ReplacementDuringExpiry;
    if (fault == 4) kind = SwarmLiveFault::GpuCrashPublish;
    else if (fault == 5) kind = SwarmLiveFault::WorkerDisconnect;
    else if (fault == 6) kind = SwarmLiveFault::DuplicateReceipt;
    else if (fault == 7) kind = SwarmLiveFault::CacheOwnerGone;
    else if (fault == 10) kind = SwarmLiveFault::PromotionInterrupted;
    else if (fault == 11) kind = SwarmLiveFault::CanaryRegress;
    else if (fault == 13) kind = SwarmLiveFault::PaymentCrashAfterEarn;
    else if (fault == 14) kind = SwarmLiveFault::RefundMature;
    else if (fault == 20) kind = SwarmLiveFault::PermanentCoordinator;
    const SwarmLiveFaultOutcome out = SwarmLiveFaultCode(kind, m_durable, err);
    m_code = out.code;
    m_bytes = out.bytes_moved ? 1 : 0;
    if (fault == 5 && SwarmWorkerDisconnected(m_earned) != m_earned) {
        err = "EARNED";
        return false;
    }
    return out.recovered && !out.committed && Keep(this, before, m_earned, m_bytes, err);
}

} // namespace modelnet

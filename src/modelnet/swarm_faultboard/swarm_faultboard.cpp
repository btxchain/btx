// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultboard/swarm_faultboard.h>

#include <modelnet/swarm_faultboard/admit.h>
#include <modelnet/swarm_faultboard/cache.h>
#include <modelnet/swarm_faultboard/coordinator.h>
#include <modelnet/swarm_faultboard/pay.h>
#include <modelnet/swarm_faultboard/promote.h>
#include <modelnet/swarm_faultboard/reorg.h>
#include <modelnet/swarm_faultboard/worker.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmFaultBoard::KeepClaim(const std::string& task, const std::string& worker, std::string& err)
{
    return m_claims.Keep(task, worker, err);
}

bool SwarmFaultBoard::KeepResult(const std::string& task, const std::string& receipt, std::string& err)
{
    return m_results.Keep(task, receipt, err);
}

bool SwarmFaultBoard::KeepEarned(const std::string& work, int64_t atoms, std::string& err)
{
    return m_earned.Keep(work, atoms, err);
}

bool SwarmFaultBoard::KeepHead(const std::string& channel, const std::string& head, std::string& err)
{
    return m_heads.Keep(channel, head, err);
}

bool SwarmFaultBoard::KeepCheckpoint(const std::string& id, std::string& err)
{
    return m_checkpoint.Keep(id, err);
}

bool SwarmFaultBoard::CoordinatorGone(std::string& err)
{
    return SwarmFaultCoordinatorGone(m_claims, err);
}

bool SwarmFaultBoard::ReplaceCoordinator(int64_t old_epoch, int64_t new_epoch, std::string& err)
{
    return SwarmFaultReplaceCoordinator(m_epoch, old_epoch, new_epoch, err);
}

bool SwarmFaultBoard::ResumeStale(int64_t epoch, int64_t current, std::string& err)
{
    return SwarmFaultResumeStale(epoch, current, err);
}

bool SwarmFaultBoard::GpuCrash(std::string& err)
{
    return SwarmFaultGpuCrash(m_checkpoint, m_quiet, err);
}

bool SwarmFaultBoard::WorkerDisconnect(const std::string& task, std::string& err)
{
    return SwarmFaultWorkerDisconnect(m_results, task, err);
}

bool SwarmFaultBoard::DuplicateReceipt(const std::string& task, const std::string& receipt, std::string& err)
{
    return SwarmFaultDuplicateReceipt(m_results, task, receipt, err);
}

bool SwarmFaultBoard::CacheOwnerGone(std::string& err)
{
    return SwarmFaultCacheOwnerGone(m_quiet, err);
}

bool SwarmFaultBoard::TruncatedCache(std::string& err)
{
    return SwarmFaultTruncatedCache(m_quiet, err);
}

bool SwarmFaultBoard::PartialPiece(std::string& err)
{
    return SwarmFaultPartialPiece(m_quiet, err);
}

bool SwarmFaultBoard::PromotionInterrupted(const std::string& channel, std::string& err)
{
    return SwarmFaultPromotionInterrupted(m_heads, channel, err);
}

bool SwarmFaultBoard::CanaryRegress(const std::string& channel, const std::string& previous, std::string& err)
{
    return SwarmFaultCanaryRegress(m_heads, channel, previous, err);
}

bool SwarmFaultBoard::ConflictingReports(std::string& err)
{
    return SwarmFaultConflictingReports(m_quiet, err);
}

bool SwarmFaultBoard::PayCrash(const std::string& work, std::string& err)
{
    return SwarmFaultPayCrash(m_earned, m_quiet, work, err);
}

bool SwarmFaultBoard::RefundMature(std::string& err)
{
    return SwarmFaultRefundMature(m_quiet, err);
}

bool SwarmFaultBoard::Reorg(std::string& err)
{
    return SwarmFaultReorg(m_reserve, err);
}

bool SwarmFaultBoard::DoubleCollateral(int64_t amount, std::string& err)
{
    return SwarmFaultDoubleCollateral(m_reserve, amount, err);
}

bool SwarmFaultBoard::RevokedRead(std::string& err)
{
    return SwarmFaultRevokedRead(m_quiet, err);
}

bool SwarmFaultBoard::DatasetWithdrawn(std::string& err)
{
    return SwarmFaultDatasetWithdrawn(m_quiet, err);
}

bool SwarmFaultBoard::FalseCompat(std::string& err)
{
    return SwarmFaultFalseCompat(m_quiet, err);
}

bool SwarmFaultBoard::PermanentGone(std::string& err)
{
    return SwarmFaultPermanentGone(m_claims, m_earned, err);
}

bool SwarmFaultBoard::Reserve(int64_t amount, std::string& err)
{
    return SwarmFaultReserveAmount(m_reserve, amount, err);
}

std::size_t SwarmFaultBoard::claim_count() const
{
    return m_claims.count();
}

bool SwarmFaultBoard::has_claim(const std::string& task) const
{
    return m_claims.contains(task);
}

std::string SwarmFaultBoard::claim(const std::string& task) const
{
    return m_claims.worker_for(task);
}

bool SwarmFaultBoard::has_result(const std::string& task) const
{
    return m_results.contains(task);
}

std::string SwarmFaultBoard::result(const std::string& task) const
{
    return m_results.receipt_for(task);
}

std::size_t SwarmFaultBoard::earned_count() const
{
    return m_earned.count();
}

bool SwarmFaultBoard::has_earned(const std::string& work) const
{
    return m_earned.contains(work);
}

int64_t SwarmFaultBoard::earned(const std::string& work) const
{
    return m_earned.atoms_for(work);
}

std::string SwarmFaultBoard::head(const std::string& channel) const
{
    return m_heads.head_for(channel);
}

bool SwarmFaultBoard::has_checkpoint() const
{
    return m_checkpoint.kept();
}

std::string SwarmFaultBoard::checkpoint() const
{
    return m_checkpoint.id();
}

int64_t SwarmFaultBoard::epoch() const
{
    return m_epoch.get();
}

bool SwarmFaultBoard::frozen() const
{
    return m_reserve.frozen();
}

bool SwarmFaultBoard::has_reservation() const
{
    return m_reserve.has();
}

int64_t SwarmFaultBoard::reservation() const
{
    return m_reserve.amount();
}

std::size_t SwarmFaultBoard::rollback_count() const
{
    return m_heads.rollback_count();
}

bool SwarmFaultBoard::qualified() const
{
    return m_quiet.qualified();
}

bool SwarmFaultBoard::admitted() const
{
    return m_quiet.admitted();
}

bool SwarmFaultBoard::running() const
{
    return m_quiet.running();
}

bool SwarmFaultBoard::saved() const
{
    return m_quiet.saved();
}

bool SwarmFaultBoard::launched() const
{
    return m_quiet.launched();
}

bool SwarmFaultBoard::gpu() const
{
    return m_quiet.gpu();
}

int64_t SwarmFaultBoard::bytes_moved() const
{
    return m_quiet.bytes_moved();
}

int64_t SwarmFaultBoard::atoms_moved() const
{
    return m_quiet.atoms_moved();
}

std::string SwarmFaultBoard::automatic_spend() const
{
    return m_quiet.automatic_spend();
}

bool SwarmFaultBoard::broadcast() const
{
    return m_quiet.broadcast();
}

bool SwarmFaultBoard::mined() const
{
    return m_quiet.mined();
}

} // namespace modelnet

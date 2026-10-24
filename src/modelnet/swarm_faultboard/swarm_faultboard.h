// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAULTBOARD_H
#define BITCOIN_MODELNET_SWARM_FAULTBOARD_H

#include <modelnet/swarm_faultboard/checkpoint.h>
#include <modelnet/swarm_faultboard/claim.h>
#include <modelnet/swarm_faultboard/earned.h>
#include <modelnet/swarm_faultboard/epoch.h>
#include <modelnet/swarm_faultboard/head.h>
#include <modelnet/swarm_faultboard/quiet.h>
#include <modelnet/swarm_faultboard/reserve.h>
#include <modelnet/swarm_faultboard/result.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * In-process fault recovery record for one swarm.
 *
 * Stores claims, results, earned rows, channel heads, one checkpoint id,
 * one epoch, one collateral reservation, and rollback entries. Does not
 * inject a live fault, start a process, open a socket, broadcast, spend,
 * mine, or move bytes. launched(), gpu(), broadcast(), mined(), saved(),
 * qualified(), admitted(), and running() stay false. bytes_moved() and
 * atoms_moved() stay 0. automatic_spend() stays "0". A stored earned row
 * is never deleted. This plane does not claim a hardware injection.
 *
 * Refusal paths return false and set err to the code. Accepted paths
 * return true and clear err.
 *
 * KeepClaim stores one durable claim per task. The same pair returns true.
 * A different worker for that task is CONFLICT and the first stays.
 * KeepResult stores one receipt per task. The same receipt returns true.
 * A different receipt is CONFLICT and the first stays.
 * KeepEarned stores one row when atoms >= 0 and does not move atoms.
 * atoms below 0 is ATOMS and stores nothing. The same atoms return true.
 * A different atoms value is CONFLICT and the first row stays.
 * KeepHead stores the active head for a channel and may replace it.
 * KeepCheckpoint stores the checkpoint id and may replace it. saved()
 * stays false.
 *
 * CoordinatorGone with a stored claim is DURABLE and keeps the claim.
 * With none it is LOST. Neither path deletes stored rows.
 * ReplaceCoordinator compares the two arguments. new_epoch greater than
 * old_epoch stores new_epoch. Otherwise it is STALE_EPOCH and the stored
 * epoch stays.
 * ResumeStale with epoch < current is STALE and commits nothing.
 * epoch >= current is accepted and stores nothing new.
 * GpuCrash is SAVE_HELD. A previously stored checkpoint id stays.
 * WorkerDisconnect is DISCONNECTED. A stored result stays. Nothing is deleted.
 * DuplicateReceipt of the stored receipt is REPLAY. A different receipt is
 * CONFLICT and the first stays. A task with no result is TASK.
 * CacheOwnerGone is HELD. TruncatedCache is INCOMPLETE. PartialPiece is PIECE.
 * RevokedRead is NOT_READ. bytes_moved() stays 0 on each of these.
 * PromotionInterrupted is NOT_GRADUATED and the active head stays.
 * CanaryRegress with an empty previous is NOT_STAGED and appends nothing.
 * Otherwise the active head for that channel becomes previous, a rollback
 * is appended, and the code is ROLLBACK.
 * ConflictingReports is NOT_AVERAGED. Nothing is averaged.
 * PayCrash is HELD. An earned row stays. A missing row is not created.
 * atoms_moved() stays 0.
 * RefundMature is BROADCAST_FORBIDDEN. broadcast() stays false.
 * Reorg sets frozen() and is FREEZE. Earned rows stay. Later Reserve is
 * FROZEN and stores nothing. Reserve before Reorg stores one reservation
 * when amount >= 1 and none is stored yet. Check order is frozen, then an
 * existing reservation (COLLATERAL_REUSE), then amount below 1 (COLLATERAL).
 * DoubleCollateral shares that one reservation. Its first accepted call
 * stores it and returns true. A later call with any amount, including an
 * amount below 1, is COLLATERAL_REUSE and does not add a second reservation.
 * amount below 1 when none is stored is COLLATERAL. Freeze does not block
 * DoubleCollateral.
 * DatasetWithdrawn is DATASET. running() stays false.
 * FalseCompat is FAMILY_NOT_COMPAT. admitted() stays false.
 * PermanentGone with any earned row or claim is DURABLE and keeps them.
 * Otherwise it is LOST.
 */
class SwarmFaultBoard {
public:
    bool KeepClaim(const std::string& task, const std::string& worker, std::string& err);
    bool KeepResult(const std::string& task, const std::string& receipt, std::string& err);
    bool KeepEarned(const std::string& work, int64_t atoms, std::string& err);
    bool KeepHead(const std::string& channel, const std::string& head, std::string& err);
    bool KeepCheckpoint(const std::string& id, std::string& err);

    bool CoordinatorGone(std::string& err);
    bool ReplaceCoordinator(int64_t old_epoch, int64_t new_epoch, std::string& err);
    bool ResumeStale(int64_t epoch, int64_t current, std::string& err);
    bool GpuCrash(std::string& err);
    bool WorkerDisconnect(const std::string& task, std::string& err);
    bool DuplicateReceipt(const std::string& task, const std::string& receipt, std::string& err);
    bool CacheOwnerGone(std::string& err);
    bool TruncatedCache(std::string& err);
    bool PartialPiece(std::string& err);
    bool PromotionInterrupted(const std::string& channel, std::string& err);
    bool CanaryRegress(const std::string& channel, const std::string& previous, std::string& err);
    bool ConflictingReports(std::string& err);
    bool PayCrash(const std::string& work, std::string& err);
    bool RefundMature(std::string& err);
    bool Reorg(std::string& err);
    bool DoubleCollateral(int64_t amount, std::string& err);
    bool RevokedRead(std::string& err);
    bool DatasetWithdrawn(std::string& err);
    bool FalseCompat(std::string& err);
    bool PermanentGone(std::string& err);
    bool Reserve(int64_t amount, std::string& err);

    std::size_t claim_count() const;
    bool has_claim(const std::string& task) const;
    std::string claim(const std::string& task) const;
    bool has_result(const std::string& task) const;
    std::string result(const std::string& task) const;
    std::size_t earned_count() const;
    bool has_earned(const std::string& work) const;
    int64_t earned(const std::string& work) const;
    std::string head(const std::string& channel) const;
    bool has_checkpoint() const;
    std::string checkpoint() const;
    int64_t epoch() const;
    bool frozen() const;
    bool has_reservation() const;
    int64_t reservation() const;
    std::size_t rollback_count() const;
    bool qualified() const;
    bool admitted() const;
    bool running() const;
    bool saved() const;
    bool launched() const;
    bool gpu() const;
    int64_t bytes_moved() const;
    int64_t atoms_moved() const;
    std::string automatic_spend() const;
    bool broadcast() const;
    bool mined() const;

private:
    SwarmFaultClaimBook m_claims;
    SwarmFaultResultBook m_results;
    SwarmFaultEarnedBook m_earned;
    SwarmFaultHeadBook m_heads;
    SwarmFaultCheckpoint m_checkpoint;
    SwarmFaultEpoch m_epoch;
    SwarmFaultReserve m_reserve;
    SwarmFaultQuiet m_quiet;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAULTBOARD_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_PHASE_DT_PHASE_H
#define BITCOIN_MODELNET_DT_PHASE_DT_PHASE_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** The requested phase is not the single next legal phase. phase() stays. */
inline constexpr char DT_PHASE_ORDER[] = "ORDER";

/** now_ms is greater than or equal to authority_until_ms. Nothing is stored. */
inline constexpr char DT_PHASE_EXPIRED[] = "EXPIRED";

/** The journal did not accept this step. phase() stays. */
inline constexpr char DT_PHASE_JOURNAL[] = "JOURNAL";

/** Advance after Failed. The phase stays Failed. */
inline constexpr char DT_PHASE_FAILED[] = "FAILED";

/**
 * In-memory training phase. The class is DtPhaseEngine because DtPhase is
 * the contract enum.
 *
 * phase() starts at DtPhase::Discovered.
 *
 * Advance accepts only the next phase in this order: Discovered, Eligible,
 * Reserved, Prepared, Running, Snapshotting, CandidateCommitted, Evaluating,
 * Waiting, Draining. A skip, a repeat, or a step backward is ORDER and
 * leaves phase() unchanged.
 *
 * now_ms >= authority_until_ms is EXPIRED, including equality. That refusal
 * stores nothing and leaves phase() unchanged. journal_ok false is JOURNAL
 * and leaves phase() unchanged.
 *
 * Fail from Running sets phase() to DtPhase::Failed. Revoke sets
 * DtPhase::Revoked. Unknown sets DtPhase::OutcomeUnknown. Those three do
 * not take a journal flag. After Revoked or Failed, Advance returns false
 * with NIFDT_REVOKED or FAILED and does not move forward.
 *
 * GpuStep returns false with NIFDT_ENGINE_ABSENT. It does not change
 * phase() and it does not change the stored weight.
 *
 * launched(), gpu(), and broadcast() stay false. automatic_spend() is "0".
 * No socket is opened.
 */
class DtPhaseEngine {
public:
    DtPhase phase() const { return m_phase; }

    /**
     * Move to the single next legal phase.
     * Revoked returns NIFDT_REVOKED. Failed returns FAILED.
     * Expiry is checked before the journal, and the journal before order.
     */
    bool Advance(DtPhase next, int64_t now_ms, int64_t authority_until_ms, bool journal_ok, std::string& err);

    /** From Running, set DtPhase::Failed. Any other phase stays. */
    bool Fail(std::string& err);
    /** Set DtPhase::Revoked. */
    bool Revoke(std::string& err);
    /** Set DtPhase::OutcomeUnknown. */
    bool Unknown(std::string& err);

    /** No GPU step. err is ENGINE_ABSENT. phase() and weight() stay. */
    bool GpuStep(std::string& err);

    /** Stored weight. GpuStep does not write it. */
    int64_t weight() const { return m_weight; }

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    static bool Successor(DtPhase current, DtPhase& next);

    DtPhase m_phase{DtPhase::Discovered};
    int64_t m_weight{static_cast<int64_t>(0)};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_PHASE_DT_PHASE_H

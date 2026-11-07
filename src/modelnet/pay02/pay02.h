// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PAY02_PAY02_H
#define BITCOIN_MODELNET_PAY02_PAY02_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/pay02/native_settlement.h>
#include <modelnet/swarm_payreg/swarm_payreg.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Pay02. DS-PAY-002, DS-PAY-003, DS-OPS-006, and DS-REC-006.
 *
 * RecordFunding stores an objective only when that objective is non-empty
 * and both the refund path and the payout path are set. An empty objective
 * is FIELD. A missing path is PATH and stores nothing. The stored objective
 * is a record, not a wallet settlement. settled() stays false.
 *
 * That record calls SwarmPayReg::Open and SwarmPayReg::Claim. Open records
 * the channel. Claim records the objective. Neither call spends or
 * broadcasts. Settle and Build are not called. atoms_moved() stays 0.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND.
 *
 * ProveExit returns NIFDT_UNQUALIFIED when any of the five flags is absent,
 * and still returns NIFDT_UNQUALIFIED when all five are present. This module
 * does not prove a watchtower.
 *
 * Federate returns ORG when organizations is below 2 or local validation is
 * absent. Two or more organizations with local validation still return
 * NIFDT_UNQUALIFIED. A second organization is not present.
 *
 * ExerciseFaults returns HOSTS when hosts is below 2 and FAULT when a fault
 * flag is absent. All four faults with hosts at or above 2 return
 * NIFDT_UNQUALIFIED. One process is not a cross-host partition.
 * hosts() stays 1.
 *
 * ObserveNative is a separate active-chain observation path: it checks exact
 * funding/spending bytes, confirmations, destinations, fees and CLTV. Its
 * receipt is bound to a chain tip and is reset on failed/reorg observations.
 * Only this path can report settled() or nonzero atoms_moved().
 *
 * passed(), release_qualified(), gpu_passed(), windows_passed(), and
 * hardware_qualified() stay false. This class opens no socket and calls no
 * wallet RPC.
 */
class Pay02 {
public:
    bool RecordFunding(const std::string& objective, bool refund_path, bool payout_path, std::string& err);
    bool ProveExit(bool unilateral, bool expiry, bool fee, bool stale, bool watchtower, std::string& err);
    bool Federate(int organizations, bool local_validation, std::string& err);
    bool ExerciseFaults(bool partition, bool clock_fault, bool response_failure, bool liquidity_loss, int hosts,
                        std::string& err);

    /** Reobserve real funding/settlement through a trusted local chain backend.
     * RecordFunding and the legacy boolean-only qualification methods remain
     * record-only. This method is the native evidence path.
     */
    bool ObserveNative(const NativePaymentChainView& chain, const NativePaymentTerms& terms,
                       const std::optional<Txid>& settlement, std::string& err);
    const NativePaymentReceipt& native_receipt() const { return m_native; }

    std::string objective() const { return m_objective; }
    bool opened() const { return m_opened; }
    bool claim_kept(const std::string& work_id) const { return m_pay.claim_kept(work_id); }
    bool settled() const { return m_native.settled; }

    bool passed() const { return false; }
    bool release_qualified() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool hardware_qualified() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t atoms_moved() const { return m_native.settled ? m_native.paid_atoms : 0; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    bool Quiet(std::string& err) const;

    SwarmPayReg m_pay;
    NativePaymentReceipt m_native;
    bool m_opened{false};
    std::string m_objective;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_PAY02_PAY02_H

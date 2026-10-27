// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/pay02/pay02.h>

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <script/interpreter.h>
#include <string>

namespace modelnet {

bool Pay02::Quiet(std::string& err) const
{
    if (m_pay.automatic_spend() != NIFDT_AUTOMATIC_SPEND || m_pay.atoms_moved() != static_cast<int64_t>(0) ||
        automatic_spend() != NIFDT_AUTOMATIC_SPEND || atoms_moved() != static_cast<int64_t>(0) || settled() ||
        m_pay.broadcast() || m_pay.spendable() || m_pay.qualified() || m_pay.mainnet()) {
        err = NIFDT_AUTOMATIC_SPEND;
        return false;
    }
    return true;
}

bool Pay02::RecordFunding(const std::string& objective, bool refund_path, bool payout_path, std::string& err)
{
    if (objective.empty()) {
        err = "FIELD";
        return false;
    }
    if (!refund_path || !payout_path) {
        err = "PATH";
        return false;
    }
    if (!m_opened) {
        if (!m_pay.Open("record", "refund", "payout", err)) return false;
        if (!Quiet(err)) return false;
        m_opened = true;
    }
    if (!m_pay.Claim(objective, err)) return false;
    if (!Quiet(err)) return false;
    m_objective = objective;
    err.clear();
    return true;
}

bool Pay02::ProveExit(bool unilateral, bool expiry, bool fee, bool stale, bool watchtower, std::string& err)
{
    if (!unilateral || !expiry || !fee || !stale || !watchtower) {
        err = NIFDT_UNQUALIFIED;
        return false;
    }
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Pay02::Federate(int organizations, bool local_validation, std::string& err)
{
    if (organizations < 2 || !local_validation) {
        err = "ORG";
        return false;
    }
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Pay02::ExerciseFaults(bool partition, bool clock_fault, bool response_failure, bool liquidity_loss, int hosts,
                           std::string& err)
{
    if (hosts < 2) {
        err = "HOSTS";
        return false;
    }
    if (!partition || !clock_fault || !response_failure || !liquidity_loss) {
        err = "FAULT";
        return false;
    }
    if (this->hosts() != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err = NIFDT_UNQUALIFIED;
    return false;
}


bool ObserveNativePayment(const NativePaymentChainView& chain, const NativePaymentTerms& terms,
                          const std::optional<Txid>& settlement, NativePaymentReceipt& receipt,
                          std::string& err)
{
    // Clear old PASS before every lookup. A lost coin, RPC error, reorg, or
    // different candidate must not leave a prior settlement latched forever.
    receipt = NativePaymentReceipt{};
    if (terms.objective.empty() || terms.funding.IsNull() || terms.funding_script.empty() ||
        terms.claim_leaf.empty() || terms.refund_leaf.empty() || terms.claim_leaf == terms.refund_leaf ||
        !MoneyRange(terms.principal_atoms) || terms.principal_atoms == 0 ||
        !MoneyRange(terms.max_settlement_fee_atoms) || terms.max_settlement_fee_atoms >= terms.principal_atoms ||
        terms.refund_height == 0 || terms.refund_height >= LOCKTIME_THRESHOLD ||
        terms.min_confirmations < 1 || terms.min_confirmations > 100000) {
        err = "NATIVE_PAYMENT_TERMS";
        return false;
    }
    NativePaymentReceipt next;
    next.chain_tip = chain.Tip();
    next.chain_height = chain.Height();
    next.objective = terms.objective;
    next.funding = terms.funding;
    next.principal_atoms = terms.principal_atoms;
    NativePaymentTransaction funded;
    if (!chain.Lookup(terms.funding.hash, funded, err) || !funded.tx) return false;
    if (funded.tx->GetHash() != terms.funding.hash || terms.funding.n >= funded.tx->vout.size() ||
        funded.tx->vout[terms.funding.n].scriptPubKey != terms.funding_script ||
        funded.tx->vout[terms.funding.n].nValue != terms.principal_atoms) {
        err = "NATIVE_PAYMENT_FUNDING_MISMATCH";
        return false;
    }
    next.funding_confirmations = funded.confirmations;
    next.funded = funded.confirmations >= terms.min_confirmations && !funded.block_hash.IsNull();
    next.state = next.funded ? "FUNDED" : "FUNDING_UNCONFIRMED";
    if (!settlement) {
        CTxOut coin;
        if (next.funded && !chain.Unspent(terms.funding, coin)) next.state = "SPENT_UNRESOLVED";
        if (next.funded && !coin.IsNull() && coin != funded.tx->vout[terms.funding.n]) {
            err = "NATIVE_PAYMENT_COIN_MISMATCH";
            return false;
        }
    } else {
        if (terms.destination.empty()) {
            err = "NATIVE_PAYMENT_DESTINATION_REQUIRED";
            return false;
        }
        NativePaymentTransaction spent;
        if (!chain.Lookup(*settlement, spent, err) || !spent.tx) return false;
        const CTransaction& tx = *spent.tx;
        if (tx.GetHash() != *settlement || tx.vin.size() != 1 || tx.vin[0].prevout != terms.funding ||
            tx.vout.size() != 1 || tx.vout[0].scriptPubKey != terms.destination ||
            !MoneyRange(tx.vout[0].nValue) || tx.vout[0].nValue == 0 ||
            tx.vout[0].nValue > terms.principal_atoms) {
            err = "NATIVE_PAYMENT_SETTLEMENT_MISMATCH";
            return false;
        }
        const auto& witness = tx.vin[0].scriptWitness.stack;
        if (witness.size() < 3) {
            err = "NATIVE_PAYMENT_WITNESS";
            return false;
        }
        const auto& leaf_bytes = witness[witness.size() - 2];
        const CScript leaf(leaf_bytes.begin(), leaf_bytes.end());
        if (leaf == terms.claim_leaf) {
            next.branch = "CLAIM";
        } else if (leaf == terms.refund_leaf) {
            if (tx.nLockTime < terms.refund_height || tx.nLockTime >= LOCKTIME_THRESHOLD ||
                tx.vin[0].nSequence == CTxIn::SEQUENCE_FINAL) {
                err = "NATIVE_PAYMENT_REFUND_LOCK";
                return false;
            }
            next.branch = "REFUND";
        } else {
            err = "NATIVE_PAYMENT_LEAF";
            return false;
        }
        next.fee_atoms = terms.principal_atoms - tx.vout[0].nValue;
        if (next.fee_atoms > terms.max_settlement_fee_atoms) {
            err = "NATIVE_PAYMENT_FEE_CAP";
            return false;
        }
        next.settlement_txid = *settlement;
        next.settlement_confirmations = spent.confirmations;
        next.settled = next.funded && spent.confirmations >= terms.min_confirmations && !spent.block_hash.IsNull();
        next.paid_atoms = next.settled ? tx.vout[0].nValue : 0;
        next.state = next.settled ? (next.branch == "CLAIM" ? "CLAIMED" : "REFUNDED") : "SETTLEMENT_UNCONFIRMED";
    }
    if (chain.Tip() != next.chain_tip || chain.Height() != next.chain_height) {
        err = "NATIVE_PAYMENT_CHAIN_CHANGED";
        return false;
    }
    receipt = std::move(next);
    err.clear();
    return true;
}

bool Pay02::ObserveNative(const NativePaymentChainView& chain, const NativePaymentTerms& terms,
                          const std::optional<Txid>& settlement, std::string& err)
{
    m_opened = false;
    if (!ObserveNativePayment(chain, terms, settlement, m_native, err)) return false;
    m_objective = terms.objective;
    m_opened = m_native.funded;
    return true;
}

} // namespace modelnet

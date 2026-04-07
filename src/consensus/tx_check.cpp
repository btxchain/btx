// Copyright (c) 2017-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_check.h>

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <consensus/validation.h>

#include <set>

bool CheckTransaction(const CTransaction& tx, TxValidationState& state)
{
    const bool has_shielded_inputs = tx.HasShieldedBundle() && tx.GetShieldedBundle().HasShieldedInputs();
    const bool has_shielded_outputs = tx.HasShieldedBundle() && tx.GetShieldedBundle().HasShieldedOutputs();
    const bool has_v2_shielded_state_transition = tx.HasShieldedBundle() && tx.GetShieldedBundle().HasV2Bundle();

    // Basic checks that don't depend on any context
    // `shielded_v2` families can carry fully non-transparent state transitions with no legacy vin/vout legs.
    if (tx.vin.empty() && !has_shielded_inputs && !has_v2_shielded_state_transition)
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vin-empty");
    if (tx.vout.empty() && !has_shielded_outputs && !has_v2_shielded_state_transition)
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-empty");

    if (tx.HasShieldedBundle()) {
        const CShieldedBundle& bundle = tx.GetShieldedBundle();
        if (!bundle.CheckStructure()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-shielded-bundle");
        }
        if (GetTransactionWeight(tx) > MAX_SHIELDED_TX_WEIGHT) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-shielded-oversize");
        }

        std::set<Nullifier> nullifiers;
        for (const auto& spend : bundle.shielded_inputs) {
            if (!nullifiers.insert(spend.nullifier).second) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-shielded-nullifier-duplicate");
            }
        }
    }

    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(TX_NO_WITNESS_WITH_SHIELDED(tx)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-oversize");
    }

    // Check for negative or overflow output values (see CVE-2010-5139)
    CAmount nValueOut = 0;
    for (const auto& txout : tx.vout)
    {
        if (txout.nValue < 0)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-txouttotal-toolarge");
    }

    // Check for duplicate inputs (see CVE-2018-17144)
    // While Consensus::CheckTxInputs does check if all inputs of a tx are available, and UpdateCoins marks all inputs
    // of a tx as spent, it does not check if the tx has duplicate inputs.
    // Failure to run this check will result in either a crash or an inflation bug, depending on the implementation of
    // the underlying coins database.
    std::set<COutPoint> vInOutPoints;
    for (const auto& txin : tx.vin) {
        if (!vInOutPoints.insert(txin.prevout).second)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputs-duplicate");
    }

    if (tx.IsCoinBase())
    {
        if (tx.HasShieldedBundle()) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-cb-shielded");
        }
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-cb-length");
    }
    else
    {
        for (const auto& txin : tx.vin)
            if (txin.prevout.IsNull())
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-prevout-null");
    }

    return true;
}

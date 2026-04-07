// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NOTE: This file is intended to be customised by the end user, and includes only local node policy logic

#include <policy/policy.h>

#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <kernel/mempool_options.h>
#include <policy/feerate.h>
#include <policy/settings.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/pqm.h>
#include <script/script.h>
#include <script/solver.h>
#include <serialize.h>
#include <shielded/bundle.h>
#include <span.h>

#include <algorithm>
#include <cstddef>
#include <limits>
#include <optional>
#include <set>
#include <utility>
#include <vector>

unsigned int g_script_size_policy_limit{DEFAULT_SCRIPT_SIZE_POLICY_LIMIT};

CAmount GetDustThreshold(const CTxOut& txout, const CFeeRate& dustRelayFeeIn)
{
    // "Dust" is defined in terms of dustRelayFee,
    // which has units satoshis-per-kilobyte.
    // If you'd pay more in fees than the value of the output
    // to spend something, then we consider it dust.
    // A typical spendable non-segwit txout is 34 bytes big, and will
    // need a CTxIn of at least 148 bytes to spend:
    // so dust is a spendable txout less than
    // 182*dustRelayFee/1000 (in satoshis).
    // 546 satoshis at the default rate of 3000 sat/kvB.
    // A typical spendable segwit P2WPKH txout is 31 bytes big, and will
    // need a CTxIn of at least 67 bytes to spend:
    // so dust is a spendable txout less than
    // 98*dustRelayFee/1000 (in satoshis).
    // 294 satoshis at the default rate of 3000 sat/kvB.
    if (txout.scriptPubKey.IsUnspendable())
        return 0;

    size_t nSize = GetSerializeSize(txout);
    int witnessversion = 0;
    std::vector<unsigned char> witnessprogram;

    // Note this computation is for spending a Segwit v0 P2WPKH output (a 33 bytes
    // public key + an ECDSA signature). For Segwit v1 Taproot outputs the minimum
    // satisfaction is lower (a single BIP340 signature) but this computation was
    // kept to not further reduce the dust level.
    // See discussion in https://github.com/bitcoin/bitcoin/pull/22779 for details.
    if constexpr (WITNESS_SCALE_FACTOR > 1) {
        if (txout.scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
            // Sum the sizes of the parts of a transaction input with the
            // witness discount applied to the script size.
            nSize += (32 + 4 + 1 + (107 / WITNESS_SCALE_FACTOR) + 4);
        } else {
            nSize += (32 + 4 + 1 + 107 + 4); // the 148 mentioned above
        }
    } else {
        // BTX currently uses a witness scale factor of 1, so witness and
        // non-witness spending have the same dust accounting cost.
        nSize += (32 + 4 + 1 + 107 + 4); // the 148 mentioned above
    }

    return dustRelayFeeIn.GetFee(nSize);
}

bool IsDust(const CTxOut& txout, const CFeeRate& dustRelayFeeIn)
{
    return (txout.nValue < GetDustThreshold(txout, dustRelayFeeIn));
}

namespace {

[[nodiscard]] bool HasNonTransparentShieldedState(const CTransaction& tx)
{
    if (!tx.HasShieldedBundle()) return false;

    const auto& bundle = tx.GetShieldedBundle();
    if (bundle.GetShieldedOutputCount() != 0) return true;

    const auto family = bundle.GetTransactionFamily();
    return family.has_value() &&
           *family == shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR;
}

enum class P2MRLeafType {
    UNKNOWN = 0,
    CHECKSIG_MLDSA,
    CHECKSIG_SLHDSA,
    MULTISIG,
    CLTV_CHECKSIG_MLDSA,
    CLTV_CHECKSIG_SLHDSA,
    CLTV_MULTISIG,
    CSV_MULTISIG,
    CTV_ONLY,
    CTV_CSFS_MLDSA,
    CTV_CSFS_SLHDSA,
    CTV_CHECKSIG_MLDSA,
    CTV_CHECKSIG_SLHDSA,
    CTV_MULTISIG,
    CSFS_MLDSA,
    CSFS_SLHDSA,
    CSFS_VERIFY_CHECKSIG_MLDSA,
    CSFS_VERIFY_CHECKSIG_SLHDSA,
};

P2MRLeafType ChecksigLeafTypeForAlgo(PQAlgorithm algo)
{
    switch (algo) {
    case PQAlgorithm::ML_DSA_44:
        return P2MRLeafType::CHECKSIG_MLDSA;
    case PQAlgorithm::SLH_DSA_128S:
        return P2MRLeafType::CHECKSIG_SLHDSA;
    }
    return P2MRLeafType::UNKNOWN;
}

P2MRLeafType CLTVChecksigLeafTypeForAlgo(PQAlgorithm algo)
{
    switch (algo) {
    case PQAlgorithm::ML_DSA_44:
        return P2MRLeafType::CLTV_CHECKSIG_MLDSA;
    case PQAlgorithm::SLH_DSA_128S:
        return P2MRLeafType::CLTV_CHECKSIG_SLHDSA;
    }
    return P2MRLeafType::UNKNOWN;
}

P2MRLeafType CTVCSFSLeafTypeForAlgo(PQAlgorithm algo)
{
    switch (algo) {
    case PQAlgorithm::ML_DSA_44:
        return P2MRLeafType::CTV_CSFS_MLDSA;
    case PQAlgorithm::SLH_DSA_128S:
        return P2MRLeafType::CTV_CSFS_SLHDSA;
    }
    return P2MRLeafType::UNKNOWN;
}

P2MRLeafType CTVChecksigLeafTypeForAlgo(PQAlgorithm algo)
{
    switch (algo) {
    case PQAlgorithm::ML_DSA_44:
        return P2MRLeafType::CTV_CHECKSIG_MLDSA;
    case PQAlgorithm::SLH_DSA_128S:
        return P2MRLeafType::CTV_CHECKSIG_SLHDSA;
    }
    return P2MRLeafType::UNKNOWN;
}

P2MRLeafType CSFSLeafTypeForAlgo(PQAlgorithm algo)
{
    switch (algo) {
    case PQAlgorithm::ML_DSA_44:
        return P2MRLeafType::CSFS_MLDSA;
    case PQAlgorithm::SLH_DSA_128S:
        return P2MRLeafType::CSFS_SLHDSA;
    }
    return P2MRLeafType::UNKNOWN;
}

std::optional<PQAlgorithm> ChecksigAlgoForLeafType(P2MRLeafType leaf_type)
{
    switch (leaf_type) {
    case P2MRLeafType::CHECKSIG_MLDSA:
    case P2MRLeafType::CLTV_CHECKSIG_MLDSA:
    case P2MRLeafType::CTV_CHECKSIG_MLDSA:
    case P2MRLeafType::CSFS_VERIFY_CHECKSIG_MLDSA:
        return PQAlgorithm::ML_DSA_44;
    case P2MRLeafType::CHECKSIG_SLHDSA:
    case P2MRLeafType::CLTV_CHECKSIG_SLHDSA:
    case P2MRLeafType::CTV_CHECKSIG_SLHDSA:
    case P2MRLeafType::CSFS_VERIFY_CHECKSIG_SLHDSA:
        return PQAlgorithm::SLH_DSA_128S;
    default:
        return std::nullopt;
    }
}

std::optional<PQAlgorithm> CSFSAlgoForLeafType(P2MRLeafType leaf_type)
{
    switch (leaf_type) {
    case P2MRLeafType::CSFS_MLDSA:
    case P2MRLeafType::CTV_CSFS_MLDSA:
        return PQAlgorithm::ML_DSA_44;
    case P2MRLeafType::CSFS_SLHDSA:
    case P2MRLeafType::CTV_CSFS_SLHDSA:
        return PQAlgorithm::SLH_DSA_128S;
    default:
        return std::nullopt;
    }
}

bool IsPolicyChecksigLeaf(Span<const unsigned char> script, PQAlgorithm algo)
{
    Span<const unsigned char> pubkey;
    size_t consumed{0};
    return ParseP2MRPubkeyPush(script, 0, algo, pubkey, consumed) &&
           script.size() == consumed + 1 &&
           script[consumed] == static_cast<unsigned char>(GetP2MRChecksigOpcode(algo));
}

struct P2MRMultisigPolicyInfo {
    uint8_t threshold{0};
    std::vector<PQAlgorithm> key_algorithms;
};

bool ParsePolicyP2MRMultisigLeafScript(Span<const unsigned char> leaf_script, P2MRMultisigPolicyInfo& info)
{
    size_t offset{0};
    std::vector<PQAlgorithm> key_algorithms;
    std::set<std::pair<PQAlgorithm, std::vector<unsigned char>>> unique_pubkeys;
    while (offset < leaf_script.size()) {
        PQAlgorithm algo{PQAlgorithm::ML_DSA_44};
        Span<const unsigned char> pubkey_span;
        size_t push_size{0};
        if (!ParseP2MRAnyPubkeyPush(leaf_script, offset, algo, pubkey_span, push_size)) break;
        std::vector<unsigned char> pubkey(pubkey_span.begin(), pubkey_span.end());
        if (!unique_pubkeys.emplace(algo, std::move(pubkey)).second) return false;

        offset += push_size;
        if (offset >= leaf_script.size()) return false;

        const unsigned char observed = leaf_script[offset];
        const unsigned char expected = key_algorithms.empty()
            ? static_cast<unsigned char>(GetP2MRChecksigOpcode(algo))
            : static_cast<unsigned char>(GetP2MRChecksigAddOpcode(algo));
        if (observed != expected) return false;
        ++offset;
        key_algorithms.push_back(algo);
    }

    if (key_algorithms.size() < 2) return false;
    if (offset + 2 != leaf_script.size()) return false;
    const opcodetype threshold_opcode = static_cast<opcodetype>(leaf_script[offset]);
    if (threshold_opcode < OP_1 || threshold_opcode > OP_16) return false;
    const uint8_t threshold = static_cast<uint8_t>(CScript::DecodeOP_N(threshold_opcode));
    if (threshold == 0 || threshold > key_algorithms.size()) return false;
    if (leaf_script[offset + 1] != static_cast<unsigned char>(OP_NUMEQUAL)) return false;

    info.threshold = threshold;
    info.key_algorithms = std::move(key_algorithms);
    return true;
}

bool ParsePolicyTimelockPrefix(Span<const unsigned char> leaf_script, opcodetype timelock_opcode, size_t& consumed)
{
    const CScript script_obj(leaf_script.begin(), leaf_script.end());
    CScript::const_iterator pc = script_obj.begin();
    opcodetype opcode{OP_INVALIDOPCODE};
    std::vector<unsigned char> push_data;
    if (!script_obj.GetOp(pc, opcode, push_data)) return false;

    switch (opcode) {
    case OP_0:
    case OP_1NEGATE:
        break;
    default:
        if (((opcode < OP_1) || (opcode > OP_16)) && push_data.empty()) return false;
        break;
    }

    if (!script_obj.GetOp(pc, opcode, push_data) || opcode != timelock_opcode) return false;
    if (!script_obj.GetOp(pc, opcode, push_data) || opcode != OP_DROP) return false;
    consumed = std::distance(script_obj.begin(), pc);
    return true;
}

bool ParsePolicyCLTVPrefix(Span<const unsigned char> leaf_script, size_t& consumed)
{
    return ParsePolicyTimelockPrefix(leaf_script, OP_CHECKLOCKTIMEVERIFY, consumed);
}

bool ParsePolicyCSVPrefix(Span<const unsigned char> leaf_script, size_t& consumed)
{
    return ParsePolicyTimelockPrefix(leaf_script, OP_CHECKSEQUENCEVERIFY, consumed);
}

P2MRLeafType ParsePolicyP2MRLeafScript(Span<const unsigned char> leaf_script)
{
    for (const PQAlgorithm algo : GetSupportedPQAlgorithms()) {
        if (IsPolicyChecksigLeaf(leaf_script, algo)) {
            return ChecksigLeafTypeForAlgo(algo);
        }
    }

    if (leaf_script.size() == 1 + 32 + 1 &&
        leaf_script[0] == 32 &&
        leaf_script.back() == static_cast<unsigned char>(OP_CHECKTEMPLATEVERIFY)) {
        return P2MRLeafType::CTV_ONLY;
    }

    if (leaf_script.size() > 35 &&
        leaf_script[0] == 32 &&
        leaf_script[33] == static_cast<unsigned char>(OP_CHECKTEMPLATEVERIFY) &&
        leaf_script[34] == static_cast<unsigned char>(OP_DROP)) {
        const Span<const unsigned char> tail = leaf_script.subspan(35);
        for (const PQAlgorithm algo : GetSupportedPQAlgorithms()) {
            Span<const unsigned char> pubkey;
            size_t csfs_prefix_len{0};
            if (ParseP2MRPubkeyPush(tail, 0, algo, pubkey, csfs_prefix_len) &&
                tail.size() == csfs_prefix_len + 1 &&
                tail[csfs_prefix_len] == static_cast<unsigned char>(OP_CHECKSIGFROMSTACK)) {
                return CTVCSFSLeafTypeForAlgo(algo);
            }
            if (IsPolicyChecksigLeaf(tail, algo)) {
                return CTVChecksigLeafTypeForAlgo(algo);
            }
        }
        P2MRMultisigPolicyInfo multisig_info;
        if (ParsePolicyP2MRMultisigLeafScript(tail, multisig_info)) {
            return P2MRLeafType::CTV_MULTISIG;
        }
    }

    size_t cltv_prefix_len{0};
    if (ParsePolicyCLTVPrefix(leaf_script, cltv_prefix_len) && cltv_prefix_len < leaf_script.size()) {
        const Span<const unsigned char> tail = leaf_script.subspan(cltv_prefix_len);
        for (const PQAlgorithm algo : GetSupportedPQAlgorithms()) {
            if (IsPolicyChecksigLeaf(tail, algo)) {
                return CLTVChecksigLeafTypeForAlgo(algo);
            }
        }
        P2MRMultisigPolicyInfo multisig_info;
        if (ParsePolicyP2MRMultisigLeafScript(tail, multisig_info)) {
            return P2MRLeafType::CLTV_MULTISIG;
        }
    }

    size_t csv_prefix_len{0};
    if (ParsePolicyCSVPrefix(leaf_script, csv_prefix_len) && csv_prefix_len < leaf_script.size()) {
        const Span<const unsigned char> tail = leaf_script.subspan(csv_prefix_len);
        P2MRMultisigPolicyInfo multisig_info;
        if (ParsePolicyP2MRMultisigLeafScript(tail, multisig_info)) {
            return P2MRLeafType::CSV_MULTISIG;
        }
    }

    for (const PQAlgorithm algo : GetSupportedPQAlgorithms()) {
        Span<const unsigned char> pubkey;
        size_t csfs_prefix_len{0};
        if (ParseP2MRPubkeyPush(leaf_script, 0, algo, pubkey, csfs_prefix_len)) {
            if (leaf_script.size() == csfs_prefix_len + 1 &&
                leaf_script[csfs_prefix_len] == static_cast<unsigned char>(OP_CHECKSIGFROMSTACK)) {
                return CSFSLeafTypeForAlgo(algo);
            }
            if (leaf_script.size() > csfs_prefix_len + 2 &&
                leaf_script[csfs_prefix_len] == static_cast<unsigned char>(OP_CHECKSIGFROMSTACK) &&
                leaf_script[csfs_prefix_len + 1] == static_cast<unsigned char>(OP_VERIFY)) {
                const Span<const unsigned char> checksig_tail = leaf_script.subspan(csfs_prefix_len + 2);
                if (IsPolicyChecksigLeaf(checksig_tail, PQAlgorithm::ML_DSA_44)) return P2MRLeafType::CSFS_VERIFY_CHECKSIG_MLDSA;
                if (IsPolicyChecksigLeaf(checksig_tail, PQAlgorithm::SLH_DSA_128S)) return P2MRLeafType::CSFS_VERIFY_CHECKSIG_SLHDSA;
            }
        }
    }

    P2MRMultisigPolicyInfo multisig_info;
    if (ParsePolicyP2MRMultisigLeafScript(leaf_script, multisig_info)) {
        return P2MRLeafType::MULTISIG;
    }

    return P2MRLeafType::UNKNOWN;
}

bool IsDefinedPolicySchnorrHashtype(const uint8_t hash_type)
{
    return (hash_type >= SIGHASH_ALL && hash_type <= SIGHASH_SINGLE) ||
           (hash_type >= (SIGHASH_ANYONECANPAY | SIGHASH_ALL) &&
            hash_type <= (SIGHASH_ANYONECANPAY | SIGHASH_SINGLE));
}

bool IsPolicyP2MRSignatureSize(Span<const unsigned char> signature, PQAlgorithm algo)
{
    const size_t expected_sig_size = GetPQSignatureSize(algo);
    if (signature.size() == expected_sig_size) return true;
    if (signature.size() == expected_sig_size + 1) {
        return IsDefinedPolicySchnorrHashtype(signature.back());
    }
    return false;
}

bool IsPolicyCSFSSignatureSize(Span<const unsigned char> signature, PQAlgorithm algo)
{
    return signature.size() == GetPQSignatureSize(algo);
}

bool ParsePolicyCSFSAlgoForDelegationLeaf(Span<const unsigned char> leaf_script, PQAlgorithm& algo)
{
    for (const PQAlgorithm candidate : GetSupportedPQAlgorithms()) {
        Span<const unsigned char> pubkey;
        size_t csfs_prefix_len{0};
        if (ParseP2MRPubkeyPush(leaf_script, 0, candidate, pubkey, csfs_prefix_len)) {
            if (leaf_script.size() > csfs_prefix_len + 2 &&
                leaf_script[csfs_prefix_len] == static_cast<unsigned char>(OP_CHECKSIGFROMSTACK) &&
                leaf_script[csfs_prefix_len + 1] == static_cast<unsigned char>(OP_VERIFY)) {
                algo = candidate;
                return true;
            }
            return false;
        }
    }
    return false;
}

} // namespace

namespace {

[[nodiscard]] int64_t ScaleShieldedResourceToWeight(const uint64_t resource_units, const uint64_t max_units)
{
    if (resource_units == 0 || max_units == 0) return 0;
    const uint64_t numerator = resource_units * static_cast<uint64_t>(MAX_BLOCK_WEIGHT);
    const uint64_t scaled = (numerator + max_units - 1) / max_units;
    if (scaled > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        return std::numeric_limits<int64_t>::max();
    }
    return static_cast<int64_t>(scaled);
}

} // namespace

std::vector<uint32_t> GetDust(const CTransaction& tx, CFeeRate dust_relay_rate)
{
    std::vector<uint32_t> dust_outputs;
    for (uint32_t i{0}; i < tx.vout.size(); ++i) {
        if (IsDust(tx.vout[i], dust_relay_rate)) dust_outputs.push_back(i);
    }
    return dust_outputs;
}

/**
 * Note this must assign whichType even if returning false, in case
 * IsStandardTx ignores the "scriptpubkey" rejection.
 */
bool IsStandard(const CScript& scriptPubKey, const std::optional<unsigned>& max_datacarrier_bytes, TxoutType& whichType)
{
    std::vector<std::vector<unsigned char> > vSolutions;
    whichType = Solver(scriptPubKey, vSolutions);

    if (whichType == TxoutType::NONSTANDARD) {
        return false;
    }

    // BTX P2MR hard-fork policy: only witness v2 P2MR outputs and OP_RETURN are relay standard.
    if (whichType == TxoutType::NULL_DATA) {
        if (!max_datacarrier_bytes || scriptPubKey.size() > *max_datacarrier_bytes) {
            return false;
        }
        return true;
    }

    return whichType == TxoutType::WITNESS_V2_P2MR;
}

static inline bool MaybeReject_(std::string& out_reason, const std::string& reason, const std::string& reason_prefix, const ignore_rejects_type& ignore_rejects) {
    if (ignore_rejects.count(reason_prefix + reason)) {
        return false;
    }

    out_reason = reason_prefix + reason;
    return true;
}

#define MaybeReject(reason)  do {  \
    if (MaybeReject_(out_reason, reason, reason_prefix, ignore_rejects)) {  \
        return false;  \
    }  \
} while(0)

bool IsStandardTx(const CTransaction& tx, const kernel::MemPoolOptions& opts, std::string& out_reason, const ignore_rejects_type& ignore_rejects)
{
    const std::string reason_prefix;

    if (tx.version > TX_MAX_STANDARD_VERSION || tx.version < 1) {
        MaybeReject("version");
    }

    // Extremely large transactions with lots of inputs can cost the network
    // almost as much to process as they cost the sender in fees, because
    // computing signature hashes is O(ninputs*txsize). Limiting transactions
    // to MAX_STANDARD_TX_WEIGHT mitigates CPU exhaustion attacks.
    const int64_t sz = GetShieldedPolicyWeight(tx);
    const int64_t max_standard_weight = [&tx]() -> int64_t {
        if (!tx.HasShieldedBundle()) return MAX_STANDARD_TX_WEIGHT;
        const auto family = tx.GetShieldedBundle().GetTransactionFamily();
        if (family.has_value() &&
            *family == shielded::v2::TransactionFamily::V2_INGRESS_BATCH) {
            return MAX_STANDARD_INGRESS_SHIELDED_POLICY_WEIGHT;
        }
        return MAX_STANDARD_SHIELDED_POLICY_WEIGHT;
    }();
    if (sz > max_standard_weight) {
        MaybeReject("tx-size");
    }

    if (tx.nLockTime == 21 && opts.reject_parasites) {
        MaybeReject("parasite-cat21");
    }

    for (const CTxIn& txin : tx.vin)
    {
        // Biggest 'standard' txin involving only keys is a 15-of-15 P2SH
        // multisig with compressed keys (remember the MAX_SCRIPT_ELEMENT_SIZE byte limit on
        // redeemScript size). That works out to a (15*(33+1))+3=513 byte
        // redeemScript, 513+1+15*(73+1)+3=1627 bytes of scriptSig, which
        // we round off to 1650(MAX_STANDARD_SCRIPTSIG_SIZE) bytes for
        // some minor future-proofing. That's also enough to spend a
        // 20-of-20 CHECKMULTISIG scriptPubKey, though such a scriptPubKey
        // is not considered standard.
        if (txin.scriptSig.size() > std::min(MAX_STANDARD_SCRIPTSIG_SIZE, g_script_size_policy_limit)) {
            MaybeReject("scriptsig-size");
        }
        if (!txin.scriptSig.IsPushOnly()) {
            MaybeReject("scriptsig-not-pushonly");
        }
    }

    unsigned int nDataOut = 0;
    unsigned int n_dust{0};
    unsigned int n_monetary{0};
    TxoutType whichType;
    for (size_t i{tx.vout.size()}; i; ) {
        const CTxOut& txout = tx.vout[--i];

        if (txout.scriptPubKey.size() > g_script_size_policy_limit) {
            MaybeReject("scriptpubkey-size");
        }

        if (!::IsStandard(txout.scriptPubKey, opts.max_datacarrier_bytes, whichType)) {
            MaybeReject("scriptpubkey");
        }

        if (whichType == TxoutType::WITNESS_UNKNOWN && !opts.acceptunknownwitness) {
            MaybeReject("scriptpubkey-unknown-witnessversion");
        }

        if (whichType == TxoutType::ANCHOR && !opts.permitephemeral_anchor) {
            MaybeReject("anchor");
        }

        if (IsDust(txout, opts.dust_relay_feerate)) {
            if (whichType != TxoutType::ANCHOR && !opts.permitephemeral_send) {
                MaybeReject("dust-nonanchor");
            }
            if (txout.nValue && !opts.permitephemeral_dust) {
                MaybeReject("dust-nonzero");
            }
            ++n_dust;
        } else if (whichType != TxoutType::NULL_DATA) {
            ++n_monetary;
        }

        if (whichType == TxoutType::NULL_DATA) {
            if (txout.scriptPubKey.size() > 2 && txout.scriptPubKey[1] == OP_13 && opts.reject_tokens) {
                MaybeReject("tokens-runes");
            }
            nDataOut++;
            continue;
        }
        else if ((whichType == TxoutType::PUBKEY) && (!opts.permit_bare_pubkey)) {
            MaybeReject("bare-pubkey");
        }
        else if ((whichType == TxoutType::MULTISIG) && (!opts.permit_bare_multisig)) {
            MaybeReject("bare-multisig");
        }
        else if (whichType == TxoutType::WITNESS_V0_SCRIPTHASH && opts.reject_tokens && txout.scriptPubKey.IsOLGA(tx.vout.size() - i))  {
            MaybeReject("tokens-olga");
        }
    }

    // Only MAX_DUST_OUTPUTS_PER_TX dust is permitted(on otherwise valid ephemeral dust)
    if (n_dust > MAX_DUST_OUTPUTS_PER_TX) {
        MaybeReject("dust");
    }

    // only one OP_RETURN txout is permitted
    if (nDataOut > 1) {
        MaybeReject("multi-op-return");
    }

    if (!n_monetary) {
        if (nDataOut && !opts.permitbaredatacarrier) {
            MaybeReject("bare-datacarrier");
        }
        if ((!nDataOut) && !HasNonTransparentShieldedState(tx) && !opts.permitbareanchor) {
            MaybeReject("bare-anchor");
        }
    }

    return true;
}

/**
 * Check the total number of non-witness sigops across the whole transaction, as per BIP54.
 */
static bool CheckSigopsBIP54(const CTransaction& tx, const CCoinsViewCache& inputs, const kernel::MemPoolOptions& opts)
{
    Assert(!tx.IsCoinBase());

    unsigned int sigops{0};
    for (const auto& txin: tx.vin) {
        const auto& prev_txo{inputs.AccessCoin(txin.prevout).out};

        // Unlike the existing block wide sigop limit which counts sigops present in the block
        // itself (including the scriptPubKey which is not executed until spending later), BIP54
        // counts sigops in the block where they are potentially executed (only).
        // This means sigops in the spent scriptPubKey count toward the limit.
        // `fAccurate` means correctly accounting sigops for CHECKMULTISIGs(VERIFY) with 16 pubkeys
        // or fewer. This method of accounting was introduced by BIP16, and BIP54 reuses it.
        // The GetSigOpCount call on the previous scriptPubKey counts both bare and P2SH sigops.
        sigops += txin.scriptSig.GetSigOpCount(/*fAccurate=*/true);
        sigops += prev_txo.scriptPubKey.GetSigOpCount(txin.scriptSig);

        if (sigops > opts.maxtxlegacysigops) {
            return false;
        }
    }

    return true;
}

/**
 * Check transaction inputs to mitigate two
 * potential denial-of-service attacks:
 *
 * 1. scriptSigs with extra data stuffed into them,
 *    not consumed by scriptPubKey (or P2SH script)
 * 2. P2SH scripts with a crazy number of expensive
 *    CHECKSIG/CHECKMULTISIG operations
 *
 * Why bother? To avoid denial-of-service attacks; an attacker
 * can submit a standard HASH... OP_EQUAL transaction,
 * which will get accepted into blocks. The redemption
 * script can be anything; an attacker could use a very
 * expensive-to-check-upon-redemption script like:
 *   DUP CHECKSIG DROP ... repeated 100 times... OP_1
 *
 * Note that only the non-witness portion of the transaction is checked here.
 *
 * We also check the total number of non-witness sigops across the whole transaction, as per BIP54.
 */
bool AreInputsStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs, const kernel::MemPoolOptions& opts, const std::string& reason_prefix, std::string& out_reason, const ignore_rejects_type& ignore_rejects)
{
    if (tx.IsCoinBase()) {
        return true; // Coinbases don't use vin normally
    }

    if (!CheckSigopsBIP54(tx, mapInputs, opts)) {
        MaybeReject("sigops-toomany-overall");
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const CTxOut& prev = mapInputs.AccessCoin(tx.vin[i].prevout).out;

        if (prev.scriptPubKey.size() > g_script_size_policy_limit) {
            MaybeReject("script-size");
        }

        std::vector<std::vector<unsigned char> > vSolutions;
        TxoutType whichType = Solver(prev.scriptPubKey, vSolutions);
        if (whichType == TxoutType::NONSTANDARD) {
            MaybeReject("script-unknown");
        } else if (whichType == TxoutType::WITNESS_UNKNOWN) {
            // WITNESS_UNKNOWN failures are typically also caught with a policy
            // flag in the script interpreter, but it can be helpful to catch
            // this type of NONSTANDARD transaction earlier in transaction
            // validation.
            MaybeReject("witness-unknown");
        } else if (whichType == TxoutType::SCRIPTHASH) {
            if (!tx.vin[i].scriptSig.IsPushOnly()) {
                // The only way we got this far, is if the user ignored scriptsig-not-pushonly.
                // However, this case is invalid, and will be caught later on.
                // But for now, we don't want to run the [possibly expensive] script here.
                continue;
            }
            std::vector<std::vector<unsigned char> > stack;
            // convert the scriptSig into a stack, so we can inspect the redeemScript
            if (!EvalScript(stack, tx.vin[i].scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE))
            {
                // This case is also invalid or a bug
                out_reason = reason_prefix + "scriptsig-failure";
                return false;
            }
            if (stack.empty())
            {
                // Also invalid
                out_reason = reason_prefix + "scriptcheck-missing";
                return false;
            }
            CScript subscript(stack.back().begin(), stack.back().end());
            if (subscript.size() > g_script_size_policy_limit) {
                MaybeReject("scriptcheck-size");
            }
            if (subscript.GetSigOpCount(true) > MAX_P2SH_SIGOPS) {
                MaybeReject("scriptcheck-sigops");
            }
        }
    }

    return true;
}

bool IsWitnessStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs, const std::string& reason_prefix, std::string& out_reason, const ignore_rejects_type& ignore_rejects)
{
    if (tx.IsCoinBase())
        return true; // Coinbases are skipped

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        // We don't care if witness for this input is empty, since it must not be bloated.
        // If the script is invalid without witness, it would be caught sooner or later during validation.
        if (tx.vin[i].scriptWitness.IsNull())
            continue;

        const CTxOut &prev = mapInputs.AccessCoin(tx.vin[i].prevout).out;

        // get the scriptPubKey corresponding to this input:
        CScript prevScript = prev.scriptPubKey;

        // witness stuffing detected
        if (prevScript.IsPayToAnchor()) {
            MaybeReject("anchor-not-empty");
        }

        bool p2sh = false;
        if (prevScript.IsPayToScriptHash()) {
            std::vector <std::vector<unsigned char> > stack;
            // If the scriptPubKey is P2SH, we try to extract the redeemScript casually by converting the scriptSig
            // into a stack. We do not check IsPushOnly nor compare the hash as these will be done later anyway.
            // If the check fails at this stage, we know that this txid must be a bad one.
            if (!EvalScript(stack, tx.vin[i].scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE))
            {
                out_reason = reason_prefix + "scriptsig-failure";
                return false;
            }
            if (stack.empty())
            {
                out_reason = reason_prefix + "scriptcheck-missing";
                return false;
            }
            prevScript = CScript(stack.back().begin(), stack.back().end());
            p2sh = true;
        }

        int witnessversion = 0;
        std::vector<unsigned char> witnessprogram;

        // Non-witness program must not be associated with any witness
        if (!prevScript.IsWitnessProgram(witnessversion, witnessprogram))
        {
            out_reason = reason_prefix + "nonwitness-input";
            return false;
        }

        const bool is_p2mr = witnessversion == 2 && witnessprogram.size() == WITNESS_V2_P2MR_SIZE && !p2sh;
        if (!is_p2mr && GetSerializeSize(tx.vin[i].scriptWitness.stack) > g_script_size_policy_limit) {
            MaybeReject("witness-size");
        }

        // Check P2WSH standard limits
        if (witnessversion == 0 && witnessprogram.size() == WITNESS_V0_SCRIPTHASH_SIZE) {
            if (tx.vin[i].scriptWitness.stack.back().size() > MAX_STANDARD_P2WSH_SCRIPT_SIZE)
                MaybeReject("script-size");
            size_t sizeWitnessStack = tx.vin[i].scriptWitness.stack.size() - 1;
            if (sizeWitnessStack > MAX_STANDARD_P2WSH_STACK_ITEMS)
                MaybeReject("stackitem-count");
            for (unsigned int j = 0; j < sizeWitnessStack; j++) {
                if (tx.vin[i].scriptWitness.stack[j].size() > MAX_STANDARD_P2WSH_STACK_ITEM_SIZE)
                    MaybeReject("stackitem-size");
            }
        }

        // Check policy limits for Taproot spends:
        // - MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE limit for stack item size
        // - No annexes
        if (witnessversion == 1 && witnessprogram.size() == WITNESS_V1_TAPROOT_SIZE && !p2sh) {
            // Taproot spend (non-P2SH-wrapped, version 1, witness program size 32; see BIP 341)
            Span stack{tx.vin[i].scriptWitness.stack};
            if (stack.size() >= 2 && !stack.back().empty() && stack.back()[0] == ANNEX_TAG) {
                // Annexes are nonstandard as long as no semantics are defined for them.
                MaybeReject("taproot-annex");
                // If reject reason is ignored, continue as if the annex wasn't there.
                SpanPopBack(stack);
            }
            if (stack.size() >= 2) {
                // Script path spend (2 or more stack elements after removing optional annex)
                const auto& control_block = SpanPopBack(stack);
                SpanPopBack(stack); // Ignore script
                if (control_block.empty()) {
                    // Empty control block is invalid
                    out_reason = reason_prefix + "taproot-control-missing";
                    return false;
                }
                if ((control_block[0] & TAPROOT_LEAF_MASK) == TAPROOT_LEAF_TAPSCRIPT) {
                    // Leaf version 0xc0 (aka Tapscript, see BIP 342)
                    if (!ignore_rejects.count(reason_prefix + "taproot-stackitem-size")) {
                    for (const auto& item : stack) {
                            if (item.size() > MAX_STANDARD_TAPSCRIPT_STACK_ITEM_SIZE) {
                                out_reason = reason_prefix + "taproot-stackitem-size";
                                return false;
                            }
                        }
                    }
                }
            } else if (stack.size() == 1) {
                // Key path spend (1 stack element after removing optional annex)
                // (no policy rules apply)
            } else {
                // 0 stack elements; this is already invalid by consensus rules
                out_reason = reason_prefix + "taproot-witness-missing";
                return false;
            }
        }

        // Check policy limits for P2MR spends:
        // - no P2SH wrapping
        // - control block has expected shape/version
        // - witness stack shape/signature size/leaf script format are constrained
        // - leaf script remains bounded by policy script size limit
        if (is_p2mr) {
            Span<const std::vector<unsigned char>> stack{tx.vin[i].scriptWitness.stack};
            if (stack.size() >= 3 && !stack.back().empty() && stack.back()[0] == ANNEX_TAG) {
                // Annexes are consensus-valid but nonstandard for P2MR until semantics are defined.
                MaybeReject("p2mr-annex");
                SpanPopBack(stack);
            }
            if (stack.size() < 2) {
                out_reason = reason_prefix + "p2mr-witness-missing";
                return false;
            }
            if (stack.size() < 2 || stack.size() > MAX_PQ_PUBKEYS_PER_MULTISIG + 2) {
                out_reason = reason_prefix + "p2mr-stack-size";
                return false;
            }
            const std::vector<unsigned char>& control_block = stack.back();
            const std::vector<unsigned char>& leaf_script = stack[stack.size() - 2];
            if (control_block.size() < P2MR_CONTROL_BASE_SIZE ||
                control_block.size() > P2MR_CONTROL_MAX_SIZE ||
                ((control_block.size() - P2MR_CONTROL_BASE_SIZE) % P2MR_CONTROL_NODE_SIZE) != 0) {
                out_reason = reason_prefix + "p2mr-control-size";
                return false;
            }
            if ((control_block[0] & P2MR_LEAF_MASK) != P2MR_LEAF_VERSION) {
                out_reason = reason_prefix + "p2mr-leaf-version";
                return false;
            }
            const P2MRLeafType leaf_type = ParsePolicyP2MRLeafScript(leaf_script);
            if (leaf_type == P2MRLeafType::UNKNOWN) {
                out_reason = reason_prefix + "p2mr-leaf-script";
                return false;
            }

            switch (leaf_type) {
            case P2MRLeafType::CTV_ONLY:
                if (stack.size() != 2) {
                    out_reason = reason_prefix + "p2mr-stack-size";
                    return false;
                }
                break;
            case P2MRLeafType::CHECKSIG_MLDSA:
            case P2MRLeafType::CHECKSIG_SLHDSA:
            case P2MRLeafType::CLTV_CHECKSIG_MLDSA:
            case P2MRLeafType::CLTV_CHECKSIG_SLHDSA:
            case P2MRLeafType::CTV_CHECKSIG_MLDSA:
            case P2MRLeafType::CTV_CHECKSIG_SLHDSA: {
                if (stack.size() != 3) {
                    out_reason = reason_prefix + "p2mr-stack-size";
                    return false;
                }
                const auto algo = ChecksigAlgoForLeafType(leaf_type);
                if (!algo.has_value() || !IsPolicyP2MRSignatureSize(stack[0], *algo)) {
                    out_reason = reason_prefix + "p2mr-signature-size";
                    return false;
                }
                break;
            }
            case P2MRLeafType::MULTISIG:
            case P2MRLeafType::CLTV_MULTISIG:
            case P2MRLeafType::CSV_MULTISIG:
            case P2MRLeafType::CTV_MULTISIG: {
                P2MRMultisigPolicyInfo multisig_info;
                Span<const unsigned char> multisig_script = leaf_script;
                size_t prefix_len{0};
                if (leaf_type == P2MRLeafType::CLTV_MULTISIG) {
                    if (!ParsePolicyCLTVPrefix(leaf_script, prefix_len) || prefix_len >= leaf_script.size()) {
                        out_reason = reason_prefix + "p2mr-leaf-script";
                        return false;
                    }
                    multisig_script = Span<const unsigned char>{leaf_script}.subspan(prefix_len);
                } else if (leaf_type == P2MRLeafType::CSV_MULTISIG) {
                    if (!ParsePolicyCSVPrefix(leaf_script, prefix_len) || prefix_len >= leaf_script.size()) {
                        out_reason = reason_prefix + "p2mr-leaf-script";
                        return false;
                    }
                    multisig_script = Span<const unsigned char>{leaf_script}.subspan(prefix_len);
                } else if (leaf_type == P2MRLeafType::CTV_MULTISIG) {
                    if (leaf_script.size() <= 35 ||
                        leaf_script[0] != 32 ||
                        leaf_script[33] != static_cast<unsigned char>(OP_CHECKTEMPLATEVERIFY) ||
                        leaf_script[34] != static_cast<unsigned char>(OP_DROP)) {
                        out_reason = reason_prefix + "p2mr-leaf-script";
                        return false;
                    }
                    multisig_script = Span<const unsigned char>{leaf_script}.subspan(35);
                }
                if (!ParsePolicyP2MRMultisigLeafScript(multisig_script, multisig_info)) {
                    out_reason = reason_prefix + "p2mr-leaf-script";
                    return false;
                }
                if (multisig_info.key_algorithms.size() > MAX_PQ_PUBKEYS_PER_MULTISIG) {
                    out_reason = reason_prefix + "p2mr-multisig-keys";
                    return false;
                }
                if (stack.size() != multisig_info.key_algorithms.size() + 2) {
                    out_reason = reason_prefix + "p2mr-stack-size";
                    return false;
                }
                size_t non_empty_signatures{0};
                for (size_t key_pos = 0; key_pos < multisig_info.key_algorithms.size(); ++key_pos) {
                    const size_t witness_pos = multisig_info.key_algorithms.size() - 1 - key_pos;
                    const auto& signature = stack[witness_pos];
                    if (signature.empty()) continue;
                    if (!IsPolicyP2MRSignatureSize(signature, multisig_info.key_algorithms[key_pos])) {
                        out_reason = reason_prefix + "p2mr-signature-size";
                        return false;
                    }
                    ++non_empty_signatures;
                }
                if (non_empty_signatures != multisig_info.threshold) {
                    out_reason = reason_prefix + "p2mr-multisig-threshold";
                    return false;
                }
                break;
            }
            case P2MRLeafType::CSFS_MLDSA:
            case P2MRLeafType::CSFS_SLHDSA: {
                if (stack.size() != 4) {
                    out_reason = reason_prefix + "p2mr-stack-size";
                    return false;
                }
                const auto algo = CSFSAlgoForLeafType(leaf_type);
                if (!algo.has_value() || !IsPolicyCSFSSignatureSize(stack[0], *algo)) {
                    out_reason = reason_prefix + "p2mr-csfs-signature-size";
                    return false;
                }
                if (stack[1].size() > MAX_SCRIPT_ELEMENT_SIZE) {
                    out_reason = reason_prefix + "p2mr-csfs-msg-size";
                    return false;
                }
                break;
            }
            case P2MRLeafType::CTV_CSFS_MLDSA:
            case P2MRLeafType::CTV_CSFS_SLHDSA: {
                if (stack.size() != 4) {
                    out_reason = reason_prefix + "p2mr-stack-size";
                    return false;
                }
                const auto algo = CSFSAlgoForLeafType(leaf_type);
                if (!algo.has_value() || !IsPolicyCSFSSignatureSize(stack[0], *algo)) {
                    out_reason = reason_prefix + "p2mr-csfs-signature-size";
                    return false;
                }
                if (stack[1].size() > MAX_SCRIPT_ELEMENT_SIZE) {
                    out_reason = reason_prefix + "p2mr-csfs-msg-size";
                    return false;
                }
                break;
            }
            case P2MRLeafType::CSFS_VERIFY_CHECKSIG_MLDSA:
            case P2MRLeafType::CSFS_VERIFY_CHECKSIG_SLHDSA: {
                if (stack.size() != 5) {
                    out_reason = reason_prefix + "p2mr-stack-size";
                    return false;
                }
                const auto checksig_algo = ChecksigAlgoForLeafType(leaf_type);
                if (!checksig_algo.has_value() || !IsPolicyP2MRSignatureSize(stack[0], *checksig_algo)) {
                    out_reason = reason_prefix + "p2mr-signature-size";
                    return false;
                }
                PQAlgorithm csfs_algo{PQAlgorithm::ML_DSA_44};
                if (!ParsePolicyCSFSAlgoForDelegationLeaf(leaf_script, csfs_algo)) {
                    out_reason = reason_prefix + "p2mr-leaf-script";
                    return false;
                }
                if (!IsPolicyCSFSSignatureSize(stack[1], csfs_algo)) {
                    out_reason = reason_prefix + "p2mr-csfs-signature-size";
                    return false;
                }
                if (stack[2].size() > MAX_SCRIPT_ELEMENT_SIZE) {
                    out_reason = reason_prefix + "p2mr-csfs-msg-size";
                    return false;
                }
                break;
            }
            default:
                out_reason = reason_prefix + "p2mr-leaf-script";
                return false;
            }
            const size_t max_leaf_size = (leaf_type == P2MRLeafType::MULTISIG ||
                                          leaf_type == P2MRLeafType::CLTV_MULTISIG ||
                                          leaf_type == P2MRLeafType::CSV_MULTISIG ||
                                          leaf_type == P2MRLeafType::CTV_MULTISIG)
                ? static_cast<size_t>(MAX_P2MR_SCRIPT_SIZE)
                : static_cast<size_t>(g_script_size_policy_limit);
            if (leaf_script.size() > max_leaf_size) {
                out_reason = reason_prefix + "p2mr-script-size";
                return false;
            }
        }
    }
    return true;
}

bool SpendsNonAnchorWitnessProg(const CTransaction& tx, const CCoinsViewCache& prevouts)
{
    if (tx.IsCoinBase()) {
        return false;
    }

    int version;
    std::vector<uint8_t> program;
    for (const auto& txin: tx.vin) {
        const auto& prev_spk{prevouts.AccessCoin(txin.prevout).out.scriptPubKey};

        // Note this includes not-yet-defined witness programs.
        if (prev_spk.IsWitnessProgram(version, program) && !prev_spk.IsPayToAnchor(version, program)) {
            return true;
        }

        // For P2SH extract the redeem script and check if it spends a non-Taproot witness program. Note
        // this is fine to call EvalScript (as done in AreInputsStandard/IsWitnessStandard) because this
        // function is only ever called after IsStandardTx, which checks the scriptsig is pushonly.
        if (prev_spk.IsPayToScriptHash()) {
            // If EvalScript fails or results in an empty stack, the transaction is invalid by consensus.
            std::vector <std::vector<uint8_t>> stack;
            if (!EvalScript(stack, txin.scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, SigVersion::BASE)
                || stack.empty()) {
                continue;
            }
            const CScript redeem_script{stack.back().begin(), stack.back().end()};
            if (redeem_script.IsWitnessProgram(version, program)) {
                return true;
            }
        }
    }

    return false;
}

int64_t GetVirtualTransactionSize(int64_t nWeight, int64_t nSigOpCost, unsigned int bytes_per_sigop)
{
    return (std::max(nWeight, nSigOpCost * bytes_per_sigop) + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR;
}

int64_t GetVirtualTransactionSize(const CTransaction& tx, int64_t nSigOpCost, unsigned int bytes_per_sigop)
{
    return GetVirtualTransactionSize(GetTransactionWeight(tx), nSigOpCost, bytes_per_sigop);
}

int64_t GetVirtualTransactionInputSize(const CTxIn& txin, int64_t nSigOpCost, unsigned int bytes_per_sigop)
{
    return GetVirtualTransactionSize(GetTransactionInputWeight(txin), nSigOpCost, bytes_per_sigop);
}

std::pair<CScript, unsigned int> GetScriptForTransactionInput(CScript prevScript, const CTxIn& txin)
{
    bool p2sh = false;
    if (prevScript.IsPayToScriptHash()) {
        std::vector <std::vector<unsigned char> > stack;
        if (!EvalScript(stack, txin.scriptSig, SCRIPT_VERIFY_NONE, BaseSignatureChecker(), SigVersion::BASE)) {
            return std::make_pair(CScript(), 0);
        }
        if (stack.empty()) {
            return std::make_pair(CScript(), 0);
        }
        prevScript = CScript(stack.back().begin(), stack.back().end());
        p2sh = true;
    }

    int witnessversion = 0;
    std::vector<unsigned char> witnessprogram;

    if (!prevScript.IsWitnessProgram(witnessversion, witnessprogram)) {
        // For P2SH, scriptSig is always push-only, so the actual script is only the last stack item
        // For non-P2SH, prevScript is likely the real script, but not part of this transaction, and scriptSig could very well be executable, so return the latter instead
        return std::make_pair(p2sh ? prevScript : txin.scriptSig, WITNESS_SCALE_FACTOR);
    }

    Span stack{txin.scriptWitness.stack};

    if (witnessversion == 0 && witnessprogram.size() == WITNESS_V0_SCRIPTHASH_SIZE) {
        if (stack.empty()) return std::make_pair(CScript(), 0);  // invalid
        auto& script_data = stack.back();
        prevScript = CScript(script_data.begin(), script_data.end());
        return std::make_pair(prevScript, 1);
    }

    if (witnessversion == 1 && witnessprogram.size() == WITNESS_V1_TAPROOT_SIZE && !p2sh) {
        if (stack.size() >= 2 && !stack.back().empty() && stack.back()[0] == ANNEX_TAG) {
            SpanPopBack(stack);
        }
        if (stack.size() >= 2) {
            SpanPopBack(stack);  // Ignore control block
            prevScript = CScript(stack.back().begin(), stack.back().end());
            return std::make_pair(prevScript, 1);
        }
    }

    return std::make_pair(CScript(), 0);
}

std::pair<size_t, size_t> DatacarrierBytes(const CTransaction& tx, const CCoinsViewCache& view)
{
    std::pair<size_t, size_t> ret{0, 0};

    for (const CTxIn& txin : tx.vin) {
        const CTxOut &utxo = view.AccessCoin(txin.prevout).out;
        auto[script, consensus_weight_per_byte] = GetScriptForTransactionInput(utxo.scriptPubKey, txin);
        const auto dcb = script.DatacarrierBytes(0);
        ret.first += dcb.first;
        ret.second += dcb.second;
    }
    for (size_t i{tx.vout.size()}; i; ) {
        const CTxOut& txout = tx.vout[--i];
        const auto dcb = txout.scriptPubKey.DatacarrierBytes(tx.vout.size() - i);
        ret.first += dcb.first;
        ret.second += dcb.second;
    }

    return ret;
}

int32_t CalculateExtraTxWeight(const CTransaction& tx, const CCoinsViewCache& view, const unsigned int weight_per_data_byte)
{
    int64_t mod_weight{0};
    const int64_t base_weight = GetTransactionWeight(tx);
    const int64_t shielded_weight = GetShieldedPolicyWeight(tx);
    if (shielded_weight <= std::numeric_limits<int64_t>::max() - mod_weight) {
        mod_weight += shielded_weight - base_weight;
    } else {
        mod_weight = std::numeric_limits<int64_t>::max();
    }

    // Add in any extra weight for data bytes
    if (weight_per_data_byte > 1) {
        for (const CTxIn& txin : tx.vin) {
            const CTxOut &utxo = view.AccessCoin(txin.prevout).out;
            auto[script, consensus_weight_per_byte] = GetScriptForTransactionInput(utxo.scriptPubKey, txin);
            if (weight_per_data_byte > consensus_weight_per_byte) {
                const auto dcb = script.DatacarrierBytes(0);
                mod_weight += static_cast<int64_t>(dcb.first + dcb.second) *
                              static_cast<int64_t>(weight_per_data_byte - consensus_weight_per_byte);
            }
        }
        if (weight_per_data_byte > WITNESS_SCALE_FACTOR) {
            for (size_t i{tx.vout.size()}; i; ) {
                const CTxOut& txout = tx.vout[--i];
                const auto dcb = txout.scriptPubKey.DatacarrierBytes(tx.vout.size() - i);
                mod_weight += static_cast<int64_t>(dcb.first + dcb.second) *
                              static_cast<int64_t>(weight_per_data_byte - WITNESS_SCALE_FACTOR);
            }
        }
    }

    if (mod_weight < std::numeric_limits<int32_t>::min()) return std::numeric_limits<int32_t>::min();
    if (mod_weight > std::numeric_limits<int32_t>::max()) return std::numeric_limits<int32_t>::max();
    return static_cast<int32_t>(mod_weight);
}

int64_t GetShieldedPolicyWeight(const CTransaction& tx)
{
    const int64_t base_weight = GetTransactionWeight(tx);
    if (!tx.HasShieldedBundle()) return base_weight;

    const auto usage = GetShieldedResourceUsage(tx.GetShieldedBundle());
    const int64_t serialized_weight =
        ScaleShieldedResourceToWeight(::GetSerializeSize(TX_WITH_WITNESS(tx)), MAX_BLOCK_SERIALIZED_SIZE);
    const int64_t verify_weight =
        ScaleShieldedResourceToWeight(usage.verify_units, Consensus::DEFAULT_MAX_BLOCK_SHIELDED_VERIFY_COST);
    const int64_t scan_weight =
        ScaleShieldedResourceToWeight(usage.scan_units, Consensus::DEFAULT_MAX_BLOCK_SHIELDED_SCAN_UNITS);
    const int64_t tree_weight =
        ScaleShieldedResourceToWeight(usage.tree_update_units, Consensus::DEFAULT_MAX_BLOCK_SHIELDED_TREE_UPDATE_UNITS);

    return std::max<int64_t>({1, serialized_weight, verify_weight, scan_weight, tree_weight});
}

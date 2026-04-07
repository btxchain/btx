// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/shielded_wallet.h>

#include <bech32.h>
#include <chainparams.h>
#include <common/args.h>
#include <psbt.h>
#include <coins.h>
#include <crypto/aes.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <util/overflow.h>
#include <interfaces/chain.h>
#include <key.h>
#include <key_io.h>
#include <logging.h>
#include <policy/policy.h>
#include <primitives/block.h>
#include <random.h>
#include <shielded/ringct/matrict.h>
#include <shielded/smile2/wallet_bridge.h>
#include <shielded/v2_bundle.h>
#include <shielded/ringct/ring_selection.h>
#include <shielded/v2_egress.h>
#include <shielded/v2_ingress.h>
#include <shielded/v2_send.h>
#include <streams.h>
#include <support/allocators/secure.h>
#include <support/cleanse.h>
#include <tinyformat.h>
#include <util/moneystr.h>
#include <util/strencodings.h>
#include <wallet/crypter.h>
#include <wallet/pq_keyderivation.h>
#include <wallet/shielded_privacy.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>

#ifdef OPAQUE
#undef OPAQUE
#endif

#include <wallet/walletdb.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>

namespace wallet {
namespace {

static constexpr const char* SHIELDED_HRP{"btxs"};
static constexpr uint8_t SHIELDED_ADDRESS_VERSION_LEGACY_HASH_ONLY{0x00};
static constexpr uint8_t SHIELDED_ADDRESS_VERSION_WITH_KEM_PUBKEY{0x01};
static constexpr uint8_t SHIELDED_ADDRESS_ALGO_BYTE{0x00};
static constexpr size_t SHIELDED_ADDRESS_BASE_PAYLOAD_SIZE{66};
static constexpr size_t SHIELDED_ADDRESS_EXTENDED_PAYLOAD_SIZE{
    SHIELDED_ADDRESS_BASE_PAYLOAD_SIZE + mlkem::PUBLICKEYBYTES};
static constexpr int SHIELDED_ADDRESS_CHAR_LIMIT{3000};
static constexpr uint32_t SHIELDED_STATE_VERSION{4};
static constexpr uint8_t SHIELDED_ADDRESS_LIFECYCLE_VERSION{1};
static constexpr size_t MAX_V2_SEND_BUILDER_PROOF_ATTEMPTS{4};
static constexpr const char* SHIELDED_ENCRYPTION_REQUIRED_ERROR{
    "Shielded keys require an encrypted wallet; encrypt this wallet before using shielded features"};
static constexpr std::string_view WALLET_SECRET_PURPOSE_PQ_MASTER_SEED{"pqmasterseed"};
static constexpr std::string_view WALLET_SECRET_PURPOSE_SHIELDED_STATE{"shieldedstate"};
struct ResolvedV2ShieldedRecipient
{
    shielded::v2::V2EgressRecipient recipient;
    const mlkem::SecretKey* local_recipient_kem_sk{nullptr};
    ShieldedAddress effective_addr;
};

[[nodiscard]] uint256 HashBytes(Span<const unsigned char> bytes)
{
    uint256 out;
    CSHA256().Write(bytes.data(), bytes.size()).Finalize(out.begin());
    return out;
}

[[nodiscard]] std::vector<uint8_t> SerializeV2SendWitness(
    const shielded::v2::proof::V2SendWitness& witness)
{
    DataStream witness_stream;
    witness_stream << witness;
    if (witness_stream.empty()) return {};
    const auto* begin = reinterpret_cast<const uint8_t*>(witness_stream.data());
    return {begin, begin + witness_stream.size()};
}

[[nodiscard]] bool ProofEnvelopesEqual(const shielded::v2::ProofEnvelope& lhs,
                                       const shielded::v2::ProofEnvelope& rhs)
{
    return lhs.version == rhs.version &&
           lhs.proof_kind == rhs.proof_kind &&
           lhs.membership_proof_kind == rhs.membership_proof_kind &&
           lhs.amount_proof_kind == rhs.amount_proof_kind &&
           lhs.balance_proof_kind == rhs.balance_proof_kind &&
           lhs.settlement_binding_kind == rhs.settlement_binding_kind &&
           lhs.statement_digest == rhs.statement_digest &&
           lhs.extension_digest == rhs.extension_digest;
}

[[nodiscard]] int32_t NextShieldedBuildValidationHeight(interfaces::Chain& chain)
{
    const auto tip_height = chain.getHeight();
    if (!tip_height.has_value() ||
        *tip_height < 0 ||
        *tip_height >= std::numeric_limits<int32_t>::max() - 1) {
        return std::numeric_limits<int32_t>::max();
    }
    return *tip_height + 1;
}

[[nodiscard]] bool ValidatePostForkCoinbaseShieldingCompatibility(const CWallet& wallet,
                                                                  Span<const COutPoint> utxos,
                                                                  int32_t validation_height,
                                                                  std::string& error)
    EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    if (AllowTransparentShieldingInDirectSendAtHeight(validation_height)) {
        return true;
    }

    for (const auto& outpoint : utxos) {
        const CWalletTx* wtx = wallet.GetWalletTx(outpoint.hash);
        if (wtx == nullptr || outpoint.n >= wtx->tx->vout.size()) {
            error = strprintf("missing wallet tx for outpoint %s:%u", outpoint.hash.GetHex(), outpoint.n);
            return false;
        }
        if (!wtx->IsCoinBase()) {
            error = GetPostForkCoinbaseShieldingCompatibilityMessage();
            return false;
        }
        if (wallet.GetTxBlocksToMaturity(*wtx) > 0) {
            error = "post-fork direct transparent shielding compatibility requires mature coinbase outputs";
            return false;
        }
    }
    return true;
}

[[nodiscard]] constexpr CAmount GetShieldedSmileValueLimit()
{
    return static_cast<CAmount>(smile2::Q) - 1;
}

[[nodiscard]] bool IsShieldedSmileValueCompatible(CAmount value)
{
    return value > 0 && MoneyRange(value) && value < static_cast<CAmount>(smile2::Q);
}

[[nodiscard]] uint256 ViewOnlyNullifier(const uint256& commitment)
{
    HashWriter hw;
    hw << std::string{"BTX_Shielded_ViewOnlyNullifier_V1"};
    hw << commitment;
    return hw.GetSHA256();
}

[[nodiscard]] std::optional<shielded::v2::LifecycleAddress> BuildLifecycleAddress(
    const wallet::ShieldedAddress& addr,
    bool require_embedded_kem)
{
    shielded::v2::LifecycleAddress out;
    out.algo_byte = addr.algo_byte;
    out.pk_hash = addr.pk_hash;
    out.kem_pk_hash = addr.kem_pk_hash;
    if (addr.HasKEMPublicKey()) {
        out.version = SHIELDED_ADDRESS_VERSION_WITH_KEM_PUBKEY;
        out.has_kem_public_key = true;
        out.kem_public_key = addr.kem_pk;
    } else {
        out.version = SHIELDED_ADDRESS_VERSION_LEGACY_HASH_ONLY;
        out.has_kem_public_key = false;
    }
    if (require_embedded_kem && !out.has_kem_public_key) {
        return std::nullopt;
    }
    if (!out.IsValid()) {
        return std::nullopt;
    }
    return out;
}

[[nodiscard]] bool UseNoncedBridgeTagsAtHeight(int height)
{
    return Params().GetConsensus().IsShieldedBridgeTagUpgradeActive(height);
}

[[nodiscard]] bool IsWalletSpendableNoteClass(shielded::v2::NoteClass note_class)
{
    return note_class == shielded::v2::NoteClass::USER;
}

[[nodiscard]] size_t GetConfiguredShieldedRingSize()
{
    const int64_t configured = gArgs.GetIntArg(
        "-shieldedringsize",
        static_cast<int64_t>(shielded::lattice::DEFAULT_RING_SIZE));
    if (configured < 0) return shielded::lattice::DEFAULT_RING_SIZE;

    const size_t ring_size = static_cast<size_t>(configured);
    const size_t consensus_max = static_cast<size_t>(Params().GetConsensus().nMaxShieldedRingSize);
    if (!shielded::lattice::IsSupportedRingSize(ring_size) || ring_size > consensus_max) {
        return shielded::lattice::DEFAULT_RING_SIZE;
    }
    return ring_size;
}

[[nodiscard]] std::optional<std::pair<uint256, shielded::registry::ShieldedAccountRegistrySpendWitness>>
GetAccountRegistryWitnessForCoin(interfaces::Chain& chain,
                                 const ShieldedCoin& coin)
{
    if (!coin.account_leaf_hint.has_value() || !coin.account_leaf_hint->IsValid()) {
        return std::nullopt;
    }
    for (const auto& account_leaf_commitment :
         shielded::registry::CollectAccountLeafCommitmentCandidatesFromNote(coin.note,
                                                                            coin.commitment,
                                                                            *coin.account_leaf_hint)) {
        auto witness = chain.getShieldedAccountRegistryWitness(account_leaf_commitment);
        if (witness.has_value()) {
            return witness;
        }
    }
    return std::nullopt;
}

void CleanseByteVector(std::vector<unsigned char>& bytes)
{
    if (bytes.empty()) return;
    memory_cleanse(bytes.data(), bytes.size());
    bytes.clear();
}

class ScopedByteVectorCleanse
{
public:
    explicit ScopedByteVectorCleanse(std::vector<unsigned char>& data) : m_data(data) {}
    ~ScopedByteVectorCleanse() { CleanseByteVector(m_data); }

private:
    std::vector<unsigned char>& m_data;
};

struct TransparentWalletCoin
{
    COutPoint outpoint;
    CAmount value{0};
};

[[nodiscard]] std::vector<TransparentWalletCoin> CollectSpendableTransparentWalletCoins(const CWallet& wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet.cs_wallet)
{
    AssertLockHeld(wallet.cs_wallet);
    std::vector<TransparentWalletCoin> coins;
    for (const auto& [txid, wtx] : wallet.mapWallet) {
        if (wtx.IsCoinBase() && wallet.GetTxBlocksToMaturity(wtx) > 0) continue;
        for (uint32_t n = 0; n < wtx.tx->vout.size(); ++n) {
            if (!(wallet.IsMine(wtx.tx->vout[n]) & ISMINE_SPENDABLE)) continue;
            const COutPoint outpoint{Txid::FromUint256(txid), n};
            if (wallet.IsSpent(outpoint)) continue;
            coins.push_back({outpoint, wtx.tx->vout[n].nValue});
        }
    }

    std::sort(coins.begin(), coins.end(), [](const auto& a, const auto& b) {
        return std::tie(a.value, a.outpoint.hash, a.outpoint.n) >
               std::tie(b.value, b.outpoint.hash, b.outpoint.n);
    });
    return coins;
}

[[nodiscard]] std::optional<ShieldedAddressLifecycleBuildResult>
BuildAddressLifecycleControlTransactionImpl(
    CWallet& parent_wallet,
    const std::map<ShieldedAddress, ShieldedKeySet>& key_sets,
    const ShieldedAddress& subject_addr,
    const ShieldedKeySet& subject_keyset,
    const ShieldedAddress& operator_addr,
    const std::optional<ShieldedAddress>& successor_addr,
    shielded::v2::AddressLifecycleControlKind kind,
    CAmount fee,
    std::string* error)
{
    const auto fail = [&](const std::string& reason)
        -> std::optional<ShieldedAddressLifecycleBuildResult> {
        if (error != nullptr) *error = reason;
        LogDebug(BCLog::WALLETDB,
                 "BuildAddressLifecycleControlTransactionImpl aborted: %s\n",
                 reason);
        return std::nullopt;
    };

    const int32_t validation_height = NextShieldedBuildValidationHeight(parent_wallet.chain());
    if (!UseShieldedPrivacyRedesignAtHeight(validation_height)) {
        return fail(strprintf("address lifecycle controls are disabled before block %d",
                              Params().GetConsensus().nShieldedMatRiCTDisableHeight));
    }
    if (fee < 0 || !MoneyRange(fee)) {
        return fail("invalid fee");
    }
    fee = shielded::RoundShieldedFeeToCanonicalBucket(
        fee,
        Params().GetConsensus(),
        validation_height);
    const auto total_needed = fee;
    (void)key_sets;
    (void)operator_addr;

    std::vector<TransparentWalletCoin> available;
    {
        LOCK(parent_wallet.cs_wallet);
        available = CollectSpendableTransparentWalletCoins(parent_wallet);
    }
    if (available.empty()) {
        return fail("no spendable transparent funds");
    }

    std::vector<TransparentWalletCoin> selected;
    CAmount total_input{0};
    for (const auto& coin : available) {
        selected.push_back(coin);
        const auto next = CheckedAdd(total_input, coin.value);
        if (!next || !MoneyRange(*next)) {
            return fail("selected transparent input total overflow");
        }
        total_input = *next;
        if (total_input >= total_needed) break;
    }
    if (total_input < total_needed) {
        return fail("transparent funds below lifecycle control fee needed");
    }
    const CAmount change = total_input - total_needed;

    const auto subject = BuildLifecycleAddress(subject_addr, /*require_embedded_kem=*/true);
    if (!subject.has_value()) {
        return fail("invalid lifecycle control subject address");
    }

    shielded::v2::AddressLifecycleControl control;
    control.kind = kind;
    control.output_index = 0;
    control.subject = *subject;
    control.has_successor = successor_addr.has_value();
    if (successor_addr.has_value()) {
        const auto successor = BuildLifecycleAddress(*successor_addr, /*require_embedded_kem=*/true);
        if (!successor.has_value()) {
            return fail("invalid lifecycle control successor address");
        }
        control.successor = *successor;
    }
    control.subject_spending_pubkey = subject_keyset.spending_key.GetPubKey();

    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION;
    mtx.nLockTime = FastRandomContext{}.rand32();
    std::map<COutPoint, Coin> signing_coins;
    {
        LOCK(parent_wallet.cs_wallet);
        for (const auto& coin : selected) {
            const CWalletTx* wtx = parent_wallet.GetWalletTx(coin.outpoint.hash);
            if (wtx == nullptr || coin.outpoint.n >= wtx->tx->vout.size()) {
                return fail("missing wallet tx for selected transparent input");
            }
            mtx.vin.emplace_back(coin.outpoint);
            const int prev_height =
                wtx->state<TxStateConfirmed>() ? wtx->state<TxStateConfirmed>()->confirmed_block_height : 0;
            signing_coins.emplace(coin.outpoint,
                                  Coin(wtx->tx->vout[coin.outpoint.n],
                                       prev_height,
                                       wtx->IsCoinBase()));
        }
        if (change > 0) {
            auto change_dest = parent_wallet.GetNewChangeDestination(OutputType::P2MR);
            if (!change_dest) {
                return fail(strprintf("unable to generate change address (%s)",
                                      util::ErrorString(change_dest).original));
            }
            mtx.vout.emplace_back(change, GetScriptForDestination(*change_dest));
        }
    }
    const auto& consensus = Params().GetConsensus();
    const uint256 binding_digest = shielded::v2::ComputeV2LifecycleTransparentBindingDigest(
        CTransaction{mtx});
    if (binding_digest.IsNull()) {
        return fail("failed to derive lifecycle transparent binding digest");
    }
    if (!subject_keyset.spending_key.Sign(
            shielded::v2::ComputeAddressLifecycleRecordSigHash(control, binding_digest),
            control.signature) ||
        !shielded::v2::VerifyAddressLifecycleRecord(control, binding_digest)) {
        return fail("failed to sign lifecycle control");
    }

    shielded::v2::LifecyclePayload payload;
    payload.transparent_binding_digest = binding_digest;
    payload.lifecycle_controls = {control};
    if (!payload.IsValid()) {
        return fail("invalid lifecycle payload");
    }

    shielded::v2::TransactionBundle bundle;
    bundle.header.family_id = shielded::v2::GetWireTransactionFamilyForValidationHeight(
        shielded::v2::TransactionFamily::V2_LIFECYCLE,
        &consensus,
        validation_height);
    bundle.header.proof_envelope.proof_kind = shielded::v2::ProofKind::NONE;
    bundle.header.proof_envelope.membership_proof_kind = shielded::v2::ProofComponentKind::NONE;
    bundle.header.proof_envelope.amount_proof_kind = shielded::v2::ProofComponentKind::NONE;
    bundle.header.proof_envelope.balance_proof_kind = shielded::v2::ProofComponentKind::NONE;
    bundle.header.proof_envelope.settlement_binding_kind =
        shielded::v2::GetWireSettlementBindingKindForValidationHeight(
            shielded::v2::TransactionFamily::V2_LIFECYCLE,
            shielded::v2::SettlementBindingKind::NONE,
            &consensus,
            validation_height);
    bundle.header.proof_envelope.statement_digest = uint256{};
    bundle.payload = payload;
    bundle.header.payload_digest = shielded::v2::ComputeLifecyclePayloadDigest(payload);
    if (!bundle.IsValid()) {
        return fail("invalid lifecycle bundle");
    }
    mtx.shielded_bundle.v2_bundle = std::move(bundle);

    {
        LOCK(parent_wallet.cs_wallet);
        std::map<int, bilingual_str> input_errors;
        if (!parent_wallet.SignTransaction(mtx, signing_coins, SIGHASH_DEFAULT, input_errors)) {
            std::string err_summary;
            int logged_errors{0};
            for (const auto& [input_index, err] : input_errors) {
                if (!err_summary.empty()) err_summary += "; ";
                err_summary += strprintf("in%d=%s", input_index, err.original);
                if (++logged_errors >= 3) break;
            }
            return fail(strprintf("failed to sign lifecycle transparent inputs (%s)", err_summary));
        }
    }

    ShieldedAddressLifecycleBuildResult result;
    result.tx = std::move(mtx);
    result.successor = successor_addr;
    return result;
}

[[nodiscard]] std::optional<CAmount> SumShieldedCoinValues(Span<const ShieldedCoin> coins)
{
    CAmount total{0};
    for (const auto& coin : coins) {
        const auto next_total = CheckedAdd(total, coin.note.value);
        if (!next_total || !MoneyRange(*next_total)) return std::nullopt;
        total = *next_total;
    }
    return total;
}

[[nodiscard]] std::vector<CAmount> BuildIngressReserveValues(
    Span<const std::pair<ShieldedAddress, CAmount>> reserve_outputs,
    CAmount reserve_change)
{
    std::vector<CAmount> reserve_values;
    reserve_values.reserve(reserve_outputs.size() + (reserve_change > 0 ? 1 : 0));
    for (const auto& [_, amount] : reserve_outputs) {
        reserve_values.push_back(amount);
    }
    if (reserve_change > 0) reserve_values.push_back(reserve_change);
    return reserve_values;
}

[[nodiscard]] bool IsSchedulableV2IngressSelection(
    Span<const ShieldedCoin> selected,
    CAmount total_needed,
    Span<const std::pair<ShieldedAddress, CAmount>> reserve_outputs,
    Span<const shielded::v2::V2IngressLeafInput> ingress_leaves)
{
    if (selected.empty() || selected.size() > shielded::ringct::MAX_MATRICT_INPUTS) return false;

    const auto total_input = SumShieldedCoinValues(selected);
    if (!total_input.has_value() || *total_input < total_needed) return false;

    const CAmount reserve_change = *total_input - total_needed;
    const auto reserve_values = BuildIngressReserveValues(reserve_outputs, reserve_change);
    if (reserve_values.empty() || reserve_values.size() > shielded::v2::MAX_BATCH_RESERVE_OUTPUTS) {
        return false;
    }

    std::vector<CAmount> spend_values;
    spend_values.reserve(selected.size());
    for (const auto& coin : selected) {
        spend_values.push_back(coin.note.value);
    }

    return shielded::v2::CanBuildCanonicalV2IngressShardPlan(
        Span<const CAmount>{spend_values.data(), spend_values.size()},
        Span<const CAmount>{reserve_values.data(), reserve_values.size()},
        ingress_leaves);
}

[[nodiscard]] std::vector<ShieldedCoin> SelectSchedulableV2IngressNotes(
    Span<const ShieldedCoin> spendable,
    CAmount total_needed,
    Span<const std::pair<ShieldedAddress, CAmount>> reserve_outputs,
    Span<const shielded::v2::V2IngressLeafInput> ingress_leaves)
{
    static constexpr size_t MAX_INGRESS_NOTE_SELECTION_STATES{100000};

    std::map<uint256, std::vector<ShieldedCoin>> grouped;
    for (const auto& coin : spendable) {
        grouped[coin.note.recipient_pk_hash].push_back(coin);
    }

    std::vector<ShieldedCoin> best_selection;
    CAmount best_excess{std::numeric_limits<CAmount>::max()};
    size_t best_count{std::numeric_limits<size_t>::max()};
    size_t search_states{0};

    for (auto& [_, group_notes] : grouped) {
        std::sort(group_notes.begin(), group_notes.end(), [](const ShieldedCoin& a, const ShieldedCoin& b) {
            return std::tie(a.note.value, a.tree_position, a.nullifier) >
                   std::tie(b.note.value, b.tree_position, b.nullifier);
        });

        std::vector<CAmount> suffix_totals(group_notes.size() + 1, 0);
        for (size_t i = group_notes.size(); i-- > 0;) {
            suffix_totals[i] = suffix_totals[i + 1] + group_notes[i].note.value;
        }

        std::vector<ShieldedCoin> current_selection;
        auto consider_selection = [&](CAmount current_total) {
            if (current_total < total_needed) return;
            const CAmount excess = current_total - total_needed;
            if (!best_selection.empty() &&
                (excess > best_excess ||
                 (excess == best_excess && current_selection.size() >= best_count))) {
                return;
            }
            if (!IsSchedulableV2IngressSelection(
                    Span<const ShieldedCoin>{current_selection.data(), current_selection.size()},
                    total_needed,
                    reserve_outputs,
                    ingress_leaves)) {
                return;
            }
            best_selection = current_selection;
            best_excess = excess;
            best_count = current_selection.size();
        };

        auto search = [&](auto&& self, size_t index, CAmount current_total) -> void {
            if (search_states++ >= MAX_INGRESS_NOTE_SELECTION_STATES) return;
            if (current_selection.size() > shielded::ringct::MAX_MATRICT_INPUTS) return;
            if (current_total >= total_needed) {
                consider_selection(current_total);
                return;
            }
            if (index == group_notes.size() ||
                current_selection.size() == shielded::ringct::MAX_MATRICT_INPUTS ||
                current_total + suffix_totals[index] < total_needed) {
                return;
            }

            current_selection.push_back(group_notes[index]);
            self(self, index + 1, current_total + group_notes[index].note.value);
            current_selection.pop_back();
            self(self, index + 1, current_total);
        };

        search(search, 0, 0);
    }

    return best_selection;
}

[[nodiscard]] std::optional<std::vector<uint256>> BuildRingMembersForSelection(
    const shielded::ShieldedMerkleTree& tree,
    const std::vector<ShieldedCoin>& selected,
    const std::vector<uint64_t>& positions)
{
    if (!shielded::lattice::IsSupportedRingSize(positions.size())) {
        LogPrintf("BuildRingMembersForSelection failed: unsupported ring size positions=%u\n",
                  static_cast<unsigned int>(positions.size()));
        return std::nullopt;
    }

    std::map<uint64_t, uint256> fallback_commitments;
    for (const auto& coin : selected) {
        fallback_commitments.emplace(coin.tree_position, coin.commitment);
    }

    std::vector<uint256> members;
    members.reserve(positions.size());
    for (const uint64_t pos : positions) {
        auto commitment = tree.CommitmentAt(pos);
        if (!commitment.has_value()) {
            const auto fallback_it = fallback_commitments.find(pos);
            if (fallback_it == fallback_commitments.end() || fallback_it->second.IsNull()) {
                LogPrintf("BuildRingMembersForSelection failed: missing commitment at pos=%u tree_size=%u has_index=%d\n",
                          static_cast<unsigned int>(pos),
                          static_cast<unsigned int>(tree.Size()),
                          tree.HasCommitmentIndex() ? 1 : 0);
                return std::nullopt;
            }
            commitment = fallback_it->second;
        }
        members.push_back(*commitment);
    }
    return members;
}

void RegisterSmilePublicAccount(std::map<uint256, smile2::CompactPublicAccount>& public_accounts,
                                const uint256& note_commitment,
                                const std::optional<smile2::CompactPublicAccount>& smile_account)
{
    if (!note_commitment.IsNull() &&
        smile_account.has_value() &&
        smile_account->IsValid() &&
        smile2::ComputeCompactPublicAccountHash(*smile_account) == note_commitment) {
        public_accounts[note_commitment] = *smile_account;
    }
}

void RegisterAccountLeafCommitment(std::map<uint256, uint256>& account_leaf_commitments,
                                   const shielded::v2::OutputDescription& output,
                                   const std::optional<shielded::registry::AccountLeafHint>& account_leaf_hint,
                                   bool use_nonced_bridge_tag)
{
    if (!account_leaf_hint.has_value() ||
        !account_leaf_hint->IsValid() ||
        !output.smile_account.has_value()) {
        return;
    }

    std::optional<shielded::registry::ShieldedAccountLeaf> account_leaf;
    switch (account_leaf_hint->domain) {
    case shielded::registry::AccountDomain::DIRECT_SEND:
        account_leaf = shielded::registry::BuildDirectSendAccountLeaf(output);
        break;
    case shielded::registry::AccountDomain::INGRESS:
        account_leaf = shielded::registry::BuildIngressAccountLeaf(output,
                                                                   account_leaf_hint->settlement_binding_digest,
                                                                   use_nonced_bridge_tag);
        break;
    case shielded::registry::AccountDomain::EGRESS:
        account_leaf = shielded::registry::BuildEgressAccountLeaf(output,
                                                                  account_leaf_hint->settlement_binding_digest,
                                                                  account_leaf_hint->output_binding_digest,
                                                                  use_nonced_bridge_tag);
        break;
    case shielded::registry::AccountDomain::REBALANCE:
        account_leaf = shielded::registry::BuildRebalanceAccountLeaf(output,
                                                                     account_leaf_hint->settlement_binding_digest,
                                                                     use_nonced_bridge_tag);
        break;
    }
    if (!account_leaf.has_value()) {
        return;
    }
    const uint256 account_leaf_commitment =
        shielded::registry::ComputeShieldedAccountLeafCommitment(*account_leaf);
    if (!account_leaf_commitment.IsNull()) {
        account_leaf_commitments[output.note_commitment] = account_leaf_commitment;
    }
}

[[nodiscard]] std::optional<std::vector<smile2::wallet::SmileRingMember>> BuildSmileRingMembersForSelection(
    const shielded::ShieldedMerkleTree& tree,
    const std::vector<ShieldedCoin>& selected,
    const std::map<uint256, smile2::CompactPublicAccount>& public_accounts,
    const std::map<uint256, uint256>& account_leaf_commitments,
    const std::vector<uint64_t>& positions)
{
    if (!shielded::lattice::IsSupportedRingSize(positions.size())) {
        LogPrintf("BuildSmileRingMembersForSelection failed: unsupported ring size positions=%u\n",
                  static_cast<unsigned int>(positions.size()));
        return std::nullopt;
    }

    std::map<uint64_t, ShieldedCoin> fallback_coins;
    for (const auto& coin : selected) {
        fallback_coins.emplace(coin.tree_position, coin);
    }

    std::vector<smile2::wallet::SmileRingMember> members;
    members.reserve(positions.size());
    for (const uint64_t pos : positions) {
        auto commitment = tree.CommitmentAt(pos);
        if (!commitment.has_value()) {
            const auto fallback_it = fallback_coins.find(pos);
            if (fallback_it == fallback_coins.end() || fallback_it->second.commitment.IsNull()) {
                LogPrintf("BuildSmileRingMembersForSelection failed: missing commitment at pos=%u tree_size=%u has_index=%d\n",
                          static_cast<unsigned int>(pos),
                          static_cast<unsigned int>(tree.Size()),
                          tree.HasCommitmentIndex() ? 1 : 0);
                return std::nullopt;
            }
            commitment = fallback_it->second.commitment;
        }

        const auto account_it = public_accounts.find(*commitment);
        const auto leaf_it = account_leaf_commitments.find(*commitment);
        if (account_it != public_accounts.end() && leaf_it != account_leaf_commitments.end()) {
            auto member = smile2::wallet::BuildRingMemberFromCompactPublicAccount(
                smile2::wallet::SMILE_GLOBAL_SEED,
                *commitment,
                account_it->second,
                leaf_it->second);
            if (!member.has_value()) {
                LogPrintf("BuildSmileRingMembersForSelection failed: invalid public account for commitment=%s\n",
                          commitment->ToString());
                return std::nullopt;
            }
            members.push_back(std::move(*member));
            continue;
        }

        const auto fallback_it = fallback_coins.find(pos);
        LogPrintf("BuildSmileRingMembersForSelection failed: missing canonical SMILE public account for commitment=%s pos=%u is_selected=%d\n",
                  commitment->ToString(),
                  static_cast<unsigned int>(pos),
                  fallback_it != fallback_coins.end() ? 1 : 0);
        return std::nullopt;
    }
    return members;
}

[[nodiscard]] bool DecryptedNoteMatchesSmileAccount(const ShieldedNote& note,
                                                    const smile2::CompactPublicAccount& account)
{
    auto derived_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        note);
    return derived_account.has_value() &&
           smile2::ComputeCompactPublicAccountHash(*derived_account) ==
               smile2::ComputeCompactPublicAccountHash(account);
}

[[nodiscard]] std::optional<shielded::ringct::SharedRingSelection> BuildSharedSmileRingSelection(
    const shielded::ShieldedMerkleTree& tree,
    const std::vector<ShieldedCoin>& selected,
    size_t ring_size,
    const uint256& shared_seed,
    uint64_t tip_exclusion_window,
    Span<const uint64_t> historical_exclusions)
{
    if (selected.empty() ||
        selected.size() > ring_size ||
        !shielded::lattice::IsSupportedRingSize(ring_size)) {
        return std::nullopt;
    }

    std::vector<uint64_t> real_positions;
    real_positions.reserve(selected.size());
    std::set<uint64_t> real_position_set;
    for (const auto& coin : selected) {
        if (coin.tree_position >= tree.Size() || !real_position_set.insert(coin.tree_position).second) {
            return std::nullopt;
        }
        real_positions.push_back(coin.tree_position);
    }

    std::vector<uint64_t> exclusions;
    if (tree.Size() > 0) {
        const uint64_t tip = tree.Size() - 1;
        const uint64_t max_excludable =
            tree.Size() > real_positions.size() ? tree.Size() - real_positions.size() : 0;
        const uint64_t tip_window = std::min<uint64_t>(tip_exclusion_window, max_excludable);
        exclusions.reserve(tip_window);
        for (uint64_t i = 0; i < tip_window; ++i) {
            const uint64_t pos = tip - i;
            if (real_position_set.count(pos) == 0) exclusions.push_back(pos);
        }
    }

    const auto combined_exclusions = wallet::BuildShieldedHistoricalRingExclusions(
        Span<const uint64_t>{exclusions.data(), exclusions.size()},
        historical_exclusions,
        tree.Size());

    auto selection = shielded::ringct::SelectSharedRingPositionsWithExclusions(
        Span<const uint64_t>{real_positions.data(), real_positions.size()},
        tree.Size(),
        shared_seed,
        ring_size,
        Span<const uint64_t>{combined_exclusions.data(), combined_exclusions.size()});
    if (selection.positions.size() != ring_size ||
        selection.real_indices.size() != selected.size()) {
        return std::nullopt;
    }
    return selection;
}

[[nodiscard]] std::optional<ResolvedV2ShieldedRecipient> ResolveV2ShieldedRecipient(
    const std::map<ShieldedAddress, ShieldedKeySet>& key_sets,
    const std::map<ShieldedAddress, ShieldedAddressLifecycle>& address_lifecycles,
    const ShieldedAddress& addr,
    CAmount amount,
    int32_t validation_height,
    const char* context)
{
    ResolvedV2ShieldedRecipient resolved;

    ShieldedAddress effective_addr = addr;
    if (UseShieldedPrivacyRedesignAtHeight(validation_height)) {
        const auto lifecycle_it = address_lifecycles.find(addr);
        if (lifecycle_it != address_lifecycles.end()) {
            const auto& lifecycle = lifecycle_it->second;
            if (!lifecycle.IsValid()) {
                LogDebug(BCLog::WALLETDB, "%s failed: invalid lifecycle metadata for %s\n",
                         context,
                         addr.Encode());
                return std::nullopt;
            }
            switch (lifecycle.state) {
            case ShieldedAddressLifecycleState::ACTIVE:
                break;
            case ShieldedAddressLifecycleState::ROTATED:
                if (!lifecycle.has_successor) {
                    LogDebug(BCLog::WALLETDB, "%s failed: rotated destination missing successor for %s\n",
                             context,
                             addr.Encode());
                    return std::nullopt;
                }
                effective_addr = lifecycle.successor;
                break;
            case ShieldedAddressLifecycleState::REVOKED:
                LogDebug(BCLog::WALLETDB, "%s failed: destination revoked for %s\n",
                         context,
                         addr.Encode());
                return std::nullopt;
            }
        }
    }

    const auto key_it = key_sets.find(effective_addr);
    if (key_it != key_sets.end()) {
        resolved.recipient.recipient_kem_pk = key_it->second.kem_key.pk;
        resolved.local_recipient_kem_sk = &key_it->second.kem_key.sk;
    } else if (effective_addr.HasKEMPublicKey()) {
        resolved.recipient.recipient_kem_pk = effective_addr.kem_pk;
    } else {
        LogDebug(BCLog::WALLETDB, "%s failed: destination KEM public key unavailable for %s\n",
                 context,
                 effective_addr.Encode());
        return std::nullopt;
    }

    const uint256 recipient_kem_pk_hash = HashBytes(
        Span<const unsigned char>{resolved.recipient.recipient_kem_pk.data(),
                                  resolved.recipient.recipient_kem_pk.size()});
    if (recipient_kem_pk_hash != effective_addr.kem_pk_hash) {
        LogDebug(BCLog::WALLETDB, "%s failed: destination KEM hash mismatch for %s\n",
                 context,
                 effective_addr.Encode());
        return std::nullopt;
    }

    resolved.recipient.recipient_pk_hash = effective_addr.pk_hash;
    resolved.recipient.amount = amount;
    resolved.effective_addr = effective_addr;
    if (!resolved.recipient.IsValid()) {
        LogDebug(BCLog::WALLETDB, "%s failed: invalid v2 recipient for %s amount=%lld\n",
                 context,
                 effective_addr.Encode(),
                 static_cast<long long>(amount));
        return std::nullopt;
    }

    return resolved;
}

[[nodiscard]] std::string DescribeShieldedBundleFamily(const CShieldedBundle& bundle)
{
    if (const auto family = bundle.GetTransactionFamily()) {
        switch (*family) {
        case shielded::v2::TransactionFamily::V2_SEND:
            return "v2_send";
        case shielded::v2::TransactionFamily::V2_LIFECYCLE:
            return "v2_lifecycle";
        case shielded::v2::TransactionFamily::V2_INGRESS_BATCH:
            return "v2_ingress_batch";
        case shielded::v2::TransactionFamily::V2_EGRESS_BATCH:
            return "v2_egress_batch";
        case shielded::v2::TransactionFamily::V2_REBALANCE:
            return "v2_rebalance";
        case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR:
            return "v2_settlement_anchor";
        case shielded::v2::TransactionFamily::V2_GENERIC:
            return "shielded_v2";
        }
    }
    if (bundle.IsShieldOnly()) return "legacy_shield";
    if (bundle.IsUnshieldOnly()) return "legacy_unshield";
    if (bundle.IsFullyShielded()) return "legacy_direct";
    return "legacy_mixed";
}

template <typename OutputRecorder>
bool RecordCanonicalOutputChunks(const shielded::v2::TransactionBundle& bundle,
                                 Span<const shielded::v2::OutputDescription> outputs,
                                 const char* context,
                                 OutputRecorder&& record_output)
{
    const auto semantic_family = shielded::v2::GetBundleSemanticFamily(bundle);
    if (!shielded::v2::TransactionBundleOutputChunksAreCanonical(bundle)) {
        LogPrintf("%s: skipping non-canonical output chunks for family=%s outputs=%u chunks=%u\n",
                  context,
                  shielded::v2::GetTransactionFamilyName(semantic_family),
                  static_cast<unsigned int>(outputs.size()),
                  static_cast<unsigned int>(bundle.output_chunks.size()));
        return false;
    }

    for (const auto& chunk : bundle.output_chunks) {
        const size_t first = chunk.first_output_index;
        const size_t count = chunk.output_count;
        if (first > outputs.size() || count > outputs.size() - first) {
            LogPrintf("%s: output chunk bounds exceeded outputs for family=%s first=%u count=%u total=%u\n",
                      context,
                      shielded::v2::GetTransactionFamilyName(semantic_family),
                      chunk.first_output_index,
                      chunk.output_count,
                      static_cast<unsigned int>(outputs.size()));
            return false;
        }
        for (size_t i = 0; i < count; ++i) {
            record_output(outputs[first + i]);
        }
    }
    return true;
}

bool AppendOutputChunkViews(ShieldedTxView& tx_view,
                            Span<const shielded::v2::OutputChunkDescriptor> output_chunks,
                            const char* context)
{
    for (const auto& chunk : output_chunks) {
        const size_t first = chunk.first_output_index;
        const size_t count = chunk.output_count;
        if (first > tx_view.outputs.size() || count > tx_view.outputs.size() - first) {
            LogPrintf("%s: cached output chunk bounds exceeded tx_view outputs first=%u count=%u total=%u\n",
                      context,
                      chunk.first_output_index,
                      chunk.output_count,
                      static_cast<unsigned int>(tx_view.outputs.size()));
            return false;
        }

        ShieldedTxViewOutputChunk chunk_view;
        chunk_view.scan_domain = shielded::v2::GetScanDomainName(chunk.scan_domain);
        chunk_view.first_output_index = chunk.first_output_index;
        chunk_view.output_count = chunk.output_count;
        chunk_view.ciphertext_bytes = chunk.ciphertext_bytes;
        chunk_view.scan_hint_commitment = chunk.scan_hint_commitment;
        chunk_view.ciphertext_commitment = chunk.ciphertext_commitment;

        for (size_t i = first; i < first + count; ++i) {
            const auto& output = tx_view.outputs[i];
            if (!output.is_ours) continue;
            ++chunk_view.owned_output_count;
            const auto next_amount = CheckedAdd(chunk_view.owned_amount, output.amount);
            if (!next_amount || !MoneyRange(*next_amount)) {
                LogPrintf("%s: cached output chunk owned amount overflowed first=%u count=%u\n",
                          context,
                          chunk.first_output_index,
                          chunk.output_count);
                return false;
            }
            chunk_view.owned_amount = *next_amount;
        }
        tx_view.output_chunks.push_back(std::move(chunk_view));
    }
    return true;
}

[[nodiscard]] bool ValidateMLKEMKeyPair(const mlkem::KeyPair& keypair)
{
    if (keypair.sk.size() != mlkem::SECRETKEYBYTES) return false;
    const auto enc = mlkem::Encaps(keypair.pk);
    const auto dec = mlkem::Decaps(enc.ct, keypair.sk);
    return dec == enc.ss;
}

[[nodiscard]] bool EncryptWithWalletKey(const CWallet& wallet,
                                        Span<const unsigned char> plaintext,
                                        uint256& iv_out,
                                        std::vector<unsigned char>& ciphertext_out,
                                        std::string_view purpose)
{
    if (!wallet.IsCrypted() || wallet.IsLocked()) {
        return false;
    }
    iv_out = GetRandHash();
    return wallet.WithEncryptionKey([&](const CKeyingMaterial& master_key) {
        return EncryptAuthenticatedSecret(
            master_key,
            std::span<const unsigned char>{plaintext.data(), plaintext.size()},
            iv_out,
            ciphertext_out,
            purpose);
    });
}

[[nodiscard]] bool RequireEncryptedShieldedWallet(const CWallet& wallet,
                                                  const char* context,
                                                  std::string* error = nullptr)
{
    if (wallet.IsCrypted()) {
        return true;
    }
    if (error != nullptr) {
        *error = SHIELDED_ENCRYPTION_REQUIRED_ERROR;
    }
    LogPrintf("%s: %s\n", context, SHIELDED_ENCRYPTION_REQUIRED_ERROR);
    return false;
}

[[nodiscard]] bool RequireUnlockedShieldedSecretPersistence(const CWallet& wallet,
                                                            const char* context,
                                                            std::string* error = nullptr)
{
    if (!RequireEncryptedShieldedWallet(wallet, context, error)) {
        return false;
    }
    if (!wallet.IsLocked()) {
        return true;
    }
    static constexpr const char* SHIELDED_UNLOCK_REQUIRED_ERROR{
        "Shielded key import requires an unlocked encrypted wallet"};
    if (error != nullptr) {
        *error = SHIELDED_UNLOCK_REQUIRED_ERROR;
    }
    LogPrintf("%s: %s\n", context, SHIELDED_UNLOCK_REQUIRED_ERROR);
    return false;
}

[[nodiscard]] bool ScrubPersistedShieldedSecrets(WalletBatch& batch, const char* context)
{
    bool ok{true};

    std::vector<unsigned char> plaintext_seed;
    if (batch.ReadPQMasterSeed(plaintext_seed) && !plaintext_seed.empty()) {
        if (!batch.ErasePQMasterSeed()) {
            LogPrintf("%s: failed to erase plaintext shielded PQ master seed\n", context);
            ok = false;
        }
    }
    CleanseByteVector(plaintext_seed);

    uint256 encrypted_seed_iv;
    std::vector<unsigned char> encrypted_seed;
    if (batch.ReadCryptedPQMasterSeed(encrypted_seed_iv, encrypted_seed) && !encrypted_seed.empty()) {
        if (!batch.EraseCryptedPQMasterSeed()) {
            LogPrintf("%s: failed to erase encrypted shielded PQ master seed\n", context);
            ok = false;
        }
    }
    CleanseByteVector(encrypted_seed);

    std::vector<unsigned char> plaintext_state;
    if (batch.ReadShieldedState(plaintext_state) && !plaintext_state.empty()) {
        if (!batch.EraseShieldedState()) {
            LogPrintf("%s: failed to erase plaintext shielded state blob\n", context);
            ok = false;
        }
    }
    CleanseByteVector(plaintext_state);

    uint256 encrypted_state_iv;
    std::vector<unsigned char> encrypted_state;
    if (batch.ReadCryptedShieldedState(encrypted_state_iv, encrypted_state) && !encrypted_state.empty()) {
        if (!batch.EraseCryptedShieldedState()) {
            LogPrintf("%s: failed to erase encrypted shielded state blob\n", context);
            ok = false;
        }
    }
    CleanseByteVector(encrypted_state);

    return ok;
}

[[nodiscard]] bool DecryptWithWalletKey(const CWallet& wallet,
                                        Span<const unsigned char> ciphertext,
                                        const uint256& iv,
                                        std::vector<unsigned char>& plaintext_out,
                                        std::string_view purpose,
                                        bool* was_authenticated = nullptr)
{
    if (!wallet.IsCrypted() || wallet.IsLocked()) {
        return false;
    }
    return wallet.WithEncryptionKey([&](const CKeyingMaterial& master_key) {
        return DecryptAuthenticatedSecret(
            master_key,
            std::span<const unsigned char>{ciphertext.data(), ciphertext.size()},
            iv,
            plaintext_out,
            purpose,
            was_authenticated);
    });
}

[[nodiscard]] bool DeriveSpendingKeyForKeyset(const std::vector<unsigned char>& master_seed,
                                              ShieldedKeySet& keyset)
{
    const uint32_t coin_type = 0;
    auto spending_key = DerivePQKeyFromBIP39(master_seed,
                                             PQAlgorithm::ML_DSA_44,
                                             coin_type,
                                             keyset.account,
                                             /*change=*/0,
                                             keyset.index);
    if (!spending_key.has_value()) {
        return false;
    }
    if (HashBytes(spending_key->GetPubKey()) != keyset.spending_pk_hash) {
        return false;
    }
    keyset.spending_key = std::move(*spending_key);
    keyset.spending_key_loaded = true;
    return true;
}

[[nodiscard]] std::vector<unsigned char> DeriveShieldedSpendSecretMaterial(
    const std::vector<unsigned char>& master_seed,
    const ShieldedKeySet& keyset)
{
    if (master_seed.empty()) return {};

    HashWriter hw;
    hw << std::string{"BTX_Shielded_SpendSecret_V1"};
    hw.write(AsBytes(Span<const unsigned char>{master_seed.data(), master_seed.size()}));
    hw << keyset.account;
    hw << keyset.index;
    hw << keyset.spending_pk_hash;
    hw << keyset.kem_pk_hash;
    uint256 secret = hw.GetSHA256();
    // R6-208: Cleanse the derived secret after copying it out.
    // Note: We cannot safely memory_cleanse the HashWriter (non-POD type),
    // but GetSHA256() finalizes the internal state, making it non-recoverable.
    std::vector<unsigned char> result{secret.begin(), secret.end()};
    memory_cleanse(secret.begin(), secret.size());
    return result;
}

struct PersistedShieldedKeySet
{
    ShieldedAddress addr;
    uint32_t account{0};
    uint32_t index{0};
    bool has_spending_key{false};
    std::vector<unsigned char> kem_pk;
    std::vector<unsigned char, secure_allocator<unsigned char>> kem_sk;

    SERIALIZE_METHODS(PersistedShieldedKeySet, obj)
    {
        READWRITE(obj.addr,
                  obj.account,
                  obj.index,
                  obj.has_spending_key,
                  obj.kem_pk,
                  obj.kem_sk);
    }
};

struct PersistedShieldedAddressLifecycleEntry
{
    ShieldedAddress addr;
    ShieldedAddressLifecycle lifecycle;

    SERIALIZE_METHODS(PersistedShieldedAddressLifecycleEntry, obj)
    {
        READWRITE(obj.addr, obj.lifecycle);
    }
};

struct PersistedShieldedNoteClassEntry
{
    Nullifier nullifier;
    uint8_t note_class{static_cast<uint8_t>(shielded::v2::NoteClass::USER)};

    SERIALIZE_METHODS(PersistedShieldedNoteClassEntry, obj)
    {
        READWRITE(obj.nullifier, obj.note_class);
    }
};

struct PersistedShieldedState
{
    uint32_t version{SHIELDED_STATE_VERSION};
    uint32_t next_spending_index{0};
    uint32_t next_kem_index{0};
    int32_t last_scanned_height{-1};
    uint256 last_scanned_hash;
    shielded::ShieldedMerkleTree tree{shielded::ShieldedMerkleTree::IndexStorageMode::MEMORY_ONLY};
    std::vector<PersistedShieldedKeySet> key_sets;
    std::vector<PersistedShieldedAddressLifecycleEntry> address_lifecycles;
    std::vector<ShieldedCoin> notes;
    std::vector<PersistedShieldedNoteClassEntry> note_classes;
    std::vector<std::pair<uint256, shielded::ShieldedMerkleWitness>> witnesses;
    std::vector<uint64_t> recent_ring_exclusions;

    SERIALIZE_METHODS(PersistedShieldedState, obj)
    {
        READWRITE(obj.version,
                  obj.next_spending_index,
                  obj.next_kem_index,
                  obj.last_scanned_height,
                  obj.last_scanned_hash,
                  obj.tree,
                  obj.key_sets,
                  obj.notes,
                  obj.witnesses);
        if (obj.version >= 2) {
            READWRITE(obj.recent_ring_exclusions);
        }
        if (obj.version >= 3) {
            READWRITE(obj.address_lifecycles);
        }
        if (obj.version >= 4) {
            READWRITE(obj.note_classes);
        }
    }
};

} // namespace

std::string ShieldedAddress::Encode() const
{
    if (!IsValid()) return {};

    std::vector<unsigned char> payload;
    payload.reserve(version == SHIELDED_ADDRESS_VERSION_WITH_KEM_PUBKEY
                        ? SHIELDED_ADDRESS_EXTENDED_PAYLOAD_SIZE
                        : SHIELDED_ADDRESS_BASE_PAYLOAD_SIZE);
    payload.push_back(version);
    payload.push_back(algo_byte);
    payload.insert(payload.end(), pk_hash.begin(), pk_hash.end());
    payload.insert(payload.end(), kem_pk_hash.begin(), kem_pk_hash.end());
    if (version == SHIELDED_ADDRESS_VERSION_WITH_KEM_PUBKEY) {
        payload.insert(payload.end(), kem_pk.begin(), kem_pk.end());
    }

    std::vector<uint8_t> data;
    data.reserve(1 + (payload.size() * 8 + 4) / 5);
    ConvertBits<8, 5, true>([&](unsigned char c) { data.push_back(c); }, payload.begin(), payload.end());
    return bech32::Encode(bech32::Encoding::BECH32M, SHIELDED_HRP, data);
}

std::optional<ShieldedAddress> ShieldedAddress::Decode(const std::string& addr)
{
    const auto dec = bech32::Decode(addr, bech32::CharLimit{SHIELDED_ADDRESS_CHAR_LIMIT});
    if (dec.encoding != bech32::Encoding::BECH32M) return std::nullopt;
    if (dec.hrp != SHIELDED_HRP) return std::nullopt;

    std::vector<unsigned char> payload;
    if (!ConvertBits<5, 8, false>([&](unsigned char c) { payload.push_back(c); },
                                  dec.data.begin(),
                                  dec.data.end())) {
        return std::nullopt;
    }
    if (payload.size() != SHIELDED_ADDRESS_BASE_PAYLOAD_SIZE &&
        payload.size() != SHIELDED_ADDRESS_EXTENDED_PAYLOAD_SIZE) {
        return std::nullopt;
    }

    ShieldedAddress out;
    out.version = payload[0];
    out.algo_byte = payload[1];
    std::copy(payload.begin() + 2, payload.begin() + 34, out.pk_hash.begin());
    std::copy(payload.begin() + 34, payload.begin() + 66, out.kem_pk_hash.begin());
    if (out.version == SHIELDED_ADDRESS_VERSION_WITH_KEM_PUBKEY) {
        if (payload.size() != SHIELDED_ADDRESS_EXTENDED_PAYLOAD_SIZE) return std::nullopt;
        std::copy(payload.begin() + SHIELDED_ADDRESS_BASE_PAYLOAD_SIZE,
                  payload.end(),
                  out.kem_pk.begin());
    } else if (out.version == SHIELDED_ADDRESS_VERSION_LEGACY_HASH_ONLY) {
        if (payload.size() != SHIELDED_ADDRESS_BASE_PAYLOAD_SIZE) return std::nullopt;
    } else {
        return std::nullopt;
    }
    if (!out.IsValid()) return std::nullopt;
    return out;
}

bool ShieldedAddress::IsValid() const
{
    if (algo_byte != SHIELDED_ADDRESS_ALGO_BYTE) return false;
    if (pk_hash.IsNull() || kem_pk_hash.IsNull()) return false;

    if (version == SHIELDED_ADDRESS_VERSION_LEGACY_HASH_ONLY) {
        return true;
    }
    if (version == SHIELDED_ADDRESS_VERSION_WITH_KEM_PUBKEY) {
        if (!HasKEMPublicKey()) return false;
        const uint256 computed_hash = HashBytes(Span<const unsigned char>{kem_pk.data(), kem_pk.size()});
        return computed_hash == kem_pk_hash;
    }
    return false;
}

bool ShieldedAddress::HasKEMPublicKey() const
{
    return std::any_of(kem_pk.begin(), kem_pk.end(), [](uint8_t b) { return b != 0; });
}

bool IsValidShieldedAddressLifecycleState(ShieldedAddressLifecycleState state)
{
    switch (state) {
    case ShieldedAddressLifecycleState::ACTIVE:
    case ShieldedAddressLifecycleState::ROTATED:
    case ShieldedAddressLifecycleState::REVOKED:
        return true;
    }
    return false;
}

const char* GetShieldedAddressLifecycleStateName(ShieldedAddressLifecycleState state)
{
    switch (state) {
    case ShieldedAddressLifecycleState::ACTIVE:
        return "active";
    case ShieldedAddressLifecycleState::ROTATED:
        return "rotated";
    case ShieldedAddressLifecycleState::REVOKED:
        return "revoked";
    }
    return "invalid";
}

bool ShieldedAddressLifecycle::IsValid() const
{
    if (version != SHIELDED_ADDRESS_LIFECYCLE_VERSION ||
        !IsValidShieldedAddressLifecycleState(state) ||
        transition_height < -1) {
        return false;
    }
    if (has_successor && !successor.IsValid()) {
        return false;
    }
    if (has_predecessor && !predecessor.IsValid()) {
        return false;
    }
    switch (state) {
    case ShieldedAddressLifecycleState::ACTIVE:
        return !has_successor;
    case ShieldedAddressLifecycleState::ROTATED:
        return has_successor;
    case ShieldedAddressLifecycleState::REVOKED:
        return !has_successor;
    }
    return false;
}

CShieldedWallet::CShieldedWallet(CWallet& parent_wallet)
    : m_parent_wallet(parent_wallet)
{
    LOCK(cs_shielded);
    LoadPersistedState();
    CatchUpToChainTip();
}

CShieldedWallet::~CShieldedWallet() = default;

ShieldedAddress CShieldedWallet::GenerateNewAddress(uint32_t account)
{
    AssertLockHeld(cs_shielded);
    if (!RequireEncryptedShieldedWallet(m_parent_wallet, "CShieldedWallet::GenerateNewAddress")) {
        throw std::runtime_error(SHIELDED_ENCRYPTION_REQUIRED_ERROR);
    }
    MaybeRehydrateSpendingKeys();
    const bool had_keys_before = !m_key_sets.empty();

    ShieldedKeySet keyset;
    keyset.account = account;
    keyset.index = m_next_spending_index;
    keyset.has_spending_key = true;
    keyset.spending_key_loaded = false;

    std::vector<unsigned char> master_seed = GetMasterSeed();
    ScopedByteVectorCleanse master_seed_cleanse(master_seed);
    if (master_seed.empty() && m_parent_wallet.IsCrypted() && m_parent_wallet.IsLocked()) {
        throw std::runtime_error("Shielded key derivation requires wallet unlock");
    }
    const uint32_t coin_type = 0;

    auto spending_key = DerivePQKeyFromBIP39(master_seed,
                                             PQAlgorithm::ML_DSA_44,
                                             coin_type,
                                             account,
                                             /*change=*/0,
                                             m_next_spending_index);
    if (!spending_key.has_value()) {
        throw std::runtime_error(strprintf(
            "CShieldedWallet::GenerateNewAddress spending key derivation failed (account=%u index=%u)",
            account,
            m_next_spending_index));
    }
    LogDebug(BCLog::WALLETDB,
             "CShieldedWallet::GenerateNewAddress derived spending key account=%u index=%u\n",
             account,
             m_next_spending_index);
    keyset.spending_key = std::move(*spending_key);
    keyset.spending_key_loaded = true;

    keyset.kem_key = DeriveMLKEMKeyFromBIP39(master_seed,
                                             coin_type,
                                             account,
                                             /*change=*/0,
                                             m_next_kem_index);
    if (std::all_of(keyset.kem_key.pk.begin(), keyset.kem_key.pk.end(), [](uint8_t b) { return b == 0; }) ||
        !ValidateMLKEMKeyPair(keyset.kem_key)) {
        LogPrintf("CShieldedWallet::GenerateNewAddress invalid derived ML-KEM keypair, falling back to random keygen\n");
        keyset.kem_key = mlkem::KeyGen();
    }
    if (!ValidateMLKEMKeyPair(keyset.kem_key)) {
        LogPrintf("CShieldedWallet::GenerateNewAddress generated ML-KEM keypair failed validation; replacing with fresh key\n");
        keyset.kem_key = mlkem::KeyGen();
    }

    const auto spending_pk = keyset.spending_key.GetPubKey();
    keyset.spending_pk_hash = HashBytes(spending_pk);
    keyset.kem_pk_hash = HashBytes(Span<const unsigned char>{keyset.kem_key.pk.data(), keyset.kem_key.pk.size()});

    ShieldedAddress addr;
    addr.version = SHIELDED_ADDRESS_VERSION_WITH_KEM_PUBKEY;
    addr.algo_byte = SHIELDED_ADDRESS_ALGO_BYTE;
    addr.pk_hash = keyset.spending_pk_hash;
    addr.kem_pk_hash = keyset.kem_pk_hash;
    addr.kem_pk = keyset.kem_key.pk;

    m_key_sets[addr] = std::move(keyset);
    m_address_lifecycles[addr] = ShieldedAddressLifecycle{};
    if (m_next_spending_index >= std::numeric_limits<uint32_t>::max() ||
        m_next_kem_index >= std::numeric_limits<uint32_t>::max()) {
        throw std::runtime_error("Shielded address key derivation index limit reached");
    }
    ++m_next_spending_index;
    ++m_next_kem_index;

    // If this is the first shielded key, ensure wallet state is fully caught up
    // and commitment lookups are available for spend construction.
    if (!had_keys_before) {
        CatchUpToChainTip();
    }

    if (!PersistState()) {
        LogPrintf("CShieldedWallet: failed to persist state after GenerateNewAddress\n");
    }
    return addr;
}

bool CShieldedWallet::ImportViewingKey(const std::vector<unsigned char>& kem_sk,
                                       const std::vector<unsigned char>& kem_pk,
                                       const uint256& spending_pk_hash)
{
    AssertLockHeld(cs_shielded);
    if (!RequireUnlockedShieldedSecretPersistence(m_parent_wallet, "CShieldedWallet::ImportViewingKey")) {
        return false;
    }
    MaybeRehydrateSpendingKeys();
    if (spending_pk_hash.IsNull()) {
        return false;
    }
    if (kem_sk.size() != mlkem::SECRETKEYBYTES || kem_pk.size() != mlkem::PUBLICKEYBYTES) {
        return false;
    }

    ShieldedKeySet keyset;
    keyset.has_spending_key = false;
    keyset.spending_pk_hash = spending_pk_hash;
    std::copy(kem_pk.begin(), kem_pk.end(), keyset.kem_key.pk.begin());
    keyset.kem_key.sk.assign(kem_sk.begin(), kem_sk.end());
    keyset.kem_pk_hash = HashBytes(Span<const unsigned char>{keyset.kem_key.pk.data(), keyset.kem_key.pk.size()});
    if (!ValidateMLKEMKeyPair(keyset.kem_key)) {
        return false;
    }

    ShieldedAddress addr;
    addr.version = SHIELDED_ADDRESS_VERSION_WITH_KEM_PUBKEY;
    addr.algo_byte = SHIELDED_ADDRESS_ALGO_BYTE;
    addr.pk_hash = keyset.spending_pk_hash;
    addr.kem_pk_hash = keyset.kem_pk_hash;
    addr.kem_pk = keyset.kem_key.pk;

    const auto existing = m_key_sets.find(addr);
    if (existing != m_key_sets.end()) {
        // Never clobber an already-loaded spending-capable entry with a watch-only import.
        if (existing->second.has_spending_key) {
            return true;
        }
        existing->second.kem_key.sk.assign(kem_sk.begin(), kem_sk.end());
    } else {
        m_key_sets[addr] = std::move(keyset);
    }
    m_address_lifecycles[addr] = ShieldedAddressLifecycle{};

    if (!PersistState()) {
        LogPrintf("CShieldedWallet: failed to persist state after ImportViewingKey\n");
        return false;
    }

    // View-only shielded wallets never add imported addresses to the legacy
    // script/address birthday trackers, so without an explicit wallet birthday
    // update the blockConnected fast-path treats every future block as too old
    // to scan. Seed the birthday from the current chain tip so newly imported
    // viewing keys can discover subsequent blocks even when no rescan is
    // requested.
    if (m_parent_wallet.HaveChain()) {
        const auto tip_height = m_parent_wallet.chain().getHeight();
        if (tip_height.has_value()) {
            int64_t tip_max_time{0};
            const uint256 tip_hash = m_parent_wallet.chain().getBlockHash(*tip_height);
            if (m_parent_wallet.chain().findBlock(tip_hash, interfaces::FoundBlock().maxTime(tip_max_time))) {
                m_parent_wallet.MaybeUpdateBirthTime(tip_max_time);
            } else {
                // If tip metadata is unavailable, prefer a conservative floor
                // over wallclock time so future blocks are never skipped.
                m_parent_wallet.MaybeUpdateBirthTime(0);
            }
        } else {
            m_parent_wallet.MaybeUpdateBirthTime(0);
        }
    }
    return true;
}

std::optional<std::vector<unsigned char>> CShieldedWallet::ExportViewingKey(const ShieldedAddress& addr) const
{
    AssertLockHeld(cs_shielded);
    const auto it = m_key_sets.find(addr);
    if (it == m_key_sets.end()) return std::nullopt;
    return std::vector<unsigned char>(it->second.kem_key.sk.begin(), it->second.kem_key.sk.end());
}

std::vector<ShieldedAddress> CShieldedWallet::GetAddresses() const
{
    AssertLockHeld(cs_shielded);
    std::vector<ShieldedAddress> out;
    out.reserve(m_key_sets.size());
    for (const auto& [addr, _] : m_key_sets) {
        out.push_back(addr);
    }
    return out;
}

std::optional<ShieldedAddressLifecycle> CShieldedWallet::GetAddressLifecycle(
    const ShieldedAddress& addr) const
{
    AssertLockHeld(cs_shielded);
    const auto it = m_address_lifecycles.find(addr);
    if (it == m_address_lifecycles.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::optional<ShieldedAddress> CShieldedWallet::GetPreferredReceiveAddress() const
{
    AssertLockHeld(cs_shielded);
    std::optional<std::pair<int32_t, ShieldedAddress>> rotated_successor_candidate;
    std::optional<ShieldedAddress> first_active_candidate;
    for (const auto& [addr, _] : m_key_sets) {
        const auto lifecycle_it = m_address_lifecycles.find(addr);
        if (lifecycle_it == m_address_lifecycles.end()) {
            if (!first_active_candidate.has_value()) {
                first_active_candidate = addr;
            }
            continue;
        }
        if (!lifecycle_it->second.IsValid()) {
            continue;
        }
        if (lifecycle_it->second.state == ShieldedAddressLifecycleState::ACTIVE &&
            lifecycle_it->second.has_predecessor) {
            const int32_t transition_height = lifecycle_it->second.transition_height;
            if (!rotated_successor_candidate.has_value() ||
                transition_height > rotated_successor_candidate->first) {
                rotated_successor_candidate = std::make_pair(transition_height, addr);
            }
        }
        if (lifecycle_it->second.state == ShieldedAddressLifecycleState::ACTIVE &&
            !lifecycle_it->second.has_predecessor &&
            !first_active_candidate.has_value()) {
            first_active_candidate = addr;
        }
    }
    if (rotated_successor_candidate.has_value()) {
        return rotated_successor_candidate->second;
    }
    return first_active_candidate;
}

bool CShieldedWallet::HaveSpendingKey(const ShieldedAddress& addr)
{
    AssertLockHeld(cs_shielded);
    MaybeRehydrateSpendingKeys();
    const auto it = m_key_sets.find(addr);
    return it != m_key_sets.end() && it->second.has_spending_key && it->second.spending_key_loaded;
}

std::optional<ShieldedAddress> CShieldedWallet::RotateAddress(const ShieldedAddress& addr,
                                                              std::string* error)
{
    AssertLockHeld(cs_shielded);
    const auto key_it = m_key_sets.find(addr);
    if (key_it == m_key_sets.end()) {
        if (error != nullptr) *error = "address not found";
        return std::nullopt;
    }
    if (!key_it->second.has_spending_key) {
        if (error != nullptr) *error = "rotation requires a spend-capable local address";
        return std::nullopt;
    }
    const auto lifecycle_it = m_address_lifecycles.find(addr);
    if (lifecycle_it != m_address_lifecycles.end()) {
        if (!lifecycle_it->second.IsValid()) {
            if (error != nullptr) *error = "address lifecycle metadata is invalid";
            return std::nullopt;
        }
        if (lifecycle_it->second.state != ShieldedAddressLifecycleState::ACTIVE) {
            if (error != nullptr) *error = "address is not active";
            return std::nullopt;
        }
    }

    const ShieldedAddress successor = GenerateNewAddress(key_it->second.account);
    if (!ApplyCommittedAddressRotation(addr, successor, error)) {
        return std::nullopt;
    }
    return successor;
}

bool CShieldedWallet::RevokeAddress(const ShieldedAddress& addr, std::string* error)
{
    AssertLockHeld(cs_shielded);
    return ApplyCommittedAddressRevocation(addr, error);
}

bool CShieldedWallet::ApplyCommittedAddressRotation(const ShieldedAddress& addr,
                                                    const ShieldedAddress& successor,
                                                    std::string* error)
{
    AssertLockHeld(cs_shielded);
    const auto key_it = m_key_sets.find(addr);
    if (key_it == m_key_sets.end()) {
        if (error != nullptr) *error = "address not found";
        return false;
    }
    const auto successor_it = m_key_sets.find(successor);
    if (successor_it == m_key_sets.end()) {
        if (error != nullptr) *error = "successor address not found";
        return false;
    }
    if (!key_it->second.has_spending_key) {
        if (error != nullptr) *error = "rotation requires a spend-capable local address";
        return false;
    }
    const auto lifecycle_it = m_address_lifecycles.find(addr);
    if (lifecycle_it != m_address_lifecycles.end() &&
        lifecycle_it->second.IsValid() &&
        lifecycle_it->second.state != ShieldedAddressLifecycleState::ACTIVE) {
        if (error != nullptr) *error = "address is not active";
        return false;
    }
    auto& successor_lifecycle = m_address_lifecycles[successor];
    if (successor_lifecycle.IsValid() &&
        (successor_lifecycle.has_predecessor ||
         successor_lifecycle.state != ShieldedAddressLifecycleState::ACTIVE)) {
        if (error != nullptr) *error = "successor address is not fresh";
        return false;
    }

    ShieldedAddressLifecycle rotated;
    rotated.state = ShieldedAddressLifecycleState::ROTATED;
    rotated.has_successor = true;
    rotated.successor = successor;
    rotated.transition_height = NextShieldedBuildValidationHeight(m_parent_wallet.chain());
    m_address_lifecycles[addr] = rotated;

    successor_lifecycle = ShieldedAddressLifecycle{};
    successor_lifecycle.has_predecessor = true;
    successor_lifecycle.predecessor = addr;
    successor_lifecycle.transition_height = rotated.transition_height;

    if (!PersistState()) {
        if (error != nullptr) *error = "failed to persist rotated address lifecycle";
        return false;
    }
    return true;
}

bool CShieldedWallet::ApplyCommittedAddressRevocation(const ShieldedAddress& addr, std::string* error)
{
    AssertLockHeld(cs_shielded);
    if (m_key_sets.count(addr) == 0) {
        if (error != nullptr) *error = "address not found";
        return false;
    }
    auto& lifecycle = m_address_lifecycles[addr];
    if (!lifecycle.IsValid()) {
        lifecycle = ShieldedAddressLifecycle{};
    }
    if (lifecycle.state == ShieldedAddressLifecycleState::ROTATED) {
        if (error != nullptr) *error = "rotated addresses cannot be revoked";
        return false;
    }
    lifecycle.state = ShieldedAddressLifecycleState::REVOKED;
    lifecycle.has_successor = false;
    lifecycle.transition_height = NextShieldedBuildValidationHeight(m_parent_wallet.chain());
    if (!PersistState()) {
        if (error != nullptr) *error = "failed to persist revoked address lifecycle";
        return false;
    }
    return true;
}

std::optional<ShieldedAddressLifecycleBuildResult> CShieldedWallet::BuildAddressRotationTransaction(
    const ShieldedAddress& addr,
    CAmount fee,
    std::string* error)
{
    AssertLockHeld(cs_shielded);
    MaybeRehydrateSpendingKeys();

    const auto key_it = m_key_sets.find(addr);
    if (key_it == m_key_sets.end()) {
        if (error != nullptr) *error = "address not found";
        return std::nullopt;
    }
    if (!key_it->second.has_spending_key ||
        !key_it->second.spending_key_loaded ||
        !key_it->second.spending_key.IsValid()) {
        if (error != nullptr) *error = "rotation requires a loaded spend-capable local address";
        return std::nullopt;
    }
    if (const auto lifecycle_it = m_address_lifecycles.find(addr);
        lifecycle_it != m_address_lifecycles.end() &&
        lifecycle_it->second.IsValid() &&
        lifecycle_it->second.state != ShieldedAddressLifecycleState::ACTIVE) {
        if (error != nullptr) *error = "address is not active";
        return std::nullopt;
    }

    const ShieldedAddress successor = GenerateNewAddress(key_it->second.account);
    return BuildAddressLifecycleControlTransactionImpl(m_parent_wallet,
                                                      m_key_sets,
                                                      addr,
                                                      key_it->second,
                                                      successor,
                                                      successor,
                                                      shielded::v2::AddressLifecycleControlKind::ROTATE,
                                                      fee,
                                                      error);
}

std::optional<ShieldedAddressLifecycleBuildResult> CShieldedWallet::BuildAddressRevocationTransaction(
    const ShieldedAddress& addr,
    CAmount fee,
    std::string* error)
{
    AssertLockHeld(cs_shielded);
    MaybeRehydrateSpendingKeys();

    const auto key_it = m_key_sets.find(addr);
    if (key_it == m_key_sets.end()) {
        if (error != nullptr) *error = "address not found";
        return std::nullopt;
    }
    if (!key_it->second.has_spending_key ||
        !key_it->second.spending_key_loaded ||
        !key_it->second.spending_key.IsValid()) {
        if (error != nullptr) *error = "revocation requires a loaded spend-capable local address";
        return std::nullopt;
    }
    if (const auto lifecycle_it = m_address_lifecycles.find(addr);
        lifecycle_it != m_address_lifecycles.end() &&
        lifecycle_it->second.IsValid() &&
        lifecycle_it->second.state == ShieldedAddressLifecycleState::ROTATED) {
        if (error != nullptr) *error = "rotated addresses cannot be revoked";
        return std::nullopt;
    }

    return BuildAddressLifecycleControlTransactionImpl(m_parent_wallet,
                                                      m_key_sets,
                                                      addr,
                                                      key_it->second,
                                                      addr,
                                                      std::nullopt,
                                                      shielded::v2::AddressLifecycleControlKind::REVOKE,
                                                      fee,
                                                      error);
}

std::optional<ShieldedAddress> CShieldedWallet::ResolveLifecycleDestination(
    const ShieldedAddress& addr,
    int32_t validation_height,
    std::string* error) const
{
    AssertLockHeld(cs_shielded);
    if (!UseShieldedPrivacyRedesignAtHeight(validation_height)) {
        return addr;
    }

    const auto lifecycle_it = m_address_lifecycles.find(addr);
    if (lifecycle_it == m_address_lifecycles.end()) {
        return addr;
    }
    const auto& lifecycle = lifecycle_it->second;
    if (!lifecycle.IsValid()) {
        if (error != nullptr) *error = "address lifecycle metadata is invalid";
        return std::nullopt;
    }
    switch (lifecycle.state) {
    case ShieldedAddressLifecycleState::ACTIVE:
        return addr;
    case ShieldedAddressLifecycleState::ROTATED:
        if (!lifecycle.has_successor) {
            if (error != nullptr) *error = "rotated address is missing successor";
            return std::nullopt;
        }
        return lifecycle.successor;
    case ShieldedAddressLifecycleState::REVOKED:
        if (error != nullptr) *error = "destination shielded address has been revoked locally";
        return std::nullopt;
    }
    if (error != nullptr) *error = "invalid address lifecycle state";
    return std::nullopt;
}

void CShieldedWallet::RecordScannedOutput(const CBlock& block,
                                          int height,
                                          const uint256& note_commitment,
                                          const shielded::EncryptedNote& enc_note,
                                          const std::vector<unsigned char>& master_seed,
                                          std::set<uint256>& block_commitments_seen,
                                          ShieldedTxView& tx_view,
                                          bool& tx_has_local_visibility)
{
    AssertLockHeld(cs_shielded);
    if (!block_commitments_seen.insert(note_commitment).second) {
        LogPrintf("CShieldedWallet::ScanBlock: skipping duplicate output commitment %s at height %d\n",
                  note_commitment.ToString(), height);
        return;
    }

    m_tree.Append(note_commitment);
    UpdateWitnesses(note_commitment);

    ShieldedTxViewOutput output_view;
    output_view.commitment = note_commitment;
    auto dec = TryDecryptNoteFull(enc_note);
    if (!dec.has_value()) {
        tx_view.outputs.push_back(std::move(output_view));
        return;
    }

    const auto& note = dec->first;
    const ShieldedKeySet* keyset = dec->second;

    ShieldedCoin coin;
    coin.note = note;
    coin.note_class = shielded::v2::NoteClass::USER;
    coin.commitment = note_commitment;
    coin.tree_position = m_tree.Size() - 1;
    coin.confirmation_height = height;
    coin.is_spent = false;
    const bool has_spending_key = keyset->has_spending_key && keyset->spending_key_loaded;
    std::vector<unsigned char> spend_secret = has_spending_key
        ? DeriveShieldedSpendSecretMaterial(master_seed, *keyset)
        : std::vector<unsigned char>{};
    ScopedByteVectorCleanse spend_secret_cleanse(spend_secret);
    const bool can_spend = !spend_secret.empty();
    coin.is_mine_spend = can_spend;
    coin.block_hash = block.GetHash();
    Nullifier spend_nullifier;
    const bool bound_nullifier = can_spend &&
        shielded::ringct::DeriveInputNullifierForNote(spend_nullifier,
                                                      Span<const unsigned char>{spend_secret.data(), spend_secret.size()},
                                                      note,
                                                      note_commitment);
    coin.nullifier = bound_nullifier ? spend_nullifier : ViewOnlyNullifier(note_commitment);

    m_notes[coin.nullifier] = coin;
    m_witnesses[coin.commitment] = m_tree.Witness();

    output_view.amount = note.value;
    output_view.is_ours = true;
    tx_has_local_visibility = true;
    tx_view.outputs.push_back(std::move(output_view));
}

void CShieldedWallet::RecordScannedOutput(const CBlock& block,
                                          int height,
                                          const shielded::v2::OutputDescription& output,
                                          const std::optional<shielded::registry::AccountLeafHint>& account_leaf_hint,
                                          const std::vector<unsigned char>& master_seed,
                                          std::set<uint256>& block_commitments_seen,
                                          ShieldedTxView& tx_view,
                                          bool& tx_has_local_visibility)
{
    AssertLockHeld(cs_shielded);
    const uint256& note_commitment = output.note_commitment;
    if (!block_commitments_seen.insert(note_commitment).second) {
        LogPrintf("CShieldedWallet::ScanBlock: skipping duplicate output commitment %s at height %d\n",
                  note_commitment.ToString(), height);
        return;
    }
    RegisterSmilePublicAccount(m_smile_public_accounts, note_commitment, output.smile_account);
    RegisterAccountLeafCommitment(m_account_leaf_commitments,
                                  output,
                                  account_leaf_hint,
                                  UseNoncedBridgeTagsAtHeight(height));

    m_tree.Append(note_commitment);
    UpdateWitnesses(note_commitment);

    ShieldedTxViewOutput output_view;
    output_view.commitment = note_commitment;
    auto dec = TryDecryptNoteFull(output.encrypted_note);
    if (!dec.has_value()) {
        tx_view.outputs.push_back(std::move(output_view));
        return;
    }

    const auto& note = dec->first;
    const ShieldedKeySet* keyset = dec->second;
    if (output.smile_account.has_value() &&
        !DecryptedNoteMatchesSmileAccount(note, *output.smile_account)) {
        LogPrintf("CShieldedWallet::ScanBlock: decrypted SMILE account mismatch for commitment %s at height %d\n",
                  note_commitment.ToString(),
                  height);
        tx_view.outputs.push_back(std::move(output_view));
        return;
    }

    ShieldedCoin coin;
    coin.note = note;
    coin.note_class = output.note_class;
    coin.commitment = note_commitment;
    coin.tree_position = m_tree.Size() - 1;
    coin.confirmation_height = height;
    coin.is_spent = false;
    const bool has_spending_key = keyset->has_spending_key && keyset->spending_key_loaded;
    std::vector<unsigned char> spend_secret = has_spending_key
        ? DeriveShieldedSpendSecretMaterial(master_seed, *keyset)
        : std::vector<unsigned char>{};
    ScopedByteVectorCleanse spend_secret_cleanse(spend_secret);
    const bool can_spend = !spend_secret.empty();
    coin.is_mine_spend = can_spend;
    coin.block_hash = block.GetHash();
    if (account_leaf_hint.has_value() && account_leaf_hint->IsValid()) {
        coin.account_leaf_hint = account_leaf_hint;
    }
    if (output.smile_account.has_value()) {
        const auto smile_nullifier = smile2::wallet::ComputeSmileNullifierFromNote(
            smile2::wallet::SMILE_GLOBAL_SEED,
            note);
        coin.nullifier = smile_nullifier.value_or(ViewOnlyNullifier(note_commitment));
    } else {
        Nullifier spend_nullifier;
        const bool bound_nullifier = can_spend &&
            shielded::ringct::DeriveInputNullifierForNote(spend_nullifier,
                                                          Span<const unsigned char>{spend_secret.data(), spend_secret.size()},
                                                          note,
                                                          note_commitment);
        coin.nullifier = bound_nullifier ? spend_nullifier : ViewOnlyNullifier(note_commitment);
    }

    m_notes[coin.nullifier] = coin;
    m_witnesses[coin.commitment] = m_tree.Witness();

    output_view.amount = note.value;
    output_view.is_ours = true;
    tx_has_local_visibility = true;
    tx_view.outputs.push_back(std::move(output_view));
}

void CShieldedWallet::RecordMempoolOutput(const uint256& txid,
                                          const uint256& note_commitment,
                                          const shielded::EncryptedNote& enc_note,
                                          const std::vector<unsigned char>& master_seed,
                                          ShieldedTxView& tx_view,
                                          bool& tx_has_local_visibility)
{
    AssertLockHeld(cs_shielded);
    ShieldedTxViewOutput output_view;
    output_view.commitment = note_commitment;
    auto dec = TryDecryptNoteFull(enc_note);
    if (!dec.has_value()) {
        tx_view.outputs.push_back(std::move(output_view));
        return;
    }
    const ShieldedNote& note = dec->first;
    const ShieldedKeySet* keyset = dec->second;

    ShieldedCoin coin;
    coin.note = note;
    coin.note_class = shielded::v2::NoteClass::USER;
    coin.commitment = note_commitment;
    coin.confirmation_height = -1;
    coin.is_spent = false;
    const bool has_spending_key = keyset->has_spending_key && keyset->spending_key_loaded;
    std::vector<unsigned char> spend_secret = has_spending_key
        ? DeriveShieldedSpendSecretMaterial(master_seed, *keyset)
        : std::vector<unsigned char>{};
    ScopedByteVectorCleanse spend_secret_cleanse_mempool(spend_secret);
    const bool can_spend = !spend_secret.empty();
    coin.is_mine_spend = can_spend;
    Nullifier spend_nullifier;
    const bool bound_nullifier = can_spend &&
        shielded::ringct::DeriveInputNullifierForNote(spend_nullifier,
                                                      Span<const unsigned char>{spend_secret.data(), spend_secret.size()},
                                                      note,
                                                      note_commitment);
    coin.nullifier = bound_nullifier ? spend_nullifier : ViewOnlyNullifier(note_commitment);
    const Nullifier output_nf = coin.nullifier;
    m_mempool_notes[output_nf] = std::move(coin);
    m_mempool_note_index[txid].insert(output_nf);

    output_view.amount = note.value;
    output_view.is_ours = true;
    tx_has_local_visibility = true;
    tx_view.outputs.push_back(std::move(output_view));
}

void CShieldedWallet::RecordMempoolOutput(const uint256& txid,
                                          const shielded::v2::OutputDescription& output,
                                          const std::optional<shielded::registry::AccountLeafHint>& account_leaf_hint,
                                          const std::vector<unsigned char>& master_seed,
                                          ShieldedTxView& tx_view,
                                          bool& tx_has_local_visibility)
{
    AssertLockHeld(cs_shielded);
    const uint256& note_commitment = output.note_commitment;
    RegisterSmilePublicAccount(m_smile_public_accounts, note_commitment, output.smile_account);
    const auto tip_height = m_parent_wallet.chain().getHeight();
    const int mempool_height = tip_height.has_value() ? (*tip_height + 1) : -1;
    RegisterAccountLeafCommitment(m_account_leaf_commitments,
                                  output,
                                  account_leaf_hint,
                                  UseNoncedBridgeTagsAtHeight(mempool_height));
    ShieldedTxViewOutput output_view;
    output_view.commitment = note_commitment;
    auto dec = TryDecryptNoteFull(output.encrypted_note);
    if (!dec.has_value()) {
        tx_view.outputs.push_back(std::move(output_view));
        return;
    }
    const ShieldedNote& note = dec->first;
    const ShieldedKeySet* keyset = dec->second;
    if (output.smile_account.has_value() &&
        !DecryptedNoteMatchesSmileAccount(note, *output.smile_account)) {
        LogPrintf("CShieldedWallet::RecordMempoolOutput: decrypted SMILE account mismatch for commitment %s txid=%s\n",
                  note_commitment.ToString(),
                  txid.ToString());
        tx_view.outputs.push_back(std::move(output_view));
        return;
    }

    ShieldedCoin coin;
    coin.note = note;
    coin.note_class = output.note_class;
    coin.commitment = note_commitment;
    coin.confirmation_height = -1;
    coin.is_spent = false;
    const bool has_spending_key = keyset->has_spending_key && keyset->spending_key_loaded;
    std::vector<unsigned char> spend_secret = has_spending_key
        ? DeriveShieldedSpendSecretMaterial(master_seed, *keyset)
        : std::vector<unsigned char>{};
    ScopedByteVectorCleanse spend_secret_cleanse_mempool(spend_secret);
    const bool can_spend = !spend_secret.empty();
    coin.is_mine_spend = can_spend;
    if (account_leaf_hint.has_value() && account_leaf_hint->IsValid()) {
        coin.account_leaf_hint = account_leaf_hint;
    }
    if (output.smile_account.has_value()) {
        const auto smile_nullifier = smile2::wallet::ComputeSmileNullifierFromNote(
            smile2::wallet::SMILE_GLOBAL_SEED,
            note);
        coin.nullifier = smile_nullifier.value_or(ViewOnlyNullifier(note_commitment));
    } else {
        Nullifier spend_nullifier;
        const bool bound_nullifier = can_spend &&
            shielded::ringct::DeriveInputNullifierForNote(spend_nullifier,
                                                          Span<const unsigned char>{spend_secret.data(), spend_secret.size()},
                                                          note,
                                                          note_commitment);
        coin.nullifier = bound_nullifier ? spend_nullifier : ViewOnlyNullifier(note_commitment);
    }
    const Nullifier output_nf = coin.nullifier;
    m_mempool_notes[output_nf] = std::move(coin);
    m_mempool_note_index[txid].insert(output_nf);

    output_view.amount = note.value;
    output_view.is_ours = true;
    tx_has_local_visibility = true;
    tx_view.outputs.push_back(std::move(output_view));
}

void CShieldedWallet::ScanBlock(const CBlock& block, int height)
{
    AssertLockHeld(cs_shielded);
    // Only touch the shielded master seed when this wallet can actually use
    // it. Unencrypted wallets cannot hold shielded spend authorities, and
    // locked encrypted wallets cannot decrypt the seed yet. Both cases should
    // still keep the public tree and scan cursor in sync without producing
    // noisy seed-access warnings.
    const bool can_access_master_seed = m_parent_wallet.IsCrypted() && !m_parent_wallet.IsLocked();
    std::vector<unsigned char> master_seed;
    if (can_access_master_seed) {
        master_seed = GetMasterSeed();
    }
    ScopedByteVectorCleanse master_seed_cleanse_scan(master_seed);
    // Finding 10 fix: track output commitments across all transactions in the
    // block to detect intra-block duplicates (consensus rejects them but the
    // wallet must also handle this defensively during scanning).
    std::set<uint256> block_commitments_seen;

    for (const auto& txref : block.vtx) {
        const CTransaction& tx = *txref;
        if (!tx.HasShieldedBundle()) continue;
        const CShieldedBundle& bundle = tx.GetShieldedBundle();
        const uint256 txid = tx.GetHash();
        ShieldedTxView tx_view;
        tx_view.value_balance = GetShieldedStateValueBalance(bundle);
        tx_view.family = DescribeShieldedBundleFamily(bundle);
        bool tx_has_local_visibility{false};

        for (const Nullifier& nullifier : CollectShieldedNullifiers(bundle)) {
            auto note_it = m_notes.find(nullifier);
            ShieldedTxViewSpend spend_view;
            spend_view.nullifier = nullifier;
            if (note_it != m_notes.end() && !note_it->second.is_spent) {
                spend_view.amount = note_it->second.note.value;
                spend_view.is_ours = true;
                tx_has_local_visibility = true;
                note_it->second.is_spent = true;
                note_it->second.spent_height = height;
                m_spent_nullifiers.insert(nullifier);
            }
            tx_view.spends.push_back(std::move(spend_view));
        }

        if (bundle.HasV2Bundle()) {
            const auto* v2_bundle = bundle.GetV2Bundle();
            if (v2_bundle != nullptr) {
                switch (shielded::v2::GetBundleSemanticFamily(*v2_bundle)) {
                case shielded::v2::TransactionFamily::V2_SEND: {
                    const auto& payload = std::get<shielded::v2::SendPayload>(v2_bundle->payload);
                    const shielded::registry::AccountLeafHint account_leaf_hint =
                        shielded::registry::MakeDirectSendAccountLeafHint();
                    for (const auto& output : payload.outputs) {
                        RecordScannedOutput(block,
                                            height,
                                            output,
                                            account_leaf_hint,
                                            master_seed,
                                            block_commitments_seen,
                                            tx_view,
                                            tx_has_local_visibility);
                    }
                    break;
                }
                case shielded::v2::TransactionFamily::V2_LIFECYCLE:
                    break;
                case shielded::v2::TransactionFamily::V2_INGRESS_BATCH: {
                    const auto& payload = std::get<shielded::v2::IngressBatchPayload>(v2_bundle->payload);
                    const auto account_leaf_hint =
                        shielded::registry::MakeIngressAccountLeafHint(payload.settlement_binding_digest);
                    for (const auto& output : payload.reserve_outputs) {
                        RecordScannedOutput(block,
                                            height,
                                            output,
                                            account_leaf_hint,
                                            master_seed,
                                            block_commitments_seen,
                                            tx_view,
                                            tx_has_local_visibility);
                    }
                    break;
                }
                case shielded::v2::TransactionFamily::V2_EGRESS_BATCH: {
                    const auto& payload = std::get<shielded::v2::EgressBatchPayload>(v2_bundle->payload);
                    const auto account_leaf_hint = shielded::registry::MakeEgressAccountLeafHint(
                        payload.settlement_binding_digest,
                        payload.output_binding_digest);
                    const bool recorded = RecordCanonicalOutputChunks(
                        *v2_bundle,
                        {payload.outputs.data(), payload.outputs.size()},
                        "CShieldedWallet::ScanBlock",
                        [&](const shielded::v2::OutputDescription& output) NO_THREAD_SAFETY_ANALYSIS {
                            RecordScannedOutput(block,
                                                height,
                                                output,
                                                account_leaf_hint,
                                                master_seed,
                                                block_commitments_seen,
                                                tx_view,
                                                tx_has_local_visibility);
                        });
                    if (recorded) {
                        AppendOutputChunkViews(tx_view,
                                               {v2_bundle->output_chunks.data(), v2_bundle->output_chunks.size()},
                                               "CShieldedWallet::ScanBlock");
                    }
                    break;
                }
                case shielded::v2::TransactionFamily::V2_REBALANCE: {
                    const auto& payload = std::get<shielded::v2::RebalancePayload>(v2_bundle->payload);
                    const auto account_leaf_hint =
                        shielded::registry::MakeRebalanceAccountLeafHint(payload.settlement_binding_digest);
                    if (!v2_bundle->output_chunks.empty()) {
                        const bool recorded = RecordCanonicalOutputChunks(
                            *v2_bundle,
                            {payload.reserve_outputs.data(), payload.reserve_outputs.size()},
                            "CShieldedWallet::ScanBlock",
                            [&](const shielded::v2::OutputDescription& output) NO_THREAD_SAFETY_ANALYSIS {
                                RecordScannedOutput(block,
                                                    height,
                                                    output,
                                                    account_leaf_hint,
                                                    master_seed,
                                                    block_commitments_seen,
                                                    tx_view,
                                                    tx_has_local_visibility);
                            });
                        if (recorded) {
                            AppendOutputChunkViews(tx_view,
                                                   {v2_bundle->output_chunks.data(), v2_bundle->output_chunks.size()},
                                                   "CShieldedWallet::ScanBlock");
                        }
                    } else {
                        for (const auto& output : payload.reserve_outputs) {
                            RecordScannedOutput(block,
                                                height,
                                                output,
                                                account_leaf_hint,
                                                master_seed,
                                                block_commitments_seen,
                                                tx_view,
                                                tx_has_local_visibility);
                        }
                    }
                    break;
                }
                case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR:
                case shielded::v2::TransactionFamily::V2_GENERIC:
                    break;
                }
            }
        } else {
            for (const auto& output : bundle.shielded_outputs) {
                RecordScannedOutput(block,
                                    height,
                                    output.note_commitment,
                                    output.encrypted_note,
                                    master_seed,
                                    block_commitments_seen,
                                    tx_view,
                                    tx_has_local_visibility);
            }
        }

        if (tx_has_local_visibility) {
            m_tx_view_cache[txid] = std::move(tx_view);
        }
    }

    PruneSpentWitnesses();

    // Evict oldest tx view cache entries to prevent unbounded memory growth.
    while (m_tx_view_cache.size() > TX_VIEW_CACHE_MAX) {
        m_tx_view_cache.erase(m_tx_view_cache.begin());
    }

    m_last_scanned_height = height;
    m_last_scanned_hash = block.GetHash();
    if (!m_defer_persist && !PersistState()) {
        LogPrintf("CShieldedWallet: failed to persist state after ScanBlock at height %d\n", height);
    }
}

void CShieldedWallet::UndoBlock(const CBlock& block, int height)
{
    AssertLockHeld(cs_shielded);
    const uint256 disconnected_hash = block.GetHash();

    // If wallet scan cursor diverged from the disconnected block, resynchronize
    // from chain rather than applying a potentially invalid local rollback.
    if (m_last_scanned_height != height || m_last_scanned_hash != disconnected_hash) {
        RebuildFromActiveChain();
        LogPrintf("CShieldedWallet: rebuilt state after block disconnect at height %d (%s), last_scanned_height=%d\n",
                  height,
                  disconnected_hash.ToString(),
                  m_last_scanned_height);
        return;
    }

    std::vector<Nullifier> spend_nullifiers;
    std::set<uint256> removed_commitments;
    uint64_t removed_output_count{0};

    for (const auto& txref : block.vtx) {
        const CTransaction& tx = *txref;
        if (!tx.HasShieldedBundle()) continue;
        const CShieldedBundle& bundle = tx.GetShieldedBundle();
        m_tx_view_cache.erase(tx.GetHash());

        const auto bundle_nullifiers = CollectShieldedNullifiers(bundle);
        spend_nullifiers.insert(spend_nullifiers.end(), bundle_nullifiers.begin(), bundle_nullifiers.end());
        const auto bundle_commitments = CollectShieldedOutputCommitments(bundle);
        removed_commitments.insert(bundle_commitments.begin(), bundle_commitments.end());
        if (removed_output_count > std::numeric_limits<uint64_t>::max() - bundle.GetShieldedOutputCount()) {
            RebuildFromActiveChain();
            LogPrintf("CShieldedWallet: rebuilt state after block disconnect at height %d (%s), last_scanned_height=%d\n",
                      height,
                      disconnected_hash.ToString(),
                      m_last_scanned_height);
            return;
        }
        removed_output_count += bundle.GetShieldedOutputCount();
    }

    if (removed_output_count > m_tree.Size()) {
        RebuildFromActiveChain();
        LogPrintf("CShieldedWallet: rebuilt state after block disconnect at height %d (%s), last_scanned_height=%d\n",
                  height,
                  disconnected_hash.ToString(),
                  m_last_scanned_height);
        return;
    }

    const uint64_t next_tree_size = m_tree.Size() - removed_output_count;
    if (!m_tree.Truncate(next_tree_size)) {
        RebuildFromActiveChain();
        LogPrintf("CShieldedWallet: rebuilt state after block disconnect at height %d (%s), last_scanned_height=%d\n",
                  height,
                  disconnected_hash.ToString(),
                  m_last_scanned_height);
        return;
    }

    for (const Nullifier& nf : spend_nullifiers) {
        auto note_it = m_notes.find(nf);
        if (note_it != m_notes.end() &&
            note_it->second.is_spent &&
            note_it->second.spent_height == height) {
            note_it->second.is_spent = false;
            note_it->second.spent_height = -1;
        }
        m_spent_nullifiers.erase(nf);
    }

    for (auto it = m_notes.begin(); it != m_notes.end();) {
        const ShieldedCoin& coin = it->second;
        const bool removed_by_block_output =
            coin.confirmation_height == height &&
            coin.block_hash == disconnected_hash &&
            removed_commitments.count(coin.commitment) != 0;
        const bool now_out_of_tree = coin.tree_position >= next_tree_size;
        if (removed_by_block_output || now_out_of_tree) {
            m_spent_nullifiers.erase(it->first);
            m_witnesses.erase(coin.commitment);
            it = m_notes.erase(it);
        } else {
            ++it;
        }
    }

    for (const auto& commitment : removed_commitments) {
        m_smile_public_accounts.erase(commitment);
        m_account_leaf_commitments.erase(commitment);
    }

    // Witnesses do not currently participate in spend construction, so clear
    // and rebuild lazily on future scans/rescans after rollback.
    m_witnesses.clear();
    m_last_scanned_height = height - 1;
    m_last_scanned_hash = block.hashPrevBlock;

    if (!m_defer_persist && !PersistState()) {
        LogPrintf("CShieldedWallet: failed to persist state after UndoBlock at height %d\n", height);
    } else {
        LogPrintf("CShieldedWallet: rolled back disconnected block at height %d (%s), removed_outputs=%u remaining_notes=%u tree_size=%u\n",
                  height,
                  disconnected_hash.ToString(),
                  static_cast<unsigned int>(removed_output_count),
                  static_cast<unsigned int>(m_notes.size()),
                  static_cast<unsigned int>(m_tree.Size()));
    }
}

void CShieldedWallet::TransactionAddedToMempool(const CTransaction& tx)
{
    AssertLockHeld(cs_shielded);
    if (!tx.HasShieldedBundle()) return;
    // Match the block-scan path: only read the shielded master seed when the
    // wallet is encrypted and currently unlocked.
    const bool can_access_master_seed = m_parent_wallet.IsCrypted() && !m_parent_wallet.IsLocked();
    std::vector<unsigned char> master_seed;
    if (can_access_master_seed) {
        master_seed = GetMasterSeed();
    }
    ScopedByteVectorCleanse master_seed_cleanse_mempool(master_seed);
    const CShieldedBundle& bundle = tx.GetShieldedBundle();
    ShieldedTxView tx_view;
    tx_view.value_balance = GetShieldedStateValueBalance(bundle);
    tx_view.family = DescribeShieldedBundleFamily(bundle);
    bool tx_has_local_visibility{false};

    for (const Nullifier& nullifier : CollectShieldedNullifiers(bundle)) {
        ShieldedTxViewSpend spend_view;
        spend_view.nullifier = nullifier;
        const auto it = m_notes.find(nullifier);
        if (it != m_notes.end()) {
            // Keep live mempool spends unavailable for reselection until the
            // transaction leaves the mempool or confirms in a block.
            m_pending_spends.insert(nullifier);
            spend_view.amount = it->second.note.value;
            spend_view.is_ours = true;
            tx_has_local_visibility = true;
        }
        tx_view.spends.push_back(std::move(spend_view));
    }

    const uint256 txid = tx.GetHash();
    if (bundle.HasV2Bundle()) {
        const auto* v2_bundle = bundle.GetV2Bundle();
        if (v2_bundle != nullptr) {
            switch (shielded::v2::GetBundleSemanticFamily(*v2_bundle)) {
            case shielded::v2::TransactionFamily::V2_SEND: {
                const auto& payload = std::get<shielded::v2::SendPayload>(v2_bundle->payload);
                const shielded::registry::AccountLeafHint account_leaf_hint =
                    shielded::registry::MakeDirectSendAccountLeafHint();
                for (const auto& output : payload.outputs) {
                    RecordMempoolOutput(txid,
                                        output,
                                        account_leaf_hint,
                                        master_seed,
                                        tx_view,
                                        tx_has_local_visibility);
                }
                break;
            }
            case shielded::v2::TransactionFamily::V2_LIFECYCLE:
                break;
            case shielded::v2::TransactionFamily::V2_INGRESS_BATCH: {
                const auto& payload = std::get<shielded::v2::IngressBatchPayload>(v2_bundle->payload);
                const auto account_leaf_hint =
                    shielded::registry::MakeIngressAccountLeafHint(payload.settlement_binding_digest);
                for (const auto& output : payload.reserve_outputs) {
                    RecordMempoolOutput(txid,
                                        output,
                                        account_leaf_hint,
                                        master_seed,
                                        tx_view,
                                        tx_has_local_visibility);
                }
                break;
            }
            case shielded::v2::TransactionFamily::V2_EGRESS_BATCH: {
                const auto& payload = std::get<shielded::v2::EgressBatchPayload>(v2_bundle->payload);
                const auto account_leaf_hint = shielded::registry::MakeEgressAccountLeafHint(
                    payload.settlement_binding_digest,
                    payload.output_binding_digest);
                const bool recorded = RecordCanonicalOutputChunks(
                    *v2_bundle,
                    {payload.outputs.data(), payload.outputs.size()},
                    "CShieldedWallet::TransactionAddedToMempool",
                    [&](const shielded::v2::OutputDescription& output) NO_THREAD_SAFETY_ANALYSIS {
                        RecordMempoolOutput(txid,
                                            output,
                                            account_leaf_hint,
                                            master_seed,
                                            tx_view,
                                            tx_has_local_visibility);
                    });
                if (recorded) {
                    AppendOutputChunkViews(tx_view,
                                           {v2_bundle->output_chunks.data(), v2_bundle->output_chunks.size()},
                                           "CShieldedWallet::TransactionAddedToMempool");
                }
                break;
            }
            case shielded::v2::TransactionFamily::V2_REBALANCE: {
                const auto& payload = std::get<shielded::v2::RebalancePayload>(v2_bundle->payload);
                const auto account_leaf_hint =
                    shielded::registry::MakeRebalanceAccountLeafHint(payload.settlement_binding_digest);
                if (!v2_bundle->output_chunks.empty()) {
                    const bool recorded = RecordCanonicalOutputChunks(
                        *v2_bundle,
                        {payload.reserve_outputs.data(), payload.reserve_outputs.size()},
                        "CShieldedWallet::TransactionAddedToMempool",
                        [&](const shielded::v2::OutputDescription& output) NO_THREAD_SAFETY_ANALYSIS {
                            RecordMempoolOutput(txid,
                                                output,
                                                account_leaf_hint,
                                                master_seed,
                                                tx_view,
                                                tx_has_local_visibility);
                        });
                    if (recorded) {
                        AppendOutputChunkViews(tx_view,
                                               {v2_bundle->output_chunks.data(), v2_bundle->output_chunks.size()},
                                               "CShieldedWallet::TransactionAddedToMempool");
                    }
                } else {
                    for (const auto& output : payload.reserve_outputs) {
                        RecordMempoolOutput(txid,
                                            output,
                                            account_leaf_hint,
                                            master_seed,
                                            tx_view,
                                            tx_has_local_visibility);
                    }
                }
                break;
            }
            case shielded::v2::TransactionFamily::V2_SETTLEMENT_ANCHOR:
            case shielded::v2::TransactionFamily::V2_GENERIC:
                break;
            }
        }
    } else {
        for (const auto& output : bundle.shielded_outputs) {
            RecordMempoolOutput(txid,
                                output.note_commitment,
                                output.encrypted_note,
                                master_seed,
                                tx_view,
                                tx_has_local_visibility);
        }
    }

    if (tx_has_local_visibility) {
        m_tx_view_cache[tx.GetHash()] = std::move(tx_view);
    }
}

void CShieldedWallet::TransactionRemovedFromMempool(const CTransaction& tx)
{
    AssertLockHeld(cs_shielded);
    if (!tx.HasShieldedBundle()) return;

    const CShieldedBundle& bundle = tx.GetShieldedBundle();
    const uint256& txid = tx.GetHash();

    // Remove mempool-tracked output notes using the reverse index (keyed by
    // output-derived nullifiers, not input spend nullifiers).
    auto idx_it = m_mempool_note_index.find(txid);
    if (idx_it != m_mempool_note_index.end()) {
        for (const auto& nf : idx_it->second) {
            m_mempool_notes.erase(nf);
        }
        m_mempool_note_index.erase(idx_it);
    }

    // Remove mempool tx view cache entry.
    m_tx_view_cache.erase(txid);

    for (const auto& [commitment, _] : CollectShieldedOutputSmileAccounts(bundle)) {
        m_smile_public_accounts.erase(commitment);
        m_account_leaf_commitments.erase(commitment);
    }

    // Release any pending spend reservations held for this transaction's inputs.
    for (const Nullifier& nullifier : CollectShieldedNullifiers(bundle)) {
        if (!NullifierReservedByAnotherMempoolTx(nullifier, txid)) {
            m_pending_spends.erase(nullifier);
        }
    }
}

void CShieldedWallet::Rescan(int start_height)
{
    AssertLockHeld(cs_shielded);
    m_notes.clear();
    m_spent_nullifiers.clear();
    m_witnesses.clear();
    m_smile_public_accounts.clear();
    m_account_leaf_commitments.clear();
    m_mempool_notes.clear();
    m_mempool_note_index.clear();
    m_pending_spends.clear();
    m_tx_view_cache.clear();
    m_tree = shielded::ShieldedMerkleTree{shielded::ShieldedMerkleTree::IndexStorageMode::MEMORY_ONLY};
    m_last_scanned_height = start_height - 1;
    m_last_scanned_hash.SetNull();
    m_locked_state_incomplete = false;
    if (!m_defer_persist && !PersistState()) {
        LogPrintf("CShieldedWallet: failed to persist state after Rescan reset\n");
    }
}

void CShieldedWallet::PruneStalePendingSpends() const
{
    AssertLockHeld(cs_shielded);

    std::vector<Nullifier> stale_pending;
    for (const auto& nf : m_pending_spends) {
        if (!NullifierReservedByAnotherMempoolTx(nf)) stale_pending.push_back(nf);
    }
    for (const auto& nf : stale_pending) {
        m_pending_spends.erase(nf);
    }
}

ShieldedBalanceSummary CShieldedWallet::GetShieldedBalanceSummary(int min_depth) const
{
    AssertLockHeld(cs_shielded);
    ShieldedBalanceSummary summary;
    const auto notes = GetUnspentNotes(min_depth);
    for (const auto& coin : notes) {
        CAmount& bucket_amount = coin.is_mine_spend ? summary.spendable : summary.watchonly;
        int64_t& bucket_count = coin.is_mine_spend ? summary.spendable_note_count : summary.watchonly_note_count;
        const auto sum = CheckedAdd(bucket_amount, coin.note.value);
            if (!sum) {
            LogPrintf("CShieldedWallet::GetShieldedBalanceSummary: overflow detected, returning partial balance\n");
            return summary;
            }
        bucket_amount = *sum;
        ++bucket_count;
    }
    return summary;
}

CAmount CShieldedWallet::GetShieldedBalance(int min_depth) const
{
    AssertLockHeld(cs_shielded);
    return GetShieldedBalanceSummary(min_depth).spendable;
}

std::vector<ShieldedCoin> CShieldedWallet::GetSpendableNotes(int min_depth) const
{
    AssertLockHeld(cs_shielded);
    const int tip_height = GetChainTipHeight();
    std::vector<ShieldedCoin> out;
    out.reserve(m_notes.size());

    PruneStalePendingSpends();

    for (const auto& [nf, coin] : m_notes) {
        if (coin.is_spent || !coin.is_mine_spend) continue;
        if (!IsWalletSpendableNoteClass(coin.note_class)) continue;
        if (!IsShieldedSmileValueCompatible(coin.note.value)) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::GetSpendableNotes skipping note commitment=%s value=%lld outside SMILE range (< %lld)\n",
                     coin.commitment.ToString(),
                     static_cast<long long>(coin.note.value),
                     static_cast<long long>(GetShieldedSmileValueLimit() + 1));
            continue;
        }
        // R5-520: Skip notes that are reserved by an in-flight transaction.
        if (m_pending_spends.count(nf)) continue;
        if (coin.GetDepth(tip_height) >= min_depth) {
            out.push_back(coin);
        }
    }
    return out;
}

std::vector<ShieldedCoin> CShieldedWallet::GetUnspentNotes(int min_depth) const
{
    AssertLockHeld(cs_shielded);
    PruneStalePendingSpends();

    const int tip_height = GetChainTipHeight();
    std::vector<ShieldedCoin> out;
    out.reserve(m_notes.size() + (min_depth == 0 ? m_mempool_notes.size() : 0));
    auto maybe_add = [&](const Nullifier& nf, const ShieldedCoin& coin) NO_THREAD_SAFETY_ANALYSIS {
        if (coin.is_spent) return;
        if (!IsWalletSpendableNoteClass(coin.note_class)) return;
        if (coin.is_mine_spend && m_pending_spends.count(nf)) return;
        if (coin.GetDepth(tip_height) >= min_depth) {
            out.push_back(coin);
        }
    };
    for (const auto& [nf, coin] : m_notes) {
        maybe_add(nf, coin);
    }
    if (min_depth == 0) {
        for (const auto& [nf, coin] : m_mempool_notes) {
            if (m_notes.count(nf) != 0) continue;
            maybe_add(nf, coin);
        }
    }
    return out;
}

std::optional<ShieldedSpendSelectionEstimate> CShieldedWallet::EstimateDirectSpendSelection(
    const std::vector<std::pair<ShieldedAddress, CAmount>>& shielded_recipients,
    const std::vector<std::pair<CTxDestination, CAmount>>& transparent_recipients,
    const CAmount fee,
    std::string* error,
    const std::vector<ShieldedCoin>* selected_override) const
{
    AssertLockHeld(cs_shielded);
    auto fail = [&](const std::string& reason) -> std::optional<ShieldedSpendSelectionEstimate> {
        if (error != nullptr) *error = reason;
        return std::nullopt;
    };

    if (shielded_recipients.empty() && transparent_recipients.empty()) return fail("no recipients");
    if (fee < 0 || !MoneyRange(fee)) return fail("invalid fee");

    CAmount total_needed{fee};
    for (const auto& [_, amount] : shielded_recipients) {
        if (amount <= 0 || !MoneyRange(amount)) return fail("invalid shielded recipient amount");
        const auto next = CheckedAdd(total_needed, amount);
        if (!next || !MoneyRange(*next)) return fail("shielded recipient total overflow");
        total_needed = *next;
    }
    for (const auto& [_, amount] : transparent_recipients) {
        if (amount <= 0 || !MoneyRange(amount)) return fail("invalid transparent recipient amount");
        const auto next = CheckedAdd(total_needed, amount);
        if (!next || !MoneyRange(*next)) return fail("transparent recipient total overflow");
        total_needed = *next;
    }

    const bool prefer_minimal_inputs = !transparent_recipients.empty();
    auto selected = selected_override != nullptr
        ? *selected_override
        : SelectNotes(total_needed, fee, prefer_minimal_inputs);
    if (selected.empty()) return fail("no spendable notes selected");
    if (selected.size() > shielded::v2::MAX_DIRECT_SPENDS) {
        return fail("selected note count exceeds v2 spend limit");
    }

    const size_t ring_size = GetConfiguredShieldedRingSize();
    if (selected.size() > ring_size) {
        return fail("selected note count exceeds SMILE shared ring limit");
    }

    CAmount total_input{0};
    for (const auto& coin : selected) {
        if (!IsShieldedSmileValueCompatible(coin.note.value)) {
            return fail("selected note exceeds SMILE input value limit");
        }
        const auto next = CheckedAdd(total_input, coin.note.value);
        if (!next || !MoneyRange(*next)) return fail("selected input total overflow");
        total_input = *next;
    }
    if (total_input < total_needed) return fail("selected input below total needed");

    CAmount change = total_input - total_needed;
    const bool reserve_shielded_change =
        change == 0 &&
        selected.size() > 1 &&
        shielded_recipients.size() == 1 &&
        transparent_recipients.empty();
    if (selected_override == nullptr &&
        ((change == 0 && shielded_recipients.empty() && !transparent_recipients.empty()) ||
         reserve_shielded_change)) {
        const auto reserved_target = CheckedAdd(total_needed, CAmount{1});
        if (!reserved_target || !MoneyRange(*reserved_target)) {
            return fail(reserve_shielded_change
                            ? "shielded send change reserve overflow"
                            : "unshield change reserve overflow");
        }

        auto reserved_selection = SelectNotes(*reserved_target, fee, prefer_minimal_inputs);
        if (reserved_selection.empty()) {
            return fail(reserve_shielded_change
                            ? "exact-balance shielded send requires at least 1 sat change reserve"
                            : "exact-balance unshield requires at least 1 sat change reserve");
        }

        CAmount reserved_total{0};
        for (const auto& coin : reserved_selection) {
            if (!IsShieldedSmileValueCompatible(coin.note.value)) {
                return fail("selected note exceeds SMILE input value limit");
            }
            const auto next = CheckedAdd(reserved_total, coin.note.value);
            if (!next || !MoneyRange(*next)) return fail("selected input total overflow");
            reserved_total = *next;
        }
        if (reserved_total < *reserved_target) {
            return fail(reserve_shielded_change
                            ? "exact-balance shielded send requires at least 1 sat change reserve"
                            : "exact-balance unshield requires at least 1 sat change reserve");
        }

        selected = std::move(reserved_selection);
        total_input = reserved_total;
        change = total_input - total_needed;
    }

    if (selected.size() > shielded::v2::MAX_DIRECT_SPENDS) {
        return fail("selected note count exceeds v2 spend limit");
    }
    if (selected.size() > shielded::v2::MAX_LIVE_DIRECT_SMILE_SPENDS) {
        return fail("direct shielded send currently supports at most 2 shielded inputs; merge notes first");
    }
    if (selected.size() > shielded::lattice::RING_SIZE) {
        return fail("selected note count exceeds SMILE shared ring limit");
    }

    const size_t shielded_output_count = shielded_recipients.size() + (change > 0 ? 1 : 0);
    if (shielded_output_count > shielded::v2::MAX_DIRECT_OUTPUTS) {
        return fail("shielded output count exceeds v2 output limit");
    }

    size_t transparent_output_bytes{0};
    for (const auto& [destination, amount] : transparent_recipients) {
        const size_t output_bytes = ::GetSerializeSize(CTxOut(amount, GetScriptForDestination(destination)));
        if (output_bytes > std::numeric_limits<size_t>::max() - transparent_output_bytes) {
            return fail("transparent output size overflow");
        }
        transparent_output_bytes += output_bytes;
    }

    ShieldedSpendSelectionEstimate estimate;
    estimate.selected = std::move(selected);
    estimate.total_needed = total_needed;
    estimate.total_input = total_input;
    estimate.change = change;
    estimate.shielded_output_count = shielded_output_count;
    estimate.transparent_output_bytes = transparent_output_bytes;
    return estimate;
}

std::optional<CMutableTransaction> CShieldedWallet::CreateV2Send(
    const std::vector<std::pair<ShieldedAddress, CAmount>>& shielded_recipients,
    const std::vector<std::pair<CTxDestination, CAmount>>& transparent_recipients,
    CAmount fee,
    std::string* error)
{
    return CreateV2Send(shielded_recipients,
                        transparent_recipients,
                        fee,
                        /*selected_override=*/nullptr,
                        error);
}

std::optional<CMutableTransaction> CShieldedWallet::CreateV2Send(
    const std::vector<std::pair<ShieldedAddress, CAmount>>& shielded_recipients,
    const std::vector<std::pair<CTxDestination, CAmount>>& transparent_recipients,
    CAmount fee,
    const std::vector<ShieldedCoin>* selected_override,
    std::string* error)
{
    AssertLockHeld(cs_shielded);
    auto fail = [&](const char* reason) -> std::optional<CMutableTransaction> {
        if (error != nullptr) *error = reason;
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2Send aborted: %s\n", reason);
        return std::nullopt;
    };

    if (!RequireEncryptedShieldedWallet(m_parent_wallet, "CShieldedWallet::CreateV2Send", error)) {
        return std::nullopt;
    }

    if (shielded_recipients.empty() && transparent_recipients.empty()) return fail("no recipients");
    if (fee < 0 || !MoneyRange(fee)) return fail("invalid fee");
    const size_t ring_size = GetConfiguredShieldedRingSize();
    const int32_t validation_height = NextShieldedBuildValidationHeight(m_parent_wallet.chain());
    fee = shielded::RoundShieldedFeeToCanonicalBucket(
        fee,
        Params().GetConsensus(),
        validation_height);
    const CFeeRate relay_dust_fee = m_parent_wallet.chain().relayDustFee();
    const CAmount shielded_dust_threshold =
        GetShieldedDustThresholdForHeight(relay_dust_fee, validation_height);
    const CAmount minimum_change_reserve =
        GetShieldedMinimumChangeReserveForHeight(relay_dust_fee, validation_height);
    const uint64_t minimum_privacy_tree_size =
        GetShieldedMinimumPrivacyTreeSizeForHeight(ring_size, validation_height);
    if (!transparent_recipients.empty() &&
        !AllowMixedTransparentShieldedSendAtHeight(validation_height)) {
        return fail("post-fork mixed shielded-to-transparent direct sends are disabled; use bridge unshield");
    }

    if (minimum_privacy_tree_size > 0 && m_tree.Size() < minimum_privacy_tree_size) {
        LogPrintf("CShieldedWallet::CreateV2Send failed: anonymity pool below post-fork minimum "
                  "(tree_size=%u, need=%u)\n",
                  static_cast<unsigned int>(m_tree.Size()),
                  static_cast<unsigned int>(minimum_privacy_tree_size));
        return fail(tfm::format("shielded anonymity pool below post-fork minimum: need at least %u shielded outputs on chain before sending",
                                static_cast<unsigned int>(minimum_privacy_tree_size)).c_str());
    }

    if (m_tree.Size() < ring_size) {
        LogPrintf("CShieldedWallet::CreateV2Send failed: insufficient ring diversity (tree_size=%u, need=%u)\n",
                  static_cast<unsigned int>(m_tree.Size()),
                  static_cast<unsigned int>(ring_size));
        return fail(tfm::format("insufficient ring diversity: need at least %u shielded outputs on chain before sending",
                                static_cast<unsigned int>(ring_size)).c_str());
    }

    for (const auto& [_, amount] : shielded_recipients) {
        if (amount <= 0 || !MoneyRange(amount)) return fail("invalid shielded recipient amount");
        if (!IsShieldedSmileValueCompatible(amount)) {
            return fail("shielded recipient amount exceeds SMILE note value limit");
        }
        if (shielded_dust_threshold > 0 && amount < shielded_dust_threshold) {
            return fail("shielded recipient amount below dust threshold");
        }
    }
    for (const auto& [_, amount] : transparent_recipients) {
        if (amount <= 0 || !MoneyRange(amount)) return fail("invalid transparent recipient amount");
    }

    ShieldedSpendSelectionEstimate selection;
    if (selected_override != nullptr) {
        selection.selected = *selected_override;
        selection.total_needed = fee;
        for (const auto& [_, amount] : shielded_recipients) {
            if (amount <= 0 || !MoneyRange(amount)) return fail("invalid shielded recipient amount");
            const auto next = CheckedAdd(selection.total_needed, amount);
            if (!next || !MoneyRange(*next)) return fail("shielded recipient total overflow");
            selection.total_needed = *next;
        }
        for (const auto& [_, amount] : transparent_recipients) {
            if (amount <= 0 || !MoneyRange(amount)) return fail("invalid transparent recipient amount");
            const auto next = CheckedAdd(selection.total_needed, amount);
            if (!next || !MoneyRange(*next)) return fail("transparent recipient total overflow");
            selection.total_needed = *next;
        }
        if (selection.selected.empty()) return fail("no spendable notes selected");
        for (const auto& coin : selection.selected) {
            if (!IsShieldedSmileValueCompatible(coin.note.value)) {
                return fail("selected note exceeds SMILE input value limit");
            }
            const auto next = CheckedAdd(selection.total_input, coin.note.value);
            if (!next || !MoneyRange(*next)) return fail("selected input total overflow");
            selection.total_input = *next;
        }
        if (selection.total_input < selection.total_needed) return fail("selected input below total needed");
        selection.change = selection.total_input - selection.total_needed;
        selection.shielded_output_count = shielded_recipients.size() + (selection.change > 0 ? 1 : 0);
    } else {
        std::string selection_error;
        const auto estimate = EstimateDirectSpendSelection(
            shielded_recipients,
            transparent_recipients,
            fee,
            &selection_error);
        if (!estimate.has_value()) return fail(selection_error.c_str());
        selection = *estimate;
    }

    auto& selected = selection.selected;
    CAmount change = selection.change;
    if (selected.size() > ring_size) {
        return fail("selected note count exceeds SMILE shared ring limit");
    }

    if (!m_tree.HasCommitmentIndex()) {
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2Send rebuilding due to missing commitment index\n");
        CatchUpToChainTip();
        if (!m_tree.HasCommitmentIndex()) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2Send aborted: commitment index unavailable after rebuild attempt\n");
            return fail("commitment index unavailable after rebuild attempt");
        }
    }

    CAmount total_input = selection.total_input;
    const bool prefer_minimal_inputs = !transparent_recipients.empty();
    const bool reserve_shielded_change =
        change == 0 &&
        selected.size() > 1 &&
        shielded_recipients.size() == 1 &&
        transparent_recipients.empty();
    const bool dust_change_needs_reserve =
        shielded_dust_threshold > 0 &&
        change > 0 &&
        change < minimum_change_reserve;
    if (selected_override == nullptr &&
        ((change == 0 && shielded_recipients.empty() && !transparent_recipients.empty()) ||
         dust_change_needs_reserve ||
         reserve_shielded_change)) {
        const auto reserved_target = CheckedAdd(
            selection.total_needed,
            dust_change_needs_reserve || reserve_shielded_change || !shielded_recipients.empty()
                ? minimum_change_reserve
                : CAmount{1});
        if (!reserved_target || !MoneyRange(*reserved_target)) {
            return fail(reserve_shielded_change
                            ? "shielded send change reserve overflow"
                            : "unshield change reserve overflow");
        }
        auto reserved_selection = SelectNotes(*reserved_target, fee, prefer_minimal_inputs);
        if (reserved_selection.empty()) {
            return fail(dust_change_needs_reserve
                            ? "shielded send requires change above the post-fork dust threshold"
                            : (reserve_shielded_change
                                   ? "exact-balance shielded send requires post-fork change reserve"
                                   : "exact-balance unshield requires post-fork change reserve"));
        }
        CAmount reserved_total{0};
        for (const auto& coin : reserved_selection) {
            if (!IsShieldedSmileValueCompatible(coin.note.value)) {
                return fail("selected note exceeds SMILE input value limit");
            }
            const auto next = CheckedAdd(reserved_total, coin.note.value);
            if (!next || !MoneyRange(*next)) return fail("selected input total overflow");
            reserved_total = *next;
        }
        if (reserved_total < *reserved_target) {
            return fail(dust_change_needs_reserve
                            ? "shielded send requires change above the post-fork dust threshold"
                            : (reserve_shielded_change
                                   ? "exact-balance shielded send requires post-fork change reserve"
                                   : "exact-balance unshield requires post-fork change reserve"));
        }
        selected = std::move(reserved_selection);
        total_input = reserved_total;
        change = total_input - selection.total_needed;
        selection.total_input = total_input;
        selection.change = change;
        selection.shielded_output_count = shielded_recipients.size() + (change > 0 ? 1 : 0);
    }
    if (shielded_dust_threshold > 0 && change > 0 && change < minimum_change_reserve) {
        return fail("shielded change would fall below the post-fork dust threshold");
    }
    if (selected.size() > shielded::v2::MAX_DIRECT_SPENDS) {
        return fail("selected note count exceeds v2 spend limit");
    }
    if (selected.size() > shielded::v2::MAX_LIVE_DIRECT_SMILE_SPENDS) {
        return fail("direct shielded send currently supports at most 2 shielded inputs; merge notes first");
    }
    if (selected.size() > shielded::lattice::RING_SIZE) {
        return fail("selected note count exceeds SMILE shared ring limit");
    }
    const size_t output_count = selection.shielded_output_count;
    if (output_count > shielded::v2::MAX_DIRECT_OUTPUTS) {
        return fail("shielded output count exceeds v2 output limit");
    }

    std::vector<unsigned char> master_seed = GetMasterSeed();
    ScopedByteVectorCleanse master_seed_cleanse(master_seed);
    if (master_seed.empty()) {
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2Send requires unlocked wallet seed material\n");
        return fail("missing unlocked master seed");
    }

    std::vector<unsigned char> spend_key_material;
    ScopedByteVectorCleanse spend_key_material_cleanse(spend_key_material);
    std::vector<shielded::v2::V2SendSpendInput> spend_inputs;
    spend_inputs.reserve(selected.size());

    for (auto& coin : selected) {
        if (coin.tree_position >= m_tree.Size()) {
            LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2Send failed: coin tree position out of range (pos=%u tree_size=%u)\n",
                     static_cast<unsigned int>(coin.tree_position),
                     static_cast<unsigned int>(m_tree.Size()));
            return fail("selected note tree position out of range");
        }

        const auto smile_nullifier = smile2::wallet::ComputeSmileNullifierFromNote(
            smile2::wallet::SMILE_GLOBAL_SEED,
            coin.note);
        if (!smile_nullifier.has_value()) {
            LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2Send failed: unable to derive SMILE nullifier for commitment=%s\n",
                     coin.commitment.ToString());
            return fail("unable to derive SMILE nullifier");
        }
        if (*smile_nullifier != coin.nullifier) {
            const auto note_it = m_notes.find(coin.nullifier);
            const auto mempool_it = m_mempool_notes.find(coin.nullifier);
            const bool confirmed_collision =
                m_notes.count(*smile_nullifier) != 0 && note_it == m_notes.end();
            const bool mempool_collision =
                m_mempool_notes.count(*smile_nullifier) != 0 && mempool_it == m_mempool_notes.end();
            if (confirmed_collision || mempool_collision) {
                LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2Send failed: SMILE nullifier migration collision for commitment=%s\n",
                         coin.commitment.ToString());
                return fail("SMILE nullifier migration collision");
            }
            if (note_it != m_notes.end()) {
                ShieldedCoin migrated = note_it->second;
                migrated.nullifier = *smile_nullifier;
                m_notes.erase(note_it);
                m_notes.emplace(*smile_nullifier, std::move(migrated));
            }
            if (mempool_it != m_mempool_notes.end()) {
                ShieldedCoin migrated = mempool_it->second;
                migrated.nullifier = *smile_nullifier;
                m_mempool_notes.erase(mempool_it);
                m_mempool_notes.emplace(*smile_nullifier, std::move(migrated));
            }
            if (m_spent_nullifiers.erase(coin.nullifier) > 0) {
                m_spent_nullifiers.insert(*smile_nullifier);
            }
            if (m_pending_spends.erase(coin.nullifier) > 0) {
                m_pending_spends.insert(*smile_nullifier);
            }
            coin.nullifier = *smile_nullifier;
        }

        const ShieldedKeySet* signing_keyset{nullptr};
        for (const auto& [_, keyset] : m_key_sets) {
            if (!keyset.has_spending_key || !keyset.spending_key_loaded || !keyset.spending_key.IsValid()) continue;
            if (keyset.spending_pk_hash == coin.note.recipient_pk_hash) {
                signing_keyset = &keyset;
                break;
            }
        }
        if (signing_keyset == nullptr) {
            LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2Send missing spending key for note pk_hash=%s\n",
                     coin.note.recipient_pk_hash.ToString());
            return fail("missing spending key for selected note");
        }

        std::vector<unsigned char> note_spend_secret = DeriveShieldedSpendSecretMaterial(master_seed, *signing_keyset);
        ScopedByteVectorCleanse note_spend_secret_cleanse(note_spend_secret);
        if (note_spend_secret.empty()) {
            LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2Send failed to derive spend secret for note pk_hash=%s\n",
                     coin.note.recipient_pk_hash.ToString());
            return fail("unable to derive spend secret");
        }
        if (spend_key_material.empty()) {
            spend_key_material = note_spend_secret;
        } else if (spend_key_material != note_spend_secret) {
            LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2Send requires notes from one spending keyset per transaction\n");
            return fail("notes from multiple spending keysets selected");
        }
    }

    uint256 build_privacy_nonce;
    GetStrongRandBytes(Span<unsigned char>{build_privacy_nonce.begin(), uint256::size()});
    std::vector<Nullifier> selected_nullifiers;
    selected_nullifiers.reserve(selected.size());
    for (const auto& coin : selected) {
        selected_nullifiers.push_back(coin.nullifier);
    }
    const uint256 shared_ring_seed = DeriveShieldedSharedRingSeed(
        selected_nullifiers,
        Span<const unsigned char>{spend_key_material.data(), spend_key_material.size()},
        build_privacy_nonce,
        validation_height);

    auto shared_ring = BuildSharedSmileRingSelection(
        m_tree,
        selected,
        ring_size,
        shared_ring_seed,
        GetShieldedDecoyTipExclusionWindowForHeight(validation_height),
        Span<const uint64_t>{m_recent_ring_exclusions.data(), m_recent_ring_exclusions.size()});
    if (!shared_ring.has_value()) {
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2Send failed: unable to build shared SMILE ring for %u notes\n",
                 static_cast<unsigned int>(selected.size()));
        return fail("unable to build shared SMILE ring");
    }
    auto shared_ring_members = BuildRingMembersForSelection(m_tree, selected, shared_ring->positions);
    if (!shared_ring_members.has_value()) {
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2Send failed: unable to build shared ring members\n");
        return fail("unable to build shared ring members");
    }
    auto shared_smile_ring_members = BuildSmileRingMembersForSelection(m_tree,
                                                                       selected,
                                                                       m_smile_public_accounts,
                                                                       m_account_leaf_commitments,
                                                                       shared_ring->positions);
    if (!shared_smile_ring_members.has_value()) {
        LogDebug(BCLog::WALLETDB,
                 "CShieldedWallet::CreateV2Send failed: unable to build shared SMILE ring members\n");
        return fail("unable to build shared SMILE ring members");
    }

    for (size_t i = 0; i < selected.size(); ++i) {
        shielded::v2::V2SendSpendInput spend_input;
        spend_input.note = selected[i].note;
        spend_input.note_commitment = selected[i].commitment;
        if (!selected[i].account_leaf_hint.has_value() || !selected[i].account_leaf_hint->IsValid()) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2Send failed: missing account leaf hint for commitment=%s\n",
                     selected[i].commitment.ToString());
            return fail("selected note missing account registry hint");
        }
        spend_input.account_leaf_hint = selected[i].account_leaf_hint;
        const auto account_registry_witness =
            GetAccountRegistryWitnessForCoin(m_parent_wallet.chain(), selected[i]);
        if (!account_registry_witness.has_value()) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2Send failed: missing account registry witness for commitment=%s\n",
                     selected[i].commitment.ToString());
            return fail("selected note missing account registry witness");
        }
        spend_input.account_registry_anchor = account_registry_witness->first;
        spend_input.account_registry_proof = account_registry_witness->second;
        spend_input.ring_positions = shared_ring->positions;
        spend_input.ring_members = *shared_ring_members;
        spend_input.smile_ring_members = *shared_smile_ring_members;
        spend_input.real_index = shared_ring->real_indices[i];
        if (!spend_input.IsValid()) {
            LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2Send failed: invalid spend input for commitment=%s\n",
                     selected[i].commitment.ToString());
            return fail("constructed spend input is invalid");
        }
        spend_inputs.push_back(std::move(spend_input));
    }

    std::vector<shielded::v2::V2SendOutputInput> output_inputs;
    output_inputs.reserve(output_count);
    std::vector<std::pair<ShieldedAddress, CAmount>> candidate_outputs;
    candidate_outputs.reserve(output_count);
    for (const auto& recipient : shielded_recipients) {
        candidate_outputs.push_back(recipient);
    }
    if (change > 0) {
        candidate_outputs.emplace_back(GenerateNewAddress(), change);
    }

    std::vector<std::pair<ShieldedAddress, CAmount>> resolved_outputs;
    resolved_outputs.reserve(candidate_outputs.size());
    for (const size_t source_index : ComputeShieldedOutputOrder(
             shielded_recipients.size(),
             change > 0,
             build_privacy_nonce,
             validation_height)) {
        if (source_index >= candidate_outputs.size()) {
            return fail("invalid shielded output ordering");
        }
        resolved_outputs.push_back(candidate_outputs[source_index]);
    }

    for (const auto& [addr, amount] : resolved_outputs) {
        if (shielded_dust_threshold > 0 && amount < shielded_dust_threshold) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2Send failed: output below dust threshold addr=%s amount=%lld threshold=%lld\n",
                     addr.Encode(),
                     static_cast<long long>(amount),
                     static_cast<long long>(shielded_dust_threshold));
            return fail("shielded output below dust threshold");
        }
        const auto key_it = m_key_sets.find(addr);
        mlkem::PublicKey recipient_kem_pk{};
        const mlkem::SecretKey* local_recipient_kem_sk{nullptr};
        if (key_it != m_key_sets.end()) {
            recipient_kem_pk = key_it->second.kem_key.pk;
            local_recipient_kem_sk = &key_it->second.kem_key.sk;
        } else if (addr.HasKEMPublicKey()) {
            recipient_kem_pk = addr.kem_pk;
        } else {
            LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2Send failed: destination KEM public key unavailable for %s\n",
                     addr.Encode());
            return fail("destination KEM public key unavailable");
        }
        const uint256 recipient_kem_pk_hash = HashBytes(Span<const unsigned char>{recipient_kem_pk.data(),
                                                                                   recipient_kem_pk.size()});
        if (recipient_kem_pk_hash != addr.kem_pk_hash) {
            LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2Send failed: destination KEM hash mismatch for %s\n",
                     addr.Encode());
            return fail("destination KEM hash mismatch");
        }

        ShieldedNote note;
        note.value = amount;
        note.recipient_pk_hash = addr.pk_hash;
        if (note.value <= 0 || !MoneyRange(note.value) || note.recipient_pk_hash.IsNull()) {
            LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2Send failed: invalid output note for %s amount=%lld\n",
                     addr.Encode(),
                     static_cast<long long>(amount));
            return fail("invalid output note");
        }
        if (!IsShieldedSmileValueCompatible(note.value)) {
            return fail("shielded output exceeds SMILE note value limit");
        }

        const auto bound_note = shielded::NoteEncryption::EncryptBoundNote(note, recipient_kem_pk);
        note = bound_note.note;
        const shielded::EncryptedNote encrypted_note = bound_note.encrypted_note;
        if (local_recipient_kem_sk != nullptr &&
            !shielded::NoteEncryption::TryDecrypt(encrypted_note,
                                                  recipient_kem_pk,
                                                  *local_recipient_kem_sk).has_value()) {
            LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2Send self-decrypt failed addr=%s\n", addr.Encode());
            return fail("output self-decrypt failed");
        }

        auto payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
            encrypted_note,
            recipient_kem_pk,
            shielded::v2::ScanDomain::OPAQUE);
        if (!payload.has_value()) {
            LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2Send failed: unable to encode output payload for %s\n",
                     addr.Encode());
            return fail("unable to encode output payload");
        }

        shielded::v2::V2SendOutputInput output_input;
        output_input.note_class = shielded::v2::NoteClass::USER;
        output_input.note = std::move(note);
        output_input.encrypted_note = std::move(*payload);
        if (!output_input.IsValid()) {
            LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2Send failed: invalid output payload for %s\n",
                     addr.Encode());
            return fail("invalid output payload");
        }
        output_inputs.push_back(std::move(output_input));
    }

    CMutableTransaction tx_template;
    tx_template.version = CTransaction::CURRENT_VERSION;
    tx_template.nLockTime = FastRandomContext{}.rand32();
    for (const auto& [dest, amount] : transparent_recipients) {
        tx_template.vout.emplace_back(amount, GetScriptForDestination(dest));
    }

    std::optional<shielded::v2::V2SendBuildResult> built;
    std::string reject_reason;
    const auto& consensus = Params().GetConsensus();
    for (size_t builder_attempt = 0; builder_attempt < MAX_V2_SEND_BUILDER_PROOF_ATTEMPTS; ++builder_attempt) {
        std::array<unsigned char, 32> proof_rng_entropy{};
        GetStrongRandBytes(Span<unsigned char>{proof_rng_entropy.data(), proof_rng_entropy.size()});
        built = shielded::v2::BuildV2SendTransaction(
            tx_template,
            m_tree.Root(),
            spend_inputs,
            output_inputs,
            fee,
            Span<const unsigned char>{spend_key_material.data(), spend_key_material.size()},
            reject_reason,
            Span<const unsigned char>{proof_rng_entropy.data(), proof_rng_entropy.size()},
            &consensus,
            validation_height);
        memory_cleanse(proof_rng_entropy.data(), proof_rng_entropy.size());
        if (built.has_value() || reject_reason != "bad-shielded-v2-builder-proof") {
            break;
        }
        LogDebug(BCLog::WALLETDB,
                 "CShieldedWallet::CreateV2Send retrying transient builder proof failure attempt=%u/%u\n",
                 static_cast<unsigned int>(builder_attempt + 1),
                 static_cast<unsigned int>(MAX_V2_SEND_BUILDER_PROOF_ATTEMPTS));
    }
    if (!built.has_value()) {
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2Send failed: %s\n", reject_reason);
        if (error != nullptr && !reject_reason.empty()) *error = reject_reason;
        return std::nullopt;
    }
    if (!built->IsValid()) {
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2Send failed: builder returned invalid result\n");
        return fail("builder returned invalid v2_send transaction");
    }
    {
        CTransaction immutable_tx{built->tx};
        const auto* immutable_bundle = immutable_tx.GetShieldedBundle().GetV2Bundle();
        bool immutable_ok{false};
        if (immutable_bundle != nullptr) {
            const uint256 expected_extension_digest =
                shielded::v2::proof::ComputeV2SendExtensionDigest(immutable_tx);
            const auto immutable_proof_statement = shielded::v2::proof::DescribeV2SendStatement(
                immutable_tx,
                consensus,
                validation_height,
                expected_extension_digest);
            const auto expected_witness = SerializeV2SendWitness(built->witness);
            immutable_ok =
                immutable_bundle->IsValid() &&
                immutable_proof_statement.IsValid() &&
                ProofEnvelopesEqual(immutable_bundle->header.proof_envelope,
                                    immutable_proof_statement.envelope) &&
                immutable_bundle->header.payload_digest ==
                    shielded::v2::ComputePayloadDigest(immutable_bundle->payload) &&
                immutable_bundle->proof_payload == expected_witness;
            if (!immutable_ok) {
                LogPrintf("CShieldedWallet::CreateV2Send immutable self-check failed txid=%s "
                          "statement=%s expected_extension=%s actual_extension=%s "
                          "payload_digest=%s recomputed_payload_digest=%s "
                          "proof_payload_bytes=%u expected_proof_payload_bytes=%u\n",
                          immutable_tx.GetHash().ToString(),
                          immutable_proof_statement.envelope.statement_digest.ToString(),
                          expected_extension_digest.ToString(),
                          immutable_bundle->header.proof_envelope.extension_digest.ToString(),
                          immutable_bundle->header.payload_digest.ToString(),
                          shielded::v2::ComputePayloadDigest(immutable_bundle->payload).ToString(),
                          static_cast<unsigned int>(immutable_bundle->proof_payload.size()),
                          static_cast<unsigned int>(expected_witness.size()));
            }
        }
        if (!immutable_ok) {
            return fail("immutable self-check failed");
        }
    }
    wallet::UpdateShieldedHistoricalRingExclusionCache(
        m_recent_ring_exclusions,
        Span<const uint64_t>{shared_ring->positions.data(), shared_ring->positions.size()},
        Span<const size_t>{shared_ring->real_indices.data(), shared_ring->real_indices.size()},
        wallet::GetShieldedHistoricalRingExclusionLimit(ring_size, validation_height));
    return built->tx;
}

std::optional<CMutableTransaction> CShieldedWallet::CreateV2EgressBatch(
    const shielded::BridgeBatchStatement& statement,
    const std::vector<shielded::BridgeProofDescriptor>& proof_descriptors,
    const shielded::BridgeProofDescriptor& imported_descriptor,
    const std::vector<shielded::BridgeProofReceipt>& proof_receipts,
    const shielded::BridgeProofReceipt& imported_receipt,
    const std::vector<std::pair<ShieldedAddress, CAmount>>& shielded_recipients,
    const std::vector<uint32_t>& output_chunk_sizes,
    std::string* error)
{
    AssertLockHeld(cs_shielded);
    MaybeRehydrateSpendingKeys();

    auto fail = [&](const char* reason) -> std::optional<CMutableTransaction> {
        if (error != nullptr) *error = reason;
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2EgressBatch aborted: %s\n", reason);
        return std::nullopt;
    };

    if (!RequireEncryptedShieldedWallet(m_parent_wallet, "CShieldedWallet::CreateV2EgressBatch", error)) {
        return std::nullopt;
    }

    if (shielded_recipients.empty()) return fail("no shielded recipients");
    if (proof_descriptors.empty() || proof_receipts.empty()) return fail("missing proof metadata");
    if (!statement.IsValid() || statement.direction != shielded::BridgeDirection::BRIDGE_OUT) {
        return fail("invalid bridge batch statement");
    }

    std::vector<ResolvedV2ShieldedRecipient> resolved_recipients;
    resolved_recipients.reserve(shielded_recipients.size());
    const int32_t validation_height = NextShieldedBuildValidationHeight(m_parent_wallet.chain());
    for (const auto& [addr, amount] : shielded_recipients) {
        if (amount <= 0 || !MoneyRange(amount)) return fail("invalid shielded recipient amount");
        auto resolved = ResolveV2ShieldedRecipient(m_key_sets,
                                                   m_address_lifecycles,
                                                   addr,
                                                   amount,
                                                   validation_height,
                                                   "CShieldedWallet::CreateV2EgressBatch");
        if (!resolved.has_value()) return std::nullopt;
        resolved_recipients.push_back(std::move(*resolved));
    }

    std::vector<shielded::v2::V2EgressRecipient> recipients;
    recipients.reserve(resolved_recipients.size());
    for (const auto& resolved : resolved_recipients) {
        recipients.push_back(resolved.recipient);
    }

    std::string reject_reason;
    auto outputs = shielded::v2::BuildDeterministicEgressOutputs(
        statement,
        Span<const shielded::v2::V2EgressRecipient>{recipients.data(), recipients.size()},
        reject_reason);
    if (!outputs.has_value()) {
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2EgressBatch failed: %s\n", reject_reason);
        return std::nullopt;
    }

    for (size_t i = 0; i < outputs->size(); ++i) {
        if (resolved_recipients[i].local_recipient_kem_sk == nullptr) continue;
        const auto decrypted = TryDecryptNote((*outputs)[i].encrypted_note);
        if (!decrypted.has_value() ||
            decrypted->value != resolved_recipients[i].recipient.amount ||
            decrypted->recipient_pk_hash != resolved_recipients[i].recipient.recipient_pk_hash) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2EgressBatch self-decrypt failed index=%u amount=%lld\n",
                     static_cast<unsigned int>(i),
                     static_cast<long long>(resolved_recipients[i].recipient.amount));
            return std::nullopt;
        }
    }

    shielded::v2::V2EgressBuildInput input;
    input.statement = statement;
    input.proof_descriptors = proof_descriptors;
    input.imported_descriptor = imported_descriptor;
    input.proof_receipts = proof_receipts;
    input.imported_receipt = imported_receipt;
    input.outputs = std::move(*outputs);
    input.output_chunk_sizes = output_chunk_sizes;

    CMutableTransaction tx_template;
    tx_template.version = CTransaction::CURRENT_VERSION;
    tx_template.nLockTime = FastRandomContext{}.rand32();

    auto built = shielded::v2::BuildV2EgressBatchTransaction(tx_template,
                                                             input,
                                                             reject_reason,
                                                             &Params().GetConsensus(),
                                                             validation_height);
    if (!built.has_value()) {
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2EgressBatch failed: %s\n", reject_reason);
        return std::nullopt;
    }
    if (!built->IsValid()) {
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2EgressBatch failed: builder returned invalid result\n");
        return std::nullopt;
    }

    const CTransaction immutable_tx{built->tx};
    const auto* immutable_bundle = immutable_tx.GetShieldedBundle().GetV2Bundle();
    if (immutable_bundle == nullptr ||
        !shielded::v2::BundleHasSemanticFamily(*immutable_bundle,
                                               shielded::v2::TransactionFamily::V2_EGRESS_BATCH)) {
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2EgressBatch immutable bundle missing or wrong family\n");
        return std::nullopt;
    }
    auto immutable_witness =
        shielded::v2::proof::ParseSettlementWitness(immutable_bundle->proof_payload, reject_reason);
    if (!immutable_witness.has_value()) {
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2EgressBatch failed: %s\n", reject_reason);
        return std::nullopt;
    }
    if (immutable_bundle->proof_shards.empty()) {
        return fail("missing proof shard");
    }
    auto immutable_receipt = shielded::v2::proof::ParseImportedSettlementReceipt(
        immutable_bundle->header.proof_envelope,
        immutable_bundle->proof_shards.front(),
        reject_reason);
    if (!immutable_receipt.has_value()) {
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2EgressBatch failed: %s\n", reject_reason);
        return std::nullopt;
    }
    const auto immutable_context =
        shielded::v2::proof::DescribeImportedSettlementReceipt(*immutable_receipt,
                                                               shielded::v2::proof::PayloadLocation::INLINE_WITNESS,
                                                               immutable_bundle->proof_payload,
                                                               Params().GetConsensus(),
                                                               validation_height,
                                                               imported_descriptor);
    if (!shielded::v2::proof::VerifySettlementContext(immutable_context, *immutable_witness, reject_reason)) {
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2EgressBatch failed: %s\n", reject_reason);
        return std::nullopt;
    }

    return built->tx;
}

std::optional<CMutableTransaction> CShieldedWallet::CreateV2IngressBatch(
    const shielded::BridgeBatchStatement& statement,
    const std::vector<shielded::v2::V2IngressLeafInput>& ingress_leaves,
    const std::vector<std::pair<ShieldedAddress, CAmount>>& reserve_outputs,
    std::optional<shielded::v2::V2IngressSettlementWitness> settlement_witness,
    std::string* error)
{
    AssertLockHeld(cs_shielded);
    MaybeRehydrateSpendingKeys();

    auto fail = [&](const char* reason) -> std::optional<CMutableTransaction> {
        if (error != nullptr) *error = reason;
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2IngressBatch aborted: %s\n", reason);
        return std::nullopt;
    };

    if (!RequireEncryptedShieldedWallet(m_parent_wallet, "CShieldedWallet::CreateV2IngressBatch", error)) {
        return std::nullopt;
    }

    if (reserve_outputs.empty()) return fail("no reserve outputs");
    if (ingress_leaves.empty()) return fail("no ingress leaves");
    if (!statement.IsValid() || statement.direction != shielded::BridgeDirection::BRIDGE_IN) {
        return fail("invalid bridge batch statement");
    }
    if (ingress_leaves.size() > shielded::v2::MAX_BATCH_LEAVES) {
        return fail("ingress leaf count exceeds limit");
    }
    if (reserve_outputs.size() > shielded::v2::MAX_BATCH_RESERVE_OUTPUTS) {
        return fail("reserve output count exceeds limit");
    }
    const size_t ring_size = GetConfiguredShieldedRingSize();
    const int32_t validation_height = NextShieldedBuildValidationHeight(m_parent_wallet.chain());
    const CAmount shielded_dust_threshold = GetShieldedDustThresholdForHeight(
        m_parent_wallet.chain().relayDustFee(),
        validation_height);
    const CAmount minimum_change_reserve = GetShieldedMinimumChangeReserveForHeight(
        m_parent_wallet.chain().relayDustFee(),
        validation_height);
    const uint64_t minimum_privacy_tree_size =
        GetShieldedMinimumPrivacyTreeSizeForHeight(ring_size, validation_height);

    CAmount total_bridge_amount{0};
    CAmount total_fee{0};
    for (const auto& ingress_leaf : ingress_leaves) {
        if (!ingress_leaf.IsValid()) return fail("invalid ingress leaf");
        const auto next_amount = CheckedAdd(total_bridge_amount, ingress_leaf.bridge_leaf.amount);
        const auto next_fee = CheckedAdd(total_fee, ingress_leaf.fee);
        if (!next_amount || !next_fee || !MoneyRange(*next_amount) || !MoneyRange(*next_fee)) {
            return fail("invalid ingress leaf total");
        }
        total_bridge_amount = *next_amount;
        total_fee = *next_fee;
    }
    if (shielded::UseShieldedCanonicalFeeBuckets(Params().GetConsensus(), validation_height) &&
        !shielded::IsCanonicalShieldedFee(total_fee, Params().GetConsensus(), validation_height)) {
        return fail("post-fork ingress total fee must use canonical shielded fee buckets");
    }

    CAmount requested_reserve_total{0};
    for (const auto& [_, amount] : reserve_outputs) {
        if (amount <= 0 || !MoneyRange(amount)) return fail("invalid reserve output amount");
        if (shielded_dust_threshold > 0 && amount < shielded_dust_threshold) {
            return fail("reserve output amount below dust threshold");
        }
        const auto next = CheckedAdd(requested_reserve_total, amount);
        if (!next || !MoneyRange(*next)) return fail("reserve output total overflow");
        requested_reserve_total = *next;
    }

    const auto target_without_change = CheckedAdd(total_bridge_amount, total_fee);
    const auto total_needed = target_without_change
        ? CheckedAdd(*target_without_change, requested_reserve_total)
        : std::nullopt;
    if (!total_needed || !MoneyRange(*total_needed)) {
        return fail("ingress total overflow");
    }

    const auto spendable_notes = GetSpendableNotes(/*min_depth=*/1);
    if (spendable_notes.empty()) return fail("no spendable notes available");

    auto selected = SelectNotes(*total_needed, /*fee=*/0);
    if (selected.empty() ||
        !IsSchedulableV2IngressSelection(
            Span<const ShieldedCoin>{selected.data(), selected.size()},
            *total_needed,
            Span<const std::pair<ShieldedAddress, CAmount>>{reserve_outputs.data(), reserve_outputs.size()},
            Span<const shielded::v2::V2IngressLeafInput>{ingress_leaves.data(), ingress_leaves.size()})) {
        auto schedulable = SelectSchedulableV2IngressNotes(
            Span<const ShieldedCoin>{spendable_notes.data(), spendable_notes.size()},
            *total_needed,
            Span<const std::pair<ShieldedAddress, CAmount>>{reserve_outputs.data(), reserve_outputs.size()},
            Span<const shielded::v2::V2IngressLeafInput>{ingress_leaves.data(), ingress_leaves.size()});
        if (!schedulable.empty()) {
            selected = std::move(schedulable);
        }
    }

    if (selected.empty()) return fail("no schedulable notes selected");
    if (selected.size() > shielded::ringct::MAX_MATRICT_INPUTS) {
        return fail("selected note count exceeds ingress spend limit");
    }
    if (minimum_privacy_tree_size > 0 && m_tree.Size() < minimum_privacy_tree_size) {
        LogPrintf("CShieldedWallet::CreateV2IngressBatch failed: anonymity pool below post-fork minimum "
                  "(tree_size=%u, need=%u)\n",
                  static_cast<unsigned int>(m_tree.Size()),
                  static_cast<unsigned int>(minimum_privacy_tree_size));
        return fail(tfm::format("shielded anonymity pool below post-fork minimum: need at least %u shielded outputs on chain before ingress",
                                static_cast<unsigned int>(minimum_privacy_tree_size)).c_str());
    }
    if (m_tree.Size() < ring_size) {
        LogPrintf("CShieldedWallet::CreateV2IngressBatch failed: insufficient ring diversity (tree_size=%u, need=%u)\n",
                  static_cast<unsigned int>(m_tree.Size()),
                  static_cast<unsigned int>(ring_size));
        return fail(tfm::format("insufficient ring diversity: need at least %u shielded outputs on chain before ingress",
                                static_cast<unsigned int>(ring_size)).c_str());
    }
    if (selected.size() > ring_size) {
        return fail("selected note count exceeds configured shielded ring size");
    }

    CAmount total_input{0};
    for (const auto& coin : selected) {
        const auto next = CheckedAdd(total_input, coin.note.value);
        if (!next || !MoneyRange(*next)) return fail("selected input total overflow");
        total_input = *next;
    }
    if (total_input < *total_needed) return fail("selected input below total needed");
    const CAmount reserve_change = total_input - *total_needed;
    if (shielded_dust_threshold > 0 &&
        reserve_change > 0 &&
        reserve_change < minimum_change_reserve) {
        return fail("ingress reserve change would fall below the post-fork dust threshold");
    }

    const size_t reserve_output_count = reserve_outputs.size() + (reserve_change > 0 ? 1 : 0);
    if (reserve_output_count == 0 || reserve_output_count > shielded::v2::MAX_BATCH_RESERVE_OUTPUTS) {
        return fail("reserve output count exceeds ingress limit");
    }

    std::vector<unsigned char> master_seed = GetMasterSeed();
    ScopedByteVectorCleanse master_seed_cleanse(master_seed);
    if (master_seed.empty()) {
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2IngressBatch requires unlocked wallet seed material\n");
        return fail("missing unlocked master seed");
    }

    std::vector<unsigned char> spend_key_material;
    ScopedByteVectorCleanse spend_key_material_cleanse(spend_key_material);
    for (const auto& coin : selected) {
        if (coin.tree_position >= m_tree.Size()) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2IngressBatch failed: coin tree position out of range (pos=%u tree_size=%u)\n",
                     static_cast<unsigned int>(coin.tree_position),
                     static_cast<unsigned int>(m_tree.Size()));
            return std::nullopt;
        }

        const ShieldedKeySet* signing_keyset{nullptr};
        for (const auto& [_, keyset] : m_key_sets) {
            if (!keyset.has_spending_key || !keyset.spending_key_loaded || !keyset.spending_key.IsValid()) continue;
            if (keyset.spending_pk_hash == coin.note.recipient_pk_hash) {
                signing_keyset = &keyset;
                break;
            }
        }
        if (signing_keyset == nullptr) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2IngressBatch missing spending key for note pk_hash=%s\n",
                     coin.note.recipient_pk_hash.ToString());
            return std::nullopt;
        }

        std::vector<unsigned char> note_spend_secret = DeriveShieldedSpendSecretMaterial(master_seed, *signing_keyset);
        ScopedByteVectorCleanse note_spend_secret_cleanse(note_spend_secret);
        if (note_spend_secret.empty()) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2IngressBatch failed to derive spend secret for note pk_hash=%s\n",
                     coin.note.recipient_pk_hash.ToString());
            return std::nullopt;
        }
        if (spend_key_material.empty()) {
            spend_key_material = note_spend_secret;
        } else if (spend_key_material != note_spend_secret) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2IngressBatch requires notes from one spending keyset per transaction\n");
            return std::nullopt;
        }
    }

    uint256 build_privacy_nonce;
    GetStrongRandBytes(Span<unsigned char>{build_privacy_nonce.begin(), uint256::size()});
    std::vector<Nullifier> selected_nullifiers;
    selected_nullifiers.reserve(selected.size());
    for (const auto& coin : selected) {
        selected_nullifiers.push_back(coin.nullifier);
    }
    const uint256 shared_ring_seed = DeriveShieldedSharedRingSeed(
        selected_nullifiers,
        Span<const unsigned char>{spend_key_material.data(), spend_key_material.size()},
        build_privacy_nonce,
        validation_height);

    auto shared_ring = BuildSharedSmileRingSelection(
        m_tree,
        selected,
        ring_size,
        shared_ring_seed,
        GetShieldedDecoyTipExclusionWindowForHeight(validation_height),
        Span<const uint64_t>{m_recent_ring_exclusions.data(), m_recent_ring_exclusions.size()});
    if (!shared_ring.has_value()) {
        LogDebug(BCLog::WALLETDB,
                 "CShieldedWallet::CreateV2IngressBatch failed: unable to build shared SMILE ring for %u notes\n",
                 static_cast<unsigned int>(selected.size()));
        return fail("unable to build shared SMILE ring");
    }
    auto shared_ring_members = BuildRingMembersForSelection(m_tree, selected, shared_ring->positions);
    if (!shared_ring_members.has_value()) {
        LogDebug(BCLog::WALLETDB,
                 "CShieldedWallet::CreateV2IngressBatch failed: unable to build shared ring members\n");
        return std::nullopt;
    }
    auto shared_smile_ring_members = BuildSmileRingMembersForSelection(m_tree,
                                                                       selected,
                                                                       m_smile_public_accounts,
                                                                       m_account_leaf_commitments,
                                                                       shared_ring->positions);
    if (!shared_smile_ring_members.has_value()) {
        LogDebug(BCLog::WALLETDB,
                 "CShieldedWallet::CreateV2IngressBatch failed: unable to build shared SMILE ring members\n");
        return std::nullopt;
    }

    std::vector<shielded::v2::V2SendSpendInput> spend_inputs;
    spend_inputs.reserve(selected.size());
    for (size_t i = 0; i < selected.size(); ++i) {
        const auto& coin = selected[i];
        shielded::v2::V2SendSpendInput spend_input;
        spend_input.note = coin.note;
        spend_input.note_commitment = coin.commitment;
        if (!coin.account_leaf_hint.has_value() || !coin.account_leaf_hint->IsValid()) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2IngressBatch failed: missing account leaf hint for commitment=%s\n",
                     coin.commitment.ToString());
            return fail("selected ingress note missing account registry hint");
        }
        spend_input.account_leaf_hint = coin.account_leaf_hint;
        const auto account_registry_witness =
            GetAccountRegistryWitnessForCoin(m_parent_wallet.chain(), coin);
        if (!account_registry_witness.has_value()) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2IngressBatch failed: missing account registry witness for commitment=%s\n",
                     coin.commitment.ToString());
            return fail("selected ingress note missing account registry witness");
        }
        spend_input.account_registry_anchor = account_registry_witness->first;
        spend_input.account_registry_proof = account_registry_witness->second;
        spend_input.ring_positions = shared_ring->positions;
        spend_input.ring_members = *shared_ring_members;
        spend_input.smile_ring_members = *shared_smile_ring_members;
        spend_input.real_index = shared_ring->real_indices[i];
        if (!spend_input.IsValid()) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2IngressBatch failed: invalid spend input for commitment=%s\n",
                     coin.commitment.ToString());
            return std::nullopt;
        }
        spend_inputs.push_back(std::move(spend_input));
    }

    std::vector<std::pair<ShieldedAddress, CAmount>> candidate_reserve_outputs;
    candidate_reserve_outputs.reserve(reserve_output_count);
    for (const auto& reserve_output : reserve_outputs) {
        candidate_reserve_outputs.push_back(reserve_output);
    }
    if (reserve_change > 0) {
        candidate_reserve_outputs.emplace_back(GenerateNewAddress(), reserve_change);
    }

    std::vector<std::pair<ShieldedAddress, CAmount>> resolved_reserve_outputs;
    resolved_reserve_outputs.reserve(candidate_reserve_outputs.size());
    for (const size_t source_index : ComputeShieldedOutputOrder(
             reserve_outputs.size(),
             reserve_change > 0,
             build_privacy_nonce,
             validation_height)) {
        if (source_index >= candidate_reserve_outputs.size()) {
            return fail("invalid ingress reserve output ordering");
        }
        resolved_reserve_outputs.push_back(candidate_reserve_outputs[source_index]);
    }

    std::vector<shielded::v2::V2SendOutputInput> reserve_output_inputs;
    reserve_output_inputs.reserve(resolved_reserve_outputs.size());
    for (const auto& [addr, amount] : resolved_reserve_outputs) {
        if (shielded_dust_threshold > 0 && amount < shielded_dust_threshold) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2IngressBatch failed: reserve output below dust threshold addr=%s amount=%lld threshold=%lld\n",
                     addr.Encode(),
                     static_cast<long long>(amount),
                     static_cast<long long>(shielded_dust_threshold));
            return fail("reserve output below dust threshold");
        }
        auto resolved = ResolveV2ShieldedRecipient(m_key_sets,
                                                   m_address_lifecycles,
                                                   addr,
                                                   amount,
                                                   validation_height,
                                                   "CShieldedWallet::CreateV2IngressBatch");
        if (!resolved.has_value()) return std::nullopt;

        ShieldedNote note_template;
        note_template.value = amount;
        note_template.recipient_pk_hash = resolved->recipient.recipient_pk_hash;
        if (note_template.value <= 0 || !MoneyRange(note_template.value) || note_template.recipient_pk_hash.IsNull()) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2IngressBatch failed: invalid reserve note for %s amount=%lld\n",
                     addr.Encode(),
                     static_cast<long long>(amount));
            return std::nullopt;
        }

        const auto bound_note =
            shielded::NoteEncryption::EncryptBoundNote(note_template, resolved->recipient.recipient_kem_pk);
        const ShieldedNote& note = bound_note.note;
        const shielded::EncryptedNote& encrypted_note = bound_note.encrypted_note;
        if (resolved->local_recipient_kem_sk != nullptr &&
            !shielded::NoteEncryption::TryDecrypt(encrypted_note,
                                                  resolved->recipient.recipient_kem_pk,
                                                  *resolved->local_recipient_kem_sk).has_value()) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2IngressBatch self-decrypt failed addr=%s\n",
                     addr.Encode());
            return std::nullopt;
        }

        auto payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
            encrypted_note,
            resolved->recipient.recipient_kem_pk,
            shielded::v2::ScanDomain::OPAQUE);
        if (!payload.has_value()) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2IngressBatch failed: unable to encode reserve payload for %s\n",
                     addr.Encode());
            return std::nullopt;
        }

        shielded::v2::V2SendOutputInput output_input;
        output_input.note_class = shielded::v2::NoteClass::RESERVE;
        output_input.note = std::move(note);
        output_input.encrypted_note = std::move(*payload);
        if (!output_input.IsValid()) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2IngressBatch failed: invalid reserve payload for %s\n",
                     addr.Encode());
            return std::nullopt;
        }
        reserve_output_inputs.push_back(std::move(output_input));
    }

    shielded::v2::V2IngressBuildInput input;
    input.statement = statement;
    input.spend_inputs = std::move(spend_inputs);
    input.reserve_outputs = std::move(reserve_output_inputs);
    input.ingress_leaves = ingress_leaves;
    input.settlement_witness = std::move(settlement_witness);

    CMutableTransaction tx_template;
    tx_template.version = CTransaction::CURRENT_VERSION;
    tx_template.nLockTime = FastRandomContext{}.rand32();

    std::array<unsigned char, 32> proof_rng_entropy{};
    GetStrongRandBytes(Span<unsigned char>{proof_rng_entropy.data(), proof_rng_entropy.size()});
    std::string reject_reason;
    const auto& consensus = Params().GetConsensus();
    const bool bind_smile_anonset_context = consensus.IsShieldedMatRiCTDisabled(validation_height);
    auto built = shielded::v2::BuildV2IngressBatchTransaction(
        tx_template,
        m_tree.Root(),
        input,
        Span<const unsigned char>{spend_key_material.data(), spend_key_material.size()},
        reject_reason,
        Span<const unsigned char>{proof_rng_entropy.data(), proof_rng_entropy.size()},
        &consensus,
        validation_height);
    memory_cleanse(proof_rng_entropy.data(), proof_rng_entropy.size());
    if (!built.has_value()) {
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2IngressBatch failed: %s\n", reject_reason);
        return std::nullopt;
    }
    if (!built->IsValid()) {
        LogDebug(BCLog::WALLETDB,
                 "CShieldedWallet::CreateV2IngressBatch failed: builder returned invalid result\n");
        return std::nullopt;
    }

    const CTransaction immutable_tx{built->tx};
    const auto* immutable_bundle = immutable_tx.GetShieldedBundle().GetV2Bundle();
    if (immutable_bundle == nullptr ||
        !shielded::v2::BundleHasSemanticFamily(*immutable_bundle,
                                               shielded::v2::TransactionFamily::V2_INGRESS_BATCH)) {
        LogDebug(BCLog::WALLETDB,
                 "CShieldedWallet::CreateV2IngressBatch immutable bundle missing or wrong family\n");
        return std::nullopt;
    }

    std::string immutable_reject;
    auto immutable_context = shielded::v2::ParseV2IngressProof(*immutable_bundle, immutable_reject);
    auto immutable_ring_members = immutable_context.has_value()
        ? shielded::v2::BuildV2IngressSmileRingMembers(*immutable_context,
                                                       m_tree,
                                                       m_smile_public_accounts,
                                                       m_account_leaf_commitments,
                                                       immutable_reject)
        : std::nullopt;
    const bool immutable_ok = immutable_context.has_value() &&
                              immutable_ring_members.has_value() &&
                              shielded::v2::VerifyV2IngressProof(*immutable_bundle,
                                                                 *immutable_context,
                                                                 *immutable_ring_members,
                                                                 immutable_reject,
                                                                 /*reject_rice_codec=*/false,
                                                                 bind_smile_anonset_context);
    if (!immutable_ok) {
        LogPrintf("CShieldedWallet::CreateV2IngressBatch immutable self-check failed txid=%s reject=%s proof_bytes=%u\n",
                  immutable_tx.GetHash().ToString(),
                  immutable_reject,
                  static_cast<unsigned int>(immutable_bundle->proof_payload.size()));
        return std::nullopt;
    }

    wallet::UpdateShieldedHistoricalRingExclusionCache(
        m_recent_ring_exclusions,
        Span<const uint64_t>{shared_ring->positions.data(), shared_ring->positions.size()},
        Span<const size_t>{shared_ring->real_indices.data(), shared_ring->real_indices.size()},
        wallet::GetShieldedHistoricalRingExclusionLimit(ring_size, validation_height));
    return built->tx;
}

std::optional<CMutableTransaction> CShieldedWallet::CreateV2Rebalance(
    const std::vector<shielded::v2::ReserveDelta>& reserve_deltas,
    const std::vector<std::pair<ShieldedAddress, CAmount>>& reserve_outputs,
    const shielded::v2::NettingManifest& netting_manifest,
    CAmount requested_fee,
    CAmount& actual_fee_paid,
    std::string* error)
{
    AssertLockHeld(cs_shielded);
    MaybeRehydrateSpendingKeys();
    actual_fee_paid = 0;

    auto fail = [&](const char* reason) -> std::optional<CMutableTransaction> {
        if (error != nullptr) *error = reason;
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2Rebalance aborted: %s\n", reason);
        return std::nullopt;
    };

    if (!RequireEncryptedShieldedWallet(m_parent_wallet, "CShieldedWallet::CreateV2Rebalance", error)) {
        return std::nullopt;
    }

    if (requested_fee <= 0 || !MoneyRange(requested_fee)) {
        return fail("invalid fee");
    }
    requested_fee = shielded::RoundShieldedFeeToCanonicalBucket(
        requested_fee,
        Params().GetConsensus(),
        NextShieldedBuildValidationHeight(m_parent_wallet.chain()));

    const Span<const shielded::v2::ReserveDelta> delta_span{reserve_deltas.data(), reserve_deltas.size()};
    if (!shielded::v2::ReserveDeltaSetIsCanonical(delta_span)) {
        return fail("reserve deltas are not canonical");
    }
    if (!netting_manifest.IsValid() || netting_manifest.binding_kind != shielded::v2::SettlementBindingKind::NETTING_MANIFEST) {
        return fail("invalid netting manifest");
    }
    if (netting_manifest.domains.size() != reserve_deltas.size()) {
        return fail("netting manifest domain count mismatch");
    }
    for (size_t i = 0; i < reserve_deltas.size(); ++i) {
        if (netting_manifest.domains[i].l2_id != reserve_deltas[i].l2_id ||
            netting_manifest.domains[i].net_reserve_delta != reserve_deltas[i].reserve_delta) {
            return fail("netting manifest domain mismatch");
        }
    }
    if (reserve_outputs.size() > shielded::v2::MAX_BATCH_RESERVE_OUTPUTS) {
        return fail("reserve output count exceeds limit");
    }
    const int32_t validation_height = NextShieldedBuildValidationHeight(m_parent_wallet.chain());
    const CAmount shielded_dust_threshold = GetShieldedDustThresholdForHeight(
        m_parent_wallet.chain().relayDustFee(),
        validation_height);

    std::vector<shielded::v2::OutputDescription> built_outputs;
    built_outputs.reserve(reserve_outputs.size());
    for (size_t i = 0; i < reserve_outputs.size(); ++i) {
        const auto& [addr, amount] = reserve_outputs[i];
        if (amount <= 0 || !MoneyRange(amount)) {
            return fail("invalid reserve output amount");
        }
        if (shielded_dust_threshold > 0 && amount < shielded_dust_threshold) {
            return fail("reserve output amount below dust threshold");
        }

        auto resolved = ResolveV2ShieldedRecipient(m_key_sets,
                                                   m_address_lifecycles,
                                                   addr,
                                                   amount,
                                                   validation_height,
                                                   "CShieldedWallet::CreateV2Rebalance");
        if (!resolved.has_value()) return std::nullopt;

        ShieldedNote note_template;
        note_template.value = amount;
        note_template.recipient_pk_hash = resolved->recipient.recipient_pk_hash;
        if (note_template.value <= 0 || !MoneyRange(note_template.value) || note_template.recipient_pk_hash.IsNull()) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2Rebalance failed: invalid reserve note for %s amount=%lld\n",
                     addr.Encode(),
                     static_cast<long long>(amount));
            return std::nullopt;
        }
        if (shielded_dust_threshold > 0 && note_template.value < shielded_dust_threshold) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2Rebalance failed: reserve output below dust threshold for %s amount=%lld threshold=%lld\n",
                     addr.Encode(),
                     static_cast<long long>(amount),
                     static_cast<long long>(shielded_dust_threshold));
            return std::nullopt;
        }

        const auto bound_note =
            shielded::NoteEncryption::EncryptBoundNote(note_template, resolved->recipient.recipient_kem_pk);
        const ShieldedNote& note = bound_note.note;
        const shielded::EncryptedNote& encrypted_note = bound_note.encrypted_note;
        if (resolved->local_recipient_kem_sk != nullptr &&
            !shielded::NoteEncryption::TryDecrypt(encrypted_note,
                                                  resolved->recipient.recipient_kem_pk,
                                                  *resolved->local_recipient_kem_sk).has_value()) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2Rebalance self-decrypt failed addr=%s\n",
                     addr.Encode());
            return std::nullopt;
        }

        auto payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
            encrypted_note,
            resolved->recipient.recipient_kem_pk,
            shielded::v2::ScanDomain::OPAQUE);
        if (!payload.has_value()) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2Rebalance failed: unable to encode reserve payload for %s\n",
                     addr.Encode());
            return std::nullopt;
        }

        shielded::v2::OutputDescription output;
        output.note_class = shielded::v2::NoteClass::RESERVE;
        auto smile_account = smile2::wallet::BuildCompactPublicAccountFromNote(
            smile2::wallet::SMILE_GLOBAL_SEED,
            note);
        if (!smile_account.has_value()) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2Rebalance failed: unable to build SMILE reserve account for %s\n",
                     addr.Encode());
            return std::nullopt;
        }
        output.note_commitment = smile2::ComputeCompactPublicAccountHash(*smile_account);
        output.value_commitment =
            shielded::v2::ComputeV2RebalanceOutputValueCommitment(static_cast<uint32_t>(i), output.note_commitment);
        output.smile_account = std::move(*smile_account);
        output.encrypted_note = std::move(*payload);
        if (!output.IsValid()) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2Rebalance failed: invalid reserve output for %s\n",
                     addr.Encode());
            return std::nullopt;
        }

        built_outputs.push_back(std::move(output));
    }

    shielded::v2::V2RebalanceBuildInput build_input;
    build_input.reserve_deltas = reserve_deltas;
    build_input.reserve_outputs = std::move(built_outputs);
    build_input.netting_manifest = netting_manifest;

    std::string reject_reason;
    auto built = shielded::v2::BuildDeterministicV2RebalanceBundle(build_input,
                                                                   reject_reason,
                                                                   &Params().GetConsensus(),
                                                                   validation_height);
    if (!built.has_value()) {
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateV2Rebalance failed: %s\n", reject_reason);
        return std::nullopt;
    }

    std::vector<TransparentWalletCoin> available;
    {
        LOCK(m_parent_wallet.cs_wallet);
        available = CollectSpendableTransparentWalletCoins(m_parent_wallet);
    }
    if (available.empty()) {
        return fail("no spendable transparent funds");
    }

    std::optional<CTxDestination> change_dest;
    CScript change_script;
    std::vector<TransparentWalletCoin> selected;
    CAmount total_input{0};
    std::optional<CAmount> change_value;
    for (const auto& coin : available) {
        selected.push_back(coin);
        const auto next_total = CheckedAdd(total_input, coin.value);
        if (!next_total || !MoneyRange(*next_total)) {
            return fail("selected transparent input total overflow");
        }
        total_input = *next_total;
        if (total_input < requested_fee) {
            continue;
        }

        const CAmount proposed_change = total_input - requested_fee;
        if (proposed_change == 0) {
            change_value.reset();
            break;
        }

        if (!change_dest.has_value()) {
            auto new_change_dest = m_parent_wallet.GetNewChangeDestination(OutputType::P2MR);
            if (!new_change_dest) {
                LogDebug(BCLog::WALLETDB,
                         "CShieldedWallet::CreateV2Rebalance failed: unable to derive P2MR change destination\n");
                return std::nullopt;
            }
            change_dest = *new_change_dest;
            change_script = GetScriptForDestination(*change_dest);
        }

        if (!::IsDust(CTxOut{proposed_change, change_script}, m_parent_wallet.chain().relayDustFee())) {
            change_value = proposed_change;
            break;
        }
    }

    if (total_input < requested_fee) {
        return fail("transparent funds below requested fee");
    }

    actual_fee_paid = total_input - (change_value.has_value() ? *change_value : 0);
    if (actual_fee_paid <= 0 || !MoneyRange(actual_fee_paid)) {
        return fail("invalid effective fee");
    }

    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION;
    mtx.nLockTime = FastRandomContext{}.rand32();
    mtx.shielded_bundle.v2_bundle = std::move(built->bundle);

    std::map<COutPoint, Coin> signing_coins;
    {
        LOCK(m_parent_wallet.cs_wallet);
        AssertLockHeld(m_parent_wallet.cs_wallet);
        for (const auto& coin : selected) {
            const CWalletTx* wtx = m_parent_wallet.GetWalletTx(coin.outpoint.hash);
            if (!wtx || coin.outpoint.n >= wtx->tx->vout.size()) {
                LogDebug(BCLog::WALLETDB,
                         "CShieldedWallet::CreateV2Rebalance failed: missing wallet tx for outpoint %s:%u\n",
                         coin.outpoint.hash.GetHex(),
                         coin.outpoint.n);
                return std::nullopt;
            }
            mtx.vin.emplace_back(coin.outpoint);
            const int prev_height = wtx->state<TxStateConfirmed>() ? wtx->state<TxStateConfirmed>()->confirmed_block_height : 0;
            signing_coins.emplace(coin.outpoint, Coin(wtx->tx->vout[coin.outpoint.n], prev_height, wtx->IsCoinBase()));
        }
    }

    if (change_value.has_value()) {
        mtx.vout.emplace_back(*change_value, change_script);
    }

    {
        LOCK(m_parent_wallet.cs_wallet);
        std::map<int, bilingual_str> input_errors;
        if (!m_parent_wallet.SignTransaction(mtx, signing_coins, SIGHASH_DEFAULT, input_errors)) {
            std::string err_summary;
            int logged_errors{0};
            for (const auto& [input_index, err] : input_errors) {
                if (!err_summary.empty()) err_summary += "; ";
                err_summary += strprintf("in%d=%s", input_index, err.original);
                if (++logged_errors >= 3) break;
            }
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateV2Rebalance failed: SignTransaction returned false for %u transparent inputs (errors=%u sample=\"%s\")\n",
                     static_cast<unsigned int>(mtx.vin.size()),
                     static_cast<unsigned int>(input_errors.size()),
                     err_summary);
            return std::nullopt;
        }
    }

    return mtx;
}

std::optional<CMutableTransaction> CShieldedWallet::CreateTransparentToShieldedSend(
    const std::vector<std::pair<ShieldedAddress, CAmount>>& shielded_recipients,
    CAmount fee,
    std::string* error)
{
    AssertLockHeld(cs_shielded);
    MaybeRehydrateSpendingKeys();

    auto fail = [&](const char* reason) -> std::optional<CMutableTransaction> {
        if (error != nullptr) *error = reason;
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateTransparentToShieldedSend aborted: %s\n", reason);
        return std::nullopt;
    };

    if (!RequireEncryptedShieldedWallet(m_parent_wallet,
                                        "CShieldedWallet::CreateTransparentToShieldedSend",
                                        error)) {
        return std::nullopt;
    }

    if (shielded_recipients.empty()) return fail("no shielded recipients");
    if (fee < 0 || !MoneyRange(fee)) return fail("invalid fee");
    const int32_t validation_height = NextShieldedBuildValidationHeight(m_parent_wallet.chain());
    if (!AllowTransparentShieldingInDirectSendAtHeight(validation_height)) {
        return fail("post-fork direct transparent shielding is disabled; use bridge ingress");
    }
    fee = shielded::RoundShieldedFeeToCanonicalBucket(
        fee,
        Params().GetConsensus(),
        validation_height);

    CAmount total_shielded_out{0};
    for (const auto& [_, amount] : shielded_recipients) {
        if (amount <= 0 || !MoneyRange(amount)) return fail("invalid shielded recipient amount");
        if (!IsShieldedSmileValueCompatible(amount)) return fail("shielded recipient amount exceeds SMILE note value limit");
        const auto next = CheckedAdd(total_shielded_out, amount);
        if (!next || !MoneyRange(*next)) return fail("shielded recipient total overflow");
        total_shielded_out = *next;
    }

    const auto total_needed = CheckedAdd(total_shielded_out, fee);
    if (!total_needed || !MoneyRange(*total_needed)) return fail("total needed overflow");

    std::vector<TransparentWalletCoin> available;
    {
        LOCK(m_parent_wallet.cs_wallet);
        available = CollectSpendableTransparentWalletCoins(m_parent_wallet);
    }
    if (available.empty()) return fail("no spendable transparent funds");

    std::vector<TransparentWalletCoin> selected;
    CAmount total_input{0};
    for (const auto& coin : available) {
        selected.push_back(coin);
        const auto next = CheckedAdd(total_input, coin.value);
        if (!next || !MoneyRange(*next)) return fail("selected transparent input total overflow");
        total_input = *next;
        if (total_input >= *total_needed) break;
    }
    if (total_input < *total_needed) return fail("transparent funds below total needed");

    const CAmount change = total_input - *total_needed;
    const CAmount shielded_dust_threshold = GetShieldedDustThresholdForHeight(
        m_parent_wallet.chain().relayDustFee(),
        validation_height);
    const CAmount minimum_change_reserve = GetShieldedMinimumChangeReserveForHeight(
        m_parent_wallet.chain().relayDustFee(),
        validation_height);
    const uint256 build_privacy_nonce = GetRandHash();
    for (const auto& [_, amount] : shielded_recipients) {
        if (shielded_dust_threshold > 0 && amount < shielded_dust_threshold) {
            return fail("shielded recipient amount below dust threshold");
        }
    }
    if (shielded_dust_threshold > 0 && change > 0 && change < minimum_change_reserve) {
        return fail("shielded change would fall below the post-fork dust threshold");
    }
    const size_t output_count = shielded_recipients.size() + (change > 0 ? 1 : 0);
    if (output_count > MAX_SHIELDED_OUTPUTS_PER_TX) {
        return fail("shielded output count exceeds per-transaction limit");
    }

    std::vector<shielded::v2::V2SendOutputInput> output_inputs;
    output_inputs.reserve(output_count);

    auto add_shielded_output = [&](const ShieldedAddress& addr, CAmount amount) EXCLUSIVE_LOCKS_REQUIRED(cs_shielded) -> bool {
        AssertLockHeld(cs_shielded);
        auto resolved = ResolveV2ShieldedRecipient(m_key_sets,
                                                   m_address_lifecycles,
                                                   addr,
                                                   amount,
                                                   validation_height,
                                                   "CShieldedWallet::CreateTransparentToShieldedSend");
        if (!resolved.has_value()) {
            if (error != nullptr) *error = "destination resolution failed";
            return false;
        }

        ShieldedNote note;
        note.value = amount;
        note.recipient_pk_hash = resolved->recipient.recipient_pk_hash;
        if (note.value <= 0 || !MoneyRange(note.value) || note.recipient_pk_hash.IsNull()) {
            LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateTransparentToShieldedSend failed: invalid output note for %s amount=%lld\n",
                     addr.Encode(),
                     static_cast<long long>(amount));
            if (error != nullptr) *error = "invalid output note";
            return false;
        }
        if (!IsShieldedSmileValueCompatible(note.value)) {
            if (error != nullptr) *error = "shielded output exceeds SMILE note value limit";
            return false;
        }
        if (shielded_dust_threshold > 0 && note.value < shielded_dust_threshold) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateTransparentToShieldedSend failed: output below dust threshold for %s amount=%lld threshold=%lld\n",
                     addr.Encode(),
                     static_cast<long long>(amount),
                     static_cast<long long>(shielded_dust_threshold));
            if (error != nullptr) *error = "shielded output below dust threshold";
            return false;
        }

        const auto bound_note = shielded::NoteEncryption::EncryptBoundNote(note, resolved->recipient.recipient_kem_pk);
        note = bound_note.note;
        const shielded::EncryptedNote encrypted_note = bound_note.encrypted_note;
        if (resolved->local_recipient_kem_sk != nullptr &&
            !shielded::NoteEncryption::TryDecrypt(encrypted_note,
                                                  resolved->recipient.recipient_kem_pk,
                                                  *resolved->local_recipient_kem_sk).has_value()) {
            LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateTransparentToShieldedSend self-decrypt failed addr=%s\n",
                     addr.Encode());
            if (error != nullptr) *error = "output self-decrypt failed";
            return false;
        }

        auto payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
            encrypted_note,
            resolved->recipient.recipient_kem_pk,
            shielded::v2::ScanDomain::OPAQUE);
        if (!payload.has_value()) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateTransparentToShieldedSend failed: unable to encode output payload for %s\n",
                     addr.Encode());
            if (error != nullptr) *error = "unable to encode output payload";
            return false;
        }

        shielded::v2::V2SendOutputInput output_input;
        output_input.note_class = shielded::v2::NoteClass::USER;
        output_input.note = std::move(note);
        output_input.encrypted_note = std::move(*payload);
        if (!output_input.IsValid()) {
            LogDebug(BCLog::WALLETDB,
                     "CShieldedWallet::CreateTransparentToShieldedSend failed: invalid output payload for %s\n",
                     addr.Encode());
            if (error != nullptr) *error = "invalid output payload";
            return false;
        }
        output_inputs.push_back(std::move(output_input));
        return true;
    };

    std::vector<std::pair<ShieldedAddress, CAmount>> candidate_outputs;
    candidate_outputs.reserve(output_count);
    for (const auto& recipient : shielded_recipients) {
        candidate_outputs.push_back(recipient);
    }
    if (change > 0) {
        candidate_outputs.emplace_back(GenerateNewAddress(), change);
    }
    for (const size_t source_index : ComputeShieldedOutputOrder(
             shielded_recipients.size(),
             change > 0,
             build_privacy_nonce,
             validation_height)) {
        if (source_index >= candidate_outputs.size()) {
            return fail("invalid shielded output ordering");
        }
        if (!add_shielded_output(candidate_outputs[source_index].first,
                                 candidate_outputs[source_index].second)) {
            return std::nullopt;
        }
    }

    CMutableTransaction mtx;
    mtx.version = CTransaction::CURRENT_VERSION;
    mtx.nLockTime = FastRandomContext{}.rand32();

    std::map<COutPoint, Coin> signing_coins;
    {
        LOCK(m_parent_wallet.cs_wallet);
        AssertLockHeld(m_parent_wallet.cs_wallet);
        for (const auto& coin : selected) {
            const CWalletTx* wtx = m_parent_wallet.GetWalletTx(coin.outpoint.hash);
            if (!wtx || coin.outpoint.n >= wtx->tx->vout.size()) {
                LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateTransparentToShieldedSend failed: missing wallet tx for outpoint %s:%u\n",
                         coin.outpoint.hash.GetHex(),
                         coin.outpoint.n);
                return fail("missing wallet tx for selected transparent input");
            }
            mtx.vin.emplace_back(coin.outpoint);
            const int prev_height = wtx->state<TxStateConfirmed>() ? wtx->state<TxStateConfirmed>()->confirmed_block_height : 0;
            signing_coins.emplace(coin.outpoint, Coin(wtx->tx->vout[coin.outpoint.n], prev_height, wtx->IsCoinBase()));
        }
    }

    std::string reject_reason;
    const auto& consensus = Params().GetConsensus();
    auto built = shielded::v2::BuildV2SendTransaction(
        mtx,
        uint256{},
        {},
        output_inputs,
        fee,
        {},
        reject_reason,
        {},
        &consensus,
        validation_height);
    if (!built.has_value()) {
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateTransparentToShieldedSend failed: %s\n", reject_reason);
        if (error != nullptr && !reject_reason.empty()) *error = reject_reason;
        return std::nullopt;
    }
    mtx = std::move(built->tx);

    {
        LOCK(m_parent_wallet.cs_wallet);
        std::map<int, bilingual_str> input_errors;
        if (!m_parent_wallet.SignTransaction(mtx, signing_coins, SIGHASH_DEFAULT, input_errors)) {
            std::string err_summary;
            int logged_errors{0};
            for (const auto& [input_index, err] : input_errors) {
                if (!err_summary.empty()) err_summary += "; ";
                err_summary += strprintf("in%d=%s", input_index, err.original);
                if (++logged_errors >= 3) break;
            }
            LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateTransparentToShieldedSend failed: SignTransaction returned false for %u transparent inputs (errors=%u sample=\"%s\")\n",
                     static_cast<unsigned int>(mtx.vin.size()),
                     static_cast<unsigned int>(input_errors.size()),
                     err_summary);
            return fail("failed to sign transparent funding inputs");
        }
    }

    return mtx;
}

std::optional<CMutableTransaction> CShieldedWallet::CreateShieldedSpend(
    const std::vector<std::pair<ShieldedAddress, CAmount>>& shielded_recipients,
    const std::vector<std::pair<CTxDestination, CAmount>>& transparent_recipients,
    CAmount fee,
    bool allow_transparent_fallback,
    std::string* error,
    const std::vector<ShieldedCoin>* selected_override)
{
    AssertLockHeld(cs_shielded);
    MaybeRehydrateSpendingKeys();
    // Ensure note visibility is up to date before selecting inputs. Functional
    // flows can invoke send RPCs immediately after mining a shielding tx.
    CatchUpToChainTip();
    auto fail = [&](const char* reason) -> std::optional<CMutableTransaction> {
        if (error != nullptr) *error = reason;
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::CreateShieldedSpend aborted: %s\n", reason);
        return std::nullopt;
    };

    if (!RequireEncryptedShieldedWallet(m_parent_wallet, "CShieldedWallet::CreateShieldedSpend", error)) {
        return std::nullopt;
    }

    if (fee < 0 || !MoneyRange(fee)) return fail("invalid fee");

    CAmount total_shielded_out{0};
    for (const auto& [_, amount] : shielded_recipients) {
        if (amount <= 0 || !MoneyRange(amount)) return fail("invalid shielded recipient amount");
        // R7-107: Use checked arithmetic for running total.
        const auto next = CheckedAdd(total_shielded_out, amount);
        if (!next || !MoneyRange(*next)) return fail("shielded recipient total overflow");
        total_shielded_out = *next;
    }
    CAmount total_transparent_out{0};
    for (const auto& [_, amount] : transparent_recipients) {
        if (amount <= 0 || !MoneyRange(amount)) return fail("invalid transparent recipient amount");
        const auto next = CheckedAdd(total_transparent_out, amount);
        if (!next || !MoneyRange(*next)) return fail("transparent recipient total overflow");
        total_transparent_out = *next;
    }
    if (shielded_recipients.empty() && transparent_recipients.empty()) return fail("no recipients");
    if (shielded_recipients.size() > MAX_SHIELDED_OUTPUTS_PER_TX) {
        return fail("shielded recipient count exceeds per-transaction limit");
    }
    if (selected_override != nullptr) {
        return CreateV2Send(shielded_recipients, transparent_recipients, fee, selected_override, error);
    }
    if (transparent_recipients.empty()) {
        const auto total_needed = CheckedAdd(total_shielded_out, fee);
        if (!total_needed || !MoneyRange(*total_needed)) return fail("recipient total overflow");

        CAmount spendable_shielded{0};
        for (const auto& coin : GetSpendableNotes(/*min_depth=*/1)) {
            const auto next = CheckedAdd(spendable_shielded, coin.note.value);
            if (!next || !MoneyRange(*next)) return fail("spendable shielded total overflow");
            spendable_shielded = *next;
        }
        if (spendable_shielded >= *total_needed) {
            return CreateV2Send(shielded_recipients, /*transparent_recipients=*/{}, fee, error);
        }
        if (!allow_transparent_fallback) {
            return fail("insufficient shielded funds for v2 send");
        }
        return CreateTransparentToShieldedSend(shielded_recipients, fee, error);
    }

    return CreateV2Send(shielded_recipients, transparent_recipients, fee, error);
}

std::optional<CMutableTransaction> CShieldedWallet::ShieldFunds(const std::vector<COutPoint>& utxos,
                                                                CAmount fee,
                                                                std::optional<ShieldedAddress> dest,
                                                                CAmount requested_amount,
                                                                std::string* error)
{
    AssertLockHeld(cs_shielded);
    MaybeRehydrateSpendingKeys();
    auto fail = [&](const std::string& reason) -> std::optional<CMutableTransaction> {
        if (error != nullptr) *error = reason;
        LogPrintf("CShieldedWallet::ShieldFunds failed: %s\n", reason);
        return std::nullopt;
    };
    if (!RequireEncryptedShieldedWallet(m_parent_wallet, "CShieldedWallet::ShieldFunds", error)) {
        return std::nullopt;
    }
    const int32_t validation_height = NextShieldedBuildValidationHeight(m_parent_wallet.chain());
    if (utxos.empty()) {
        return fail("no transparent inputs provided");
    }
    if (fee < 0 || !MoneyRange(fee)) {
        return fail(strprintf("invalid fee=%s", FormatMoney(fee)));
    }
    fee = shielded::RoundShieldedFeeToCanonicalBucket(
        fee,
        Params().GetConsensus(),
        validation_height);

    ShieldedAddress shield_dest;
    if (dest.has_value()) {
        shield_dest = *dest;
    } else {
        auto preferred = GetPreferredReceiveAddress();
        shield_dest = preferred.has_value() ? *preferred : GenerateNewAddress();
    }

    if (m_key_sets.find(shield_dest) == m_key_sets.end() && !shield_dest.HasKEMPublicKey()) {
        return fail(strprintf("destination keyset missing and address has no embedded KEM public key for %s",
                              shield_dest.Encode()));
    }

    CAmount total_in{0};
    std::map<COutPoint, Coin> signing_coins;
    CMutableTransaction tx_template;
    tx_template.version = CTransaction::CURRENT_VERSION;
    tx_template.nLockTime = FastRandomContext{}.rand32();
    {
        LOCK(m_parent_wallet.cs_wallet);
        std::string compatibility_error;
        if (!ValidatePostForkCoinbaseShieldingCompatibility(
                m_parent_wallet,
                Span<const COutPoint>{utxos.data(), utxos.size()},
                validation_height,
                compatibility_error)) {
            return fail(compatibility_error);
        }
        for (const auto& outpoint : utxos) {
            const CWalletTx* wtx = m_parent_wallet.GetWalletTx(outpoint.hash);
            if (!wtx || outpoint.n >= wtx->tx->vout.size()) {
                return fail(strprintf("missing wallet tx for outpoint %s:%u",
                                      outpoint.hash.GetHex(), outpoint.n));
            }
            // R5-505: Checked accumulation to prevent overflow before MoneyRange check.
            const auto next = CheckedAdd(total_in, wtx->tx->vout[outpoint.n].nValue);
            if (!next || !MoneyRange(*next)) {
                return fail(strprintf("input accumulation overflow for outpoint %s:%u",
                                      outpoint.hash.GetHex(), outpoint.n));
            }
            total_in = *next;
            tx_template.vin.emplace_back(outpoint);
            const int prev_height = wtx->state<TxStateConfirmed>() ? wtx->state<TxStateConfirmed>()->confirmed_block_height : 0;
            signing_coins.emplace(outpoint, Coin(wtx->tx->vout[outpoint.n], prev_height, wtx->IsCoinBase()));
        }
    }
    const CAmount max_shieldable = total_in - fee;
    if (max_shieldable <= 0) {
        return fail(strprintf("shield amount non-positive total_in=%s fee=%s",
                              FormatMoney(total_in),
                              FormatMoney(fee)));
    }
    const bool use_shielded_change = UseShieldedPrivacyRedesignAtHeight(validation_height);
    const CAmount shielded_dust_threshold = GetShieldedDustThresholdForHeight(
        m_parent_wallet.chain().relayDustFee(),
        validation_height);
    const uint256 build_privacy_nonce = GetRandHash();

    // When requested_amount is positive, shield only that amount and return
    // the rest as change. After the privacy redesign activates, change is
    // routed back into a fresh shielded note instead of a transparent output.
    const CAmount shield_amount = (requested_amount > 0) ? std::min(requested_amount, max_shieldable) : max_shieldable;
    const CAmount change = max_shieldable - shield_amount;

    CAmount effective_primary_amount = shield_amount;
    std::optional<CAmount> shielded_change_amount;
    if (change > 0) {
        if (use_shielded_change) {
            if (shielded_dust_threshold > 0 && change < shielded_dust_threshold) {
                effective_primary_amount = max_shieldable;
            } else {
                shielded_change_amount = change;
            }
        } else {
            LOCK(m_parent_wallet.cs_wallet);
            auto change_dest = m_parent_wallet.GetNewChangeDestination(OutputType::P2MR);
            if (change_dest) {
                tx_template.vout.emplace_back(change, GetScriptForDestination(*change_dest));
            } else {
                LogPrintf("CShieldedWallet::ShieldFunds: unable to generate change address (%s), shielding full amount\n",
                          util::ErrorString(change_dest).original);
                effective_primary_amount = max_shieldable;
            }
        }
    }

    std::vector<std::pair<ShieldedAddress, CAmount>> candidate_outputs;
    candidate_outputs.emplace_back(shield_dest, effective_primary_amount);
    if (shielded_change_amount.has_value()) {
        candidate_outputs.emplace_back(GenerateNewAddress(), *shielded_change_amount);
    }

    std::vector<shielded::v2::V2SendOutputInput> output_inputs;
    output_inputs.reserve(candidate_outputs.size());
    for (const size_t source_index : ComputeShieldedOutputOrder(
             /*recipient_count=*/1,
             shielded_change_amount.has_value(),
             build_privacy_nonce,
             validation_height)) {
        if (source_index >= candidate_outputs.size()) {
            return fail("invalid shielded output ordering");
        }
        const auto& [address, amount] = candidate_outputs[source_index];
        auto resolved = ResolveV2ShieldedRecipient(m_key_sets,
                                                   m_address_lifecycles,
                                                   address,
                                                   amount,
                                                   validation_height,
                                                   "CShieldedWallet::ShieldFunds");
        if (!resolved.has_value()) {
            return fail(strprintf("generated note is invalid for destination %s", address.Encode()));
        }

        ShieldedNote note;
        note.value = amount;
        note.recipient_pk_hash = resolved->recipient.recipient_pk_hash;
        if (note.value <= 0 || !MoneyRange(note.value) || note.recipient_pk_hash.IsNull()) {
            return fail(strprintf("generated note is invalid for destination %s", address.Encode()));
        }
        if (!IsShieldedSmileValueCompatible(note.value)) {
            return fail(strprintf("shielded output exceeds SMILE note value limit for %s", address.Encode()));
        }
        if (shielded_dust_threshold > 0 && note.value < shielded_dust_threshold) {
            return fail(strprintf("shielded output below dust threshold for %s", address.Encode()));
        }

        auto bound_note = shielded::NoteEncryption::EncryptBoundNote(note, resolved->recipient.recipient_kem_pk);
        note = bound_note.note;
        shielded::EncryptedNote encrypted_note = bound_note.encrypted_note;
        if (resolved->local_recipient_kem_sk != nullptr &&
            !shielded::NoteEncryption::TryDecrypt(encrypted_note,
                                                  resolved->recipient.recipient_kem_pk,
                                                  *resolved->local_recipient_kem_sk).has_value()) {
            return fail(strprintf("self-decrypt failed for destination %s", address.Encode()));
        }

        auto payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
            encrypted_note,
            resolved->recipient.recipient_kem_pk,
            shielded::v2::ScanDomain::OPAQUE);
        if (!payload.has_value()) {
            return fail(strprintf("unable to encode v2 shielded output for %s", address.Encode()));
        }

        shielded::v2::V2SendOutputInput output_input;
        output_input.note_class = shielded::v2::NoteClass::USER;
        output_input.note = std::move(note);
        output_input.encrypted_note = std::move(*payload);
        if (!output_input.IsValid()) {
            return fail(strprintf("invalid v2 shielded output for %s", address.Encode()));
        }
        output_inputs.push_back(std::move(output_input));
    }

    std::string reject_reason;
    const auto& consensus = Params().GetConsensus();
    auto built = shielded::v2::BuildV2SendTransaction(
        tx_template,
        uint256{},
        {},
        output_inputs,
        fee,
        {},
        reject_reason,
        {},
        &consensus,
        validation_height);
    if (!built.has_value()) {
        return fail(reject_reason.empty() ? "v2 shielded deposit builder failed" : reject_reason);
    }
    CMutableTransaction mtx = std::move(built->tx);

    {
        LOCK(m_parent_wallet.cs_wallet);
        std::map<int, bilingual_str> input_errors;
        if (!m_parent_wallet.SignTransaction(mtx, signing_coins, SIGHASH_DEFAULT, input_errors)) {
            std::string err_summary;
            int logged_errors{0};
            for (const auto& [input_index, err] : input_errors) {
                if (!err_summary.empty()) err_summary += "; ";
                err_summary += strprintf("in%d=%s", input_index, err.original);
                if (++logged_errors >= 3) break;
            }
            return fail(strprintf("SignTransaction returned false for %u transparent inputs (errors=%u sample=\"%s\")",
                                  mtx.vin.size(),
                                  input_errors.size(),
                                  err_summary));
        }
    }
    return mtx;
}

std::optional<PartiallySignedTransaction> CShieldedWallet::ShieldFundsPSBT(
    const std::vector<COutPoint>& utxos,
    CAmount fee,
    std::optional<ShieldedAddress> dest,
    CAmount requested_amount,
    std::string* error)
{
    AssertLockHeld(cs_shielded);
    MaybeRehydrateSpendingKeys();
    if (utxos.empty()) {
        if (error != nullptr) *error = "no transparent inputs provided";
        LogPrintf("CShieldedWallet::ShieldFundsPSBT failed: no transparent inputs provided\n");
        return std::nullopt;
    }
    if (fee < 0 || !MoneyRange(fee)) {
        if (error != nullptr) *error = "invalid fee";
        LogPrintf("CShieldedWallet::ShieldFundsPSBT failed: invalid fee=%s\n", FormatMoney(fee));
        return std::nullopt;
    }
    const int32_t validation_height = NextShieldedBuildValidationHeight(m_parent_wallet.chain());
    fee = shielded::RoundShieldedFeeToCanonicalBucket(
        fee,
        Params().GetConsensus(),
        validation_height);

    ShieldedAddress shield_dest;
    if (dest.has_value()) {
        shield_dest = *dest;
    } else {
        if (!RequireEncryptedShieldedWallet(m_parent_wallet, "CShieldedWallet::ShieldFundsPSBT", error)) {
            return std::nullopt;
        }
        auto preferred = GetPreferredReceiveAddress();
        shield_dest = preferred.has_value() ? *preferred : GenerateNewAddress();
    }

    if (m_key_sets.find(shield_dest) == m_key_sets.end() && !shield_dest.HasKEMPublicKey()) {
        if (error != nullptr) *error = "destination keyset missing and address has no embedded KEM public key";
        LogPrintf("CShieldedWallet::ShieldFundsPSBT failed: destination keyset missing and address has no embedded KEM public key for %s\n", shield_dest.Encode());
        return std::nullopt;
    }

    CAmount total_in{0};
    std::map<COutPoint, Coin> signing_coins;
    CMutableTransaction tx_template;
    tx_template.version = CTransaction::CURRENT_VERSION;
    tx_template.nLockTime = FastRandomContext{}.rand32();
    {
        LOCK(m_parent_wallet.cs_wallet);
        std::string compatibility_error;
        if (!ValidatePostForkCoinbaseShieldingCompatibility(
                m_parent_wallet,
                Span<const COutPoint>{utxos.data(), utxos.size()},
                validation_height,
                compatibility_error)) {
            if (error != nullptr) *error = compatibility_error;
            LogPrintf("CShieldedWallet::ShieldFundsPSBT failed: %s\n", compatibility_error);
            return std::nullopt;
        }
        for (const auto& outpoint : utxos) {
            const CWalletTx* wtx = m_parent_wallet.GetWalletTx(outpoint.hash);
            if (!wtx || outpoint.n >= wtx->tx->vout.size()) {
                if (error != nullptr) *error = "missing wallet tx for selected transparent input";
                LogPrintf("CShieldedWallet::ShieldFundsPSBT failed: missing wallet tx for outpoint %s:%u\n",
                          outpoint.hash.GetHex(), outpoint.n);
                return std::nullopt;
            }
            const auto next = CheckedAdd(total_in, wtx->tx->vout[outpoint.n].nValue);
            if (!next || !MoneyRange(*next)) {
                if (error != nullptr) *error = "selected transparent input total overflow";
                LogPrintf("CShieldedWallet::ShieldFundsPSBT failed: input accumulation overflow for outpoint %s:%u\n",
                          outpoint.hash.GetHex(), outpoint.n);
                return std::nullopt;
            }
            total_in = *next;
            tx_template.vin.emplace_back(outpoint);
            const int prev_height = wtx->state<TxStateConfirmed>() ? wtx->state<TxStateConfirmed>()->confirmed_block_height : 0;
            signing_coins.emplace(outpoint, Coin(wtx->tx->vout[outpoint.n], prev_height, wtx->IsCoinBase()));
        }
    }
    const CAmount max_shieldable = total_in - fee;
    if (max_shieldable <= 0) {
        if (error != nullptr) *error = "shield amount is non-positive after fee";
        LogPrintf("CShieldedWallet::ShieldFundsPSBT failed: shield amount non-positive total_in=%s fee=%s\n",
                  FormatMoney(total_in), FormatMoney(fee));
        return std::nullopt;
    }
    const bool use_shielded_change = UseShieldedPrivacyRedesignAtHeight(validation_height);
    const CAmount shielded_dust_threshold = GetShieldedDustThresholdForHeight(
        m_parent_wallet.chain().relayDustFee(),
        validation_height);
    const uint256 build_privacy_nonce = GetRandHash();
    const CAmount shield_amount = (requested_amount > 0) ? std::min(requested_amount, max_shieldable) : max_shieldable;
    const CAmount change = max_shieldable - shield_amount;

    CAmount effective_primary_amount = shield_amount;
    std::optional<CAmount> shielded_change_amount;
    if (change > 0) {
        if (use_shielded_change) {
            if (!RequireEncryptedShieldedWallet(m_parent_wallet,
                                                "CShieldedWallet::ShieldFundsPSBT",
                                                error)) {
                return std::nullopt;
            }
            if (shielded_dust_threshold > 0 && change < shielded_dust_threshold) {
                effective_primary_amount = max_shieldable;
            } else {
                shielded_change_amount = change;
            }
        } else {
            LOCK(m_parent_wallet.cs_wallet);
            auto change_dest = m_parent_wallet.GetNewChangeDestination(OutputType::P2MR);
            if (change_dest) {
                tx_template.vout.emplace_back(change, GetScriptForDestination(*change_dest));
            } else {
                LogPrintf("CShieldedWallet::ShieldFundsPSBT: unable to generate change address (%s), shielding full amount\n",
                          util::ErrorString(change_dest).original);
                effective_primary_amount = max_shieldable;
            }
        }
    }

    std::vector<std::pair<ShieldedAddress, CAmount>> candidate_outputs;
    candidate_outputs.emplace_back(shield_dest, effective_primary_amount);
    if (shielded_change_amount.has_value()) {
        candidate_outputs.emplace_back(GenerateNewAddress(), *shielded_change_amount);
    }

    std::vector<shielded::v2::V2SendOutputInput> output_inputs;
    output_inputs.reserve(candidate_outputs.size());
    for (const size_t source_index : ComputeShieldedOutputOrder(
             /*recipient_count=*/1,
             shielded_change_amount.has_value(),
             build_privacy_nonce,
             validation_height)) {
        if (source_index >= candidate_outputs.size()) {
            if (error != nullptr) *error = "invalid shielded output ordering";
            return std::nullopt;
        }
        const auto& [address, amount] = candidate_outputs[source_index];
        auto resolved = ResolveV2ShieldedRecipient(m_key_sets,
                                                   m_address_lifecycles,
                                                   address,
                                                   amount,
                                                   validation_height,
                                                   "CShieldedWallet::ShieldFundsPSBT");
        if (!resolved.has_value()) {
            if (error != nullptr) {
                *error = source_index == 0 ? "generated note is invalid"
                                           : "invalid shielded change output";
            }
            return std::nullopt;
        }

        ShieldedNote note;
        note.value = amount;
        note.recipient_pk_hash = resolved->recipient.recipient_pk_hash;
        if (note.value <= 0 || !MoneyRange(note.value) || note.recipient_pk_hash.IsNull()) {
            if (error != nullptr) {
                *error = source_index == 0 ? "generated note is invalid"
                                           : "invalid shielded change output";
            }
            return std::nullopt;
        }
        if (!IsShieldedSmileValueCompatible(note.value)) {
            if (error != nullptr) *error = "shielded output exceeds SMILE note value limit";
            return std::nullopt;
        }
        if (shielded_dust_threshold > 0 && note.value < shielded_dust_threshold) {
            if (error != nullptr) *error = "shielded output below dust threshold";
            return std::nullopt;
        }

        auto bound_note = shielded::NoteEncryption::EncryptBoundNote(note, resolved->recipient.recipient_kem_pk);
        note = bound_note.note;
        shielded::EncryptedNote encrypted_note = bound_note.encrypted_note;
        if (resolved->local_recipient_kem_sk != nullptr &&
            !shielded::NoteEncryption::TryDecrypt(encrypted_note,
                                                  resolved->recipient.recipient_kem_pk,
                                                  *resolved->local_recipient_kem_sk).has_value()) {
            if (error != nullptr) *error = "output self-decrypt failed";
            return std::nullopt;
        }

        auto payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
            encrypted_note,
            resolved->recipient.recipient_kem_pk,
            shielded::v2::ScanDomain::OPAQUE);
        if (!payload.has_value()) {
            if (error != nullptr) *error = "unable to encode v2 shielded output";
            return std::nullopt;
        }

        shielded::v2::V2SendOutputInput output_input;
        output_input.note_class = shielded::v2::NoteClass::USER;
        output_input.note = std::move(note);
        output_input.encrypted_note = std::move(*payload);
        if (!output_input.IsValid()) {
            if (error != nullptr) {
                *error = source_index == 0 ? "generated note is invalid"
                                           : "invalid shielded change output";
            }
            return std::nullopt;
        }
        output_inputs.push_back(std::move(output_input));
    }

    std::string reject_reason;
    const auto& consensus = Params().GetConsensus();
    auto built = shielded::v2::BuildV2SendTransaction(
        tx_template,
        uint256{},
        {},
        output_inputs,
        fee,
        {},
        reject_reason,
        {},
        &consensus,
        validation_height);
    if (!built.has_value()) {
        LogPrintf("CShieldedWallet::ShieldFundsPSBT failed: %s\n", reject_reason);
        return std::nullopt;
    }
    CMutableTransaction mtx = std::move(built->tx);

    // Instead of signing, construct a PSBT with witness UTXO data for each input.
    PartiallySignedTransaction psbtx(mtx);
    for (size_t i = 0; i < mtx.vin.size(); ++i) {
        const auto& outpoint = mtx.vin[i].prevout;
        const auto coin_it = signing_coins.find(outpoint);
        if (coin_it != signing_coins.end()) {
            psbtx.inputs[i].witness_utxo = coin_it->second.out;
        }
    }
    return psbtx;
}

std::optional<CMutableTransaction> CShieldedWallet::UnshieldFunds(CAmount amount,
                                                                   const CTxDestination& destination,
                                                                   CAmount fee)
{
    AssertLockHeld(cs_shielded);
    return CreateShieldedSpend(/*shielded_recipients=*/{},
                               /*transparent_recipients=*/{{destination, amount}},
                               fee);
}

std::optional<CMutableTransaction> CShieldedWallet::MergeNotes(size_t max_notes, CAmount fee, std::string* error)
{
    AssertLockHeld(cs_shielded);
    MaybeRehydrateSpendingKeys();
    if (!RequireEncryptedShieldedWallet(m_parent_wallet, "CShieldedWallet::MergeNotes", error)) {
        return std::nullopt;
    }

    auto spendable = GetSpendableNotes(/*min_depth=*/1);
    if (spendable.size() <= 1) {
        if (error != nullptr) *error = "Need at least two spendable notes";
        return std::nullopt;
    }
    if (max_notes < 2) {
        if (error != nullptr) *error = "Merge requires at least two notes";
        return std::nullopt;
    }

    std::map<uint256, std::vector<ShieldedCoin>> grouped;
    for (const auto& coin : spendable) {
        grouped[coin.note.recipient_pk_hash].push_back(coin);
    }

    std::vector<std::reference_wrapper<std::vector<ShieldedCoin>>> candidate_groups;
    candidate_groups.reserve(grouped.size());
    for (auto& group_entry : grouped) {
        auto& group_notes = group_entry.second;
        if (group_notes.size() < 2) continue;
        std::sort(group_notes.begin(), group_notes.end(), [](const ShieldedCoin& a, const ShieldedCoin& b) {
            return std::tie(a.note.value, a.tree_position, a.nullifier) <
                   std::tie(b.note.value, b.tree_position, b.nullifier);
        });
        candidate_groups.push_back(group_notes);
    }
    std::sort(candidate_groups.begin(),
              candidate_groups.end(),
              [](const auto& lhs, const auto& rhs) {
                  const auto& left = lhs.get();
                  const auto& right = rhs.get();
                  if (left.size() != right.size()) return left.size() > right.size();
                  return std::tie(left.front().tree_position, left.front().nullifier) <
                         std::tie(right.front().tree_position, right.front().nullifier);
              });

    if (candidate_groups.empty()) {
        if (error != nullptr) *error = "No merge candidate notes found under one spending key";
        return std::nullopt;
    }

    std::string last_error{"No merge candidate notes found under one spending key"};
    for (auto& group_ref : candidate_groups) {
        const auto& group_notes = group_ref.get();
        const size_t merge_count =
            std::min({max_notes,
                      group_notes.size(),
                      static_cast<size_t>(shielded::v2::MAX_LIVE_DIRECT_SMILE_SPENDS)});
        if (merge_count < 2) continue;

        std::vector<ShieldedCoin> selected_group(group_notes.begin(), group_notes.begin() + merge_count);
        CAmount total{0};
        bool overflow{false};
        for (const auto& coin : selected_group) {
            const auto next = CheckedAdd(total, coin.note.value);
            if (!next || !MoneyRange(*next)) {
                last_error = "Merge input total overflow";
                overflow = true;
                break;
            }
            total = *next;
        }
        if (overflow) continue;

        const CAmount merged_value = total - fee;
        if (merged_value <= 0) {
            last_error = "Merge amount must exceed fee";
            continue;
        }

        const uint256 target_pk_hash = selected_group.front().note.recipient_pk_hash;
        auto target_addr_it = std::find_if(
            m_key_sets.begin(),
            m_key_sets.end(),
            [&](const auto& entry) { return entry.first.pk_hash == target_pk_hash; });
        if (target_addr_it == m_key_sets.end()) {
            last_error = "Merge target keyset unavailable";
            continue;
        }

        std::string create_error;
        auto merged = CreateV2Send({{target_addr_it->first, merged_value}},
                                   /*transparent_recipients=*/{},
                                   fee,
                                   &selected_group,
                                   &create_error);
        if (merged.has_value()) return merged;
        if (!create_error.empty()) last_error = create_error;
    }

    if (error != nullptr) *error = last_error;
    return std::nullopt;
}

std::optional<ShieldedNote> CShieldedWallet::TryDecryptNote(const shielded::EncryptedNote& enc_note) const
{
    AssertLockHeld(cs_shielded);
    auto dec = TryDecryptNoteFull(enc_note);
    if (!dec.has_value()) return std::nullopt;
    return dec->first;
}

std::optional<ShieldedNote> CShieldedWallet::TryDecryptNote(const shielded::v2::EncryptedNotePayload& enc_note) const
{
    AssertLockHeld(cs_shielded);
    auto dec = TryDecryptNoteFull(enc_note);
    if (!dec.has_value()) return std::nullopt;
    return dec->first;
}

std::optional<ShieldedCoin> CShieldedWallet::GetCoinByNullifier(const Nullifier& nf) const
{
    AssertLockHeld(cs_shielded);
    const auto it = m_notes.find(nf);
    if (it == m_notes.end()) return std::nullopt;
    return it->second;
}

std::optional<std::vector<ShieldedCoin>> CShieldedWallet::GetConflictSpendSelection(
    const uint256& txid,
    std::string* error) const
{
    AssertLockHeld(cs_shielded);
    LOCK(m_parent_wallet.cs_wallet);

    const CWalletTx* wtx = m_parent_wallet.GetWalletTx(txid);
    if (wtx == nullptr) {
        if (error != nullptr) *error = "conflict_txid is not a wallet transaction";
        return std::nullopt;
    }
    if (!wtx->InMempool()) {
        if (error != nullptr) *error = "conflict_txid is not currently in the wallet mempool";
        return std::nullopt;
    }
    if (!wtx->tx->HasShieldedBundle()) {
        if (error != nullptr) *error = "conflict_txid does not spend shielded notes";
        return std::nullopt;
    }

    const CShieldedBundle& bundle = wtx->tx->GetShieldedBundle();
    if (!bundle.HasV2Bundle() ||
        bundle.GetTransactionFamily() != shielded::v2::TransactionFamily::V2_SEND) {
        if (error != nullptr) *error = "conflict_txid must reference an in-mempool v2 shielded send";
        return std::nullopt;
    }

    std::vector<ShieldedCoin> selected;
    selected.reserve(bundle.GetShieldedInputCount());
    for (const Nullifier& nf : CollectShieldedNullifiers(bundle)) {
        const auto coin_it = m_notes.find(nf);
        if (coin_it == m_notes.end()) {
            if (error != nullptr) *error = "conflict_txid includes a note that is no longer spendable";
            return std::nullopt;
        }
        if (!coin_it->second.is_mine_spend) {
            if (error != nullptr) *error = "conflict_txid includes a non-spendable wallet note";
            return std::nullopt;
        }
        selected.push_back(coin_it->second);
    }
    if (selected.empty()) {
        if (error != nullptr) *error = "conflict_txid does not spend any wallet shielded notes";
        return std::nullopt;
    }
    return selected;
}

std::optional<ShieldedTxView> CShieldedWallet::GetCachedTransactionView(const uint256& txid) const
{
    AssertLockHeld(cs_shielded);
    const auto it = m_tx_view_cache.find(txid);
    if (it == m_tx_view_cache.end()) return std::nullopt;
    return it->second;
}

bool CShieldedWallet::GetKEMPublicKey(const ShieldedAddress& addr, mlkem::PublicKey& out_pk) const
{
    AssertLockHeld(cs_shielded);
    const auto it = m_key_sets.find(addr);
    if (it == m_key_sets.end()) return false;
    out_pk = it->second.kem_key.pk;
    return true;
}

bool CShieldedWallet::NullifierReservedByAnotherMempoolTx(const Nullifier& nf,
                                                          const uint256& excluding_txid) const
{
    AssertLockHeld(cs_shielded);
    LOCK(m_parent_wallet.cs_wallet);
    for (const auto& [txid, wtx] : m_parent_wallet.mapWallet) {
        if (txid == excluding_txid) continue;
        if (!wtx.InMempool()) continue;
        if (!wtx.tx->HasShieldedBundle()) continue;
        for (const auto& spend_nf : CollectShieldedNullifiers(wtx.tx->GetShieldedBundle())) {
            if (spend_nf == nf) return true;
        }
    }
    return false;
}

std::vector<unsigned char> CShieldedWallet::GetMasterSeed() const
{
    LOCK(m_parent_wallet.cs_wallet);
    if (!m_parent_wallet.IsCrypted()) {
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::GetMasterSeed: refusing shielded seed access for unencrypted wallet\n");
        return {};
    }
    WalletBatch batch(m_parent_wallet.GetDatabase());

    uint256 seed_iv;
    std::vector<unsigned char> encrypted_seed;
    if (batch.ReadCryptedPQMasterSeed(seed_iv, encrypted_seed) && !encrypted_seed.empty()) {
        if (!m_parent_wallet.IsCrypted()) {
            throw std::runtime_error("Shielded PQ master seed is encrypted but the wallet is not marked encrypted");
        }
        if (m_parent_wallet.IsLocked()) {
            LogPrintf("CShieldedWallet::GetMasterSeed: unable to decrypt encrypted seed while wallet is locked\n");
            return {};
        }
        std::vector<unsigned char> decrypted_seed;
        // R6-207: ScopedByteVectorCleanse ensures decrypted_seed is wiped on all paths.
        ScopedByteVectorCleanse decrypted_seed_cleanse(decrypted_seed);
        bool seed_was_authenticated{false};
        if (!DecryptWithWalletKey(m_parent_wallet,
                                  Span<const unsigned char>{encrypted_seed.data(), encrypted_seed.size()},
                                  seed_iv,
                                  decrypted_seed,
                                  WALLET_SECRET_PURPOSE_PQ_MASTER_SEED,
                                  &seed_was_authenticated) ||
            decrypted_seed.size() != 32) {
            throw std::runtime_error("Shielded PQ master seed is unreadable or corrupted");
        }
        if (!seed_was_authenticated) {
            uint256 new_iv;
            std::vector<unsigned char> migrated_seed;
            if (EncryptWithWalletKey(m_parent_wallet,
                                     Span<const unsigned char>{decrypted_seed.data(), decrypted_seed.size()},
                                     new_iv,
                                     migrated_seed,
                                     WALLET_SECRET_PURPOSE_PQ_MASTER_SEED) &&
                batch.WriteCryptedPQMasterSeed(new_iv, migrated_seed)) {
                LogDebug(BCLog::WALLETDB, "CShieldedWallet::GetMasterSeed migrated legacy encrypted PQ seed to authenticated format\n");
            }
        }
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::GetMasterSeed using encrypted pqmasterseed (len=%u)\n",
                  static_cast<unsigned int>(decrypted_seed.size()));
        // Return a copy; the local decrypted_seed is cleansed by the scoped guard.
        std::vector<unsigned char> result(decrypted_seed.begin(), decrypted_seed.end());
        return result;
    }

    std::vector<unsigned char> seed;
    if (batch.ReadPQMasterSeed(seed)) {
        if (seed.size() != 32) {
            throw std::runtime_error("Shielded PQ master seed has invalid length");
        }
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::GetMasterSeed using pqmasterseed (len=%u)\n",
                  static_cast<unsigned int>(seed.size()));
        if (m_parent_wallet.IsCrypted() && !m_parent_wallet.IsLocked()) {
            uint256 iv;
            std::vector<unsigned char> encrypted;
            if (EncryptWithWalletKey(m_parent_wallet,
                                     Span<const unsigned char>{seed.data(), seed.size()},
                                     iv,
                                     encrypted,
                                     WALLET_SECRET_PURPOSE_PQ_MASTER_SEED)) {
                if (!batch.WriteCryptedPQMasterSeed(iv, encrypted)) {
                    LogDebug(BCLog::WALLETDB, "CShieldedWallet::GetMasterSeed failed to persist encrypted seed copy\n");
                } else if (!batch.ErasePQMasterSeed()) {
                    LogDebug(BCLog::WALLETDB, "CShieldedWallet::GetMasterSeed failed to erase plaintext seed after migration\n");
                }
            }
        }
        return seed;
    }

    LegacyDataSPKM* legacy_spkm = m_parent_wallet.GetLegacyDataSPKM();
    if (legacy_spkm != nullptr) {
        const CHDChain& hd_chain = legacy_spkm->GetHDChain();
        if (!hd_chain.seed_id.IsNull()) {
            CKey seed_key;
            if (legacy_spkm->GetKey(hd_chain.seed_id, seed_key)) {
                const auto* begin = reinterpret_cast<const unsigned char*>(seed_key.data());
                seed.assign(begin, begin + seed_key.size());
            }
        }
    }

    if (seed.empty()) {
        std::array<unsigned char, 32> fallback_seed{};
        GetStrongRandBytes(fallback_seed);
        seed.assign(fallback_seed.begin(), fallback_seed.end());
        // R6-207: Cleanse the stack-allocated fallback seed immediately after copying.
        memory_cleanse(fallback_seed.data(), fallback_seed.size());
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::GetMasterSeed generated random fallback seed (len=%u)\n",
                  static_cast<unsigned int>(seed.size()));
    } else {
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::GetMasterSeed using legacy hd seed (len=%u)\n",
                  static_cast<unsigned int>(seed.size()));
    }

    bool persisted{false};
    if (m_parent_wallet.IsCrypted() && !m_parent_wallet.IsLocked()) {
        uint256 iv;
        std::vector<unsigned char> encrypted;
        if (EncryptWithWalletKey(m_parent_wallet,
                                 Span<const unsigned char>{seed.data(), seed.size()},
                                 iv,
                                 encrypted,
                                 WALLET_SECRET_PURPOSE_PQ_MASTER_SEED) &&
            batch.WriteCryptedPQMasterSeed(iv, encrypted)) {
            batch.ErasePQMasterSeed();
            persisted = true;
            LogDebug(BCLog::WALLETDB, "CShieldedWallet::GetMasterSeed persisted encrypted seed\n");
        }
    }

    if (!persisted) {
        if (!batch.WritePQMasterSeed(seed)) {
            LogPrintf("CShieldedWallet: failed to persist PQ master seed fallback\n");
        } else {
            LogDebug(BCLog::WALLETDB, "CShieldedWallet::GetMasterSeed persisted pqmasterseed fallback\n");
        }
    }
    return seed;
}

int CShieldedWallet::GetChainTipHeight() const
{
    const auto tip = m_parent_wallet.chain().getHeight();
    return tip.value_or(0);
}

std::vector<ShieldedCoin> CShieldedWallet::SelectNotes(CAmount target,
                                                       CAmount fee,
                                                       bool prefer_minimal_inputs) const
{
    AssertLockHeld(cs_shielded);
    auto spendable = GetSpendableNotes(/*min_depth=*/1);
    if (spendable.empty()) return {};

    // `fee` is an absolute transaction fee (in satoshis), not a feerate.
    // Feeding absolute fees into per-weight effective-value scoring can make
    // every note appear unspendable for valid user-provided fees.
    (void)fee;
    static constexpr CAmount kSelectionFeePerWeight{1};
    const CAmount fee_per_weight = kSelectionFeePerWeight;

    // Current proof generation path uses one spending key material per tx.
    // Prefer selecting notes from a single spend authority set.
    std::map<uint256, std::vector<ShieldedCoin>> grouped;
    for (const auto& coin : spendable) {
        grouped[coin.note.recipient_pk_hash].push_back(coin);
    }

    std::vector<ShieldedCoin> best_group_selection;
    CAmount best_group_excess{std::numeric_limits<CAmount>::max()};
    size_t best_group_count{std::numeric_limits<size_t>::max()};

    for (const auto& [_, group_notes] : grouped) {
        auto selected = prefer_minimal_inputs
            ? ShieldedKnapsackSolver(group_notes, target)
            : ShieldedCoinSelection(group_notes, target, fee_per_weight);
        if (selected.empty()) continue;

        CAmount total{0};
        for (const auto& coin : selected) {
            const auto next = CheckedAdd(total, coin.note.value);
            if (!next || !MoneyRange(*next)) {
                total = 0;
                break;
            }
            total = *next;
        }
        if (total < target) continue;

        const CAmount excess = total - target;
        const bool better = prefer_minimal_inputs
            ? (best_group_selection.empty() ||
               selected.size() < best_group_count ||
               (selected.size() == best_group_count && excess < best_group_excess))
            : (best_group_selection.empty() ||
               excess < best_group_excess ||
               (excess == best_group_excess && selected.size() < best_group_selection.size()));
        if (better) {
            best_group_excess = excess;
            best_group_count = selected.size();
            best_group_selection = std::move(selected);
        }
    }

    if (!best_group_selection.empty()) {
        return best_group_selection;
    }

    // Fallback path for compatibility if grouping cannot satisfy target.
    return prefer_minimal_inputs
        ? ShieldedKnapsackSolver(spendable, target)
        : ShieldedCoinSelection(spendable, target, fee_per_weight);
}

std::optional<std::pair<ShieldedNote, const ShieldedKeySet*>> CShieldedWallet::TryDecryptNoteFull(
    const shielded::EncryptedNote& enc_note) const
{
    AssertLockHeld(cs_shielded);
    std::optional<ShieldedNote> first_match;
    const ShieldedKeySet* first_keyset{nullptr};
    for (const auto& [_, keyset] : m_key_sets) {
        // R6-213 mitigation: execute a constant-time-style scan path by trying
        // decapsulation/decryption against every local keyset and deferring the
        // match decision until after the loop.
        auto note = shielded::NoteEncryption::TryDecrypt(
            enc_note,
            keyset.kem_key.pk,
            keyset.kem_key.sk,
            /*constant_time_scan=*/true);
        if (note.has_value() && !first_match.has_value()) {
            first_match = std::move(note);
            first_keyset = &keyset;
        }
    }
    if (first_match.has_value() && first_keyset != nullptr) {
        return std::make_pair(std::move(*first_match), first_keyset);
    }
    return std::nullopt;
}

std::optional<std::pair<ShieldedNote, const ShieldedKeySet*>> CShieldedWallet::TryDecryptNoteFull(
    const shielded::v2::EncryptedNotePayload& enc_note) const
{
    AssertLockHeld(cs_shielded);
    auto legacy_note = shielded::v2::DecodeLegacyEncryptedNotePayload(enc_note);
    if (!legacy_note.has_value()) {
        LogDebug(BCLog::WALLETDB, "TryDecryptNoteFull(v2): DecodeLegacyEncryptedNotePayload failed "
                 "(valid=%d ephemeral_key=%s ciphertext_size=%u)\n",
                 enc_note.IsValid(),
                 enc_note.ephemeral_key.ToString(),
                 static_cast<unsigned int>(enc_note.ciphertext.size()));
        return std::nullopt;
    }

    std::optional<ShieldedNote> first_hint_match;
    const ShieldedKeySet* first_hint_keyset{nullptr};
    std::optional<ShieldedNote> first_fallback_match;
    const ShieldedKeySet* first_fallback_keyset{nullptr};

    // Execute the constant-time scan path against every local keyset and use
    // scan hints only to prioritize the returned match, not to skip work.
    for (const auto& [_, keyset] : m_key_sets) {
        const bool hint_match =
            shielded::v2::LegacyEncryptedNotePayloadMatchesRecipient(enc_note, *legacy_note, keyset.kem_key.pk);

        auto note = shielded::NoteEncryption::TryDecrypt(
            *legacy_note,
            keyset.kem_key.pk,
            keyset.kem_key.sk,
            /*constant_time_scan=*/true);
        if (!note.has_value()) continue;

        if (hint_match && !first_hint_match.has_value()) {
            first_hint_match = std::move(note);
            first_hint_keyset = &keyset;
            continue;
        }

        if (!first_fallback_match.has_value()) {
            first_fallback_match = std::move(note);
            first_fallback_keyset = &keyset;
        }
    }

    if (first_hint_match.has_value() && first_hint_keyset != nullptr) {
        return std::make_pair(std::move(*first_hint_match), first_hint_keyset);
    }
    if (first_fallback_match.has_value() && first_fallback_keyset != nullptr) {
        LogPrintf("TryDecryptNoteFull(v2): scan-hint miss recovered via full keyset "
                  "scan (kem_pk_hash=%s)\n",
                  first_fallback_keyset->kem_pk_hash.ToString());
        return std::make_pair(std::move(*first_fallback_match), first_fallback_keyset);
    }
    return std::nullopt;
}

void CShieldedWallet::UpdateWitnesses(const uint256& new_commitment)
{
    AssertLockHeld(cs_shielded);
    for (auto& [_, witness] : m_witnesses) {
        witness.IncrementalUpdate(new_commitment);
    }
}

void CShieldedWallet::PruneSpentWitnesses()
{
    AssertLockHeld(cs_shielded);
    for (auto it = m_notes.begin(); it != m_notes.end(); ++it) {
        if (it->second.is_spent) {
            m_witnesses.erase(it->second.commitment);
        }
    }
}

bool CShieldedWallet::PersistState()
{
    AssertLockHeld(cs_shielded);

    PersistedShieldedState state;
    state.next_spending_index = m_next_spending_index;
    state.next_kem_index = m_next_kem_index;
    state.last_scanned_height = m_last_scanned_height;
    state.last_scanned_hash = m_last_scanned_hash;
    state.tree = m_tree;

    state.key_sets.reserve(m_key_sets.size());
    for (const auto& [addr, keyset] : m_key_sets) {
        PersistedShieldedKeySet out;
        out.addr = addr;
        out.account = keyset.account;
        out.index = keyset.index;
        out.has_spending_key = keyset.has_spending_key;
        out.kem_pk.assign(keyset.kem_key.pk.begin(), keyset.kem_key.pk.end());
        out.kem_sk.assign(keyset.kem_key.sk.begin(), keyset.kem_key.sk.end());
        state.key_sets.push_back(std::move(out));
    }
    state.address_lifecycles.reserve(m_address_lifecycles.size());
    for (const auto& [addr, lifecycle] : m_address_lifecycles) {
        if (!lifecycle.IsValid()) {
            continue;
        }
        state.address_lifecycles.push_back({addr, lifecycle});
    }

    state.notes.reserve(m_notes.size());
    state.note_classes.reserve(m_notes.size());
    for (const auto& [_, coin] : m_notes) {
        state.notes.push_back(coin);
        state.note_classes.push_back(
            {coin.nullifier, static_cast<uint8_t>(coin.note_class)});
    }

    state.witnesses.reserve(m_witnesses.size());
    for (const auto& [commitment, witness] : m_witnesses) {
        state.witnesses.emplace_back(commitment, witness);
    }
    state.recent_ring_exclusions = m_recent_ring_exclusions;

    DataStream ss;
    ss << state;
    const auto* begin = reinterpret_cast<const unsigned char*>(ss.data());
    std::vector<unsigned char> blob(begin, begin + ss.size());

    WalletBatch batch(m_parent_wallet.GetDatabase());

    // Persist the commitment index in plaintext — these are public on-chain
    // values.  Storing them avoids a full chain walk to rebuild the position
    // index after loading the serialized tree frontier (which does not carry
    // per-leaf data).
    if (m_tree.HasCommitmentIndex() && m_tree.Size() > 0) {
        std::vector<uint256> commitments;
        commitments.reserve(static_cast<size_t>(m_tree.Size()));
        for (uint64_t i = 0; i < m_tree.Size(); ++i) {
            auto c = m_tree.CommitmentAt(i);
            if (!c.has_value()) break;
            commitments.push_back(*c);
        }
        if (commitments.size() == static_cast<size_t>(m_tree.Size())) {
            if (!batch.WriteShieldedCommitments(commitments)) {
                LogPrintf("CShieldedWallet::PersistState: failed to write commitment index\n");
            }
        }
    }

    if (!m_parent_wallet.IsCrypted()) {
        LogDebug(BCLog::WALLETDB, "CShieldedWallet::PersistState: wallet is unencrypted, persisting tree-only public state\n");
        if (!ScrubPersistedShieldedSecrets(batch, "CShieldedWallet::PersistState")) {
            LogPrintf("CShieldedWallet::PersistState: failed to scrub persisted shielded secrets\n");
            return false;
        }
        PersistedShieldedState tree_only;
        tree_only.next_spending_index = state.next_spending_index;
        tree_only.next_kem_index = state.next_kem_index;
        tree_only.last_scanned_height = state.last_scanned_height;
        tree_only.last_scanned_hash = state.last_scanned_hash;
        tree_only.tree = state.tree;
        tree_only.recent_ring_exclusions = state.recent_ring_exclusions;
        tree_only.address_lifecycles = state.address_lifecycles;
        DataStream ts;
        ts << tree_only;
        const auto* tbegin = reinterpret_cast<const unsigned char*>(ts.data());
        std::vector<unsigned char> tree_blob(tbegin, tbegin + ts.size());
        return batch.WriteShieldedState(tree_blob);
    }

    if (m_parent_wallet.IsCrypted()) {
        uint256 iv;
        std::vector<unsigned char> encrypted_blob;
        if (!EncryptWithWalletKey(m_parent_wallet,
                                  Span<const unsigned char>{blob.data(), blob.size()},
                                  iv,
                                  encrypted_blob,
                                  WALLET_SECRET_PURPOSE_SHIELDED_STATE)) {
            if (!m_parent_wallet.IsLocked()) {
                LogPrintf("CShieldedWallet::PersistState: failed to encrypt shielded state while wallet is unlocked\n");
                return false;
            }
            // Wallet is locked — persist only the non-sensitive tree and scan
            // cursor in plaintext so the anchor stays in sync across restarts.
            // Omit key_sets, notes, and witnesses to avoid writing secret key
            // material to disk unencrypted.  The existing encrypted blob (if
            // any) is deliberately left untouched so that it can be decrypted
            // on the next unlock to restore the full state without a rescan.
            // Expected condition: wallet is locked, persist tree-only state.
            // This runs on every block for locked encrypted wallets; use
            // LogDebug to avoid flooding the log.
            LogDebug(BCLog::WALLETDB, "CShieldedWallet::PersistState: wallet locked, persisting tree-only state in plaintext\n");
            PersistedShieldedState tree_only;
            tree_only.next_spending_index = state.next_spending_index;
            tree_only.next_kem_index = state.next_kem_index;
            tree_only.last_scanned_height = state.last_scanned_height;
            tree_only.last_scanned_hash = state.last_scanned_hash;
            tree_only.tree = state.tree;
            tree_only.recent_ring_exclusions = state.recent_ring_exclusions;
            tree_only.address_lifecycles = state.address_lifecycles;
            // key_sets, notes, witnesses left empty — no secrets written.
            DataStream ts;
            ts << tree_only;
            const auto* tbegin = reinterpret_cast<const unsigned char*>(ts.data());
            std::vector<unsigned char> tree_blob(tbegin, tbegin + ts.size());
            return batch.WriteShieldedState(tree_blob);
        }
        // Guard against overwriting a populated encrypted blob with empty
        // state.  This can happen when the wallet starts locked (tree-only
        // fallback loaded, m_key_sets empty), the user unlocks, and an
        // operation like Rescan() calls PersistState() before keys have been
        // rehydrated.  Overwriting in that situation would permanently destroy
        // the keys and notes, requiring a full chain rescan to recover.
        if (state.key_sets.empty()) {
            uint256 existing_iv;
            std::vector<unsigned char> existing_encrypted;
            if (batch.ReadCryptedShieldedState(existing_iv, existing_encrypted) && !existing_encrypted.empty()) {
                LogPrintf("CShieldedWallet::PersistState: refusing to overwrite encrypted blob with empty key_sets\n");
                return true;
            }
        }
        if (!batch.WriteCryptedShieldedState(iv, encrypted_blob)) {
            return false;
        }
        if (!batch.EraseShieldedState()) {
            LogPrintf("CShieldedWallet::PersistState failed to erase plaintext shielded state after encryption\n");
        }
        return true;
    }
    return batch.WriteShieldedState(blob);
}

void CShieldedWallet::LoadPersistedState()
{
    AssertLockHeld(cs_shielded);

    // On startup, clear any stale pending-spend reservations from the previous
    // session. The mempool is empty after a restart, so no in-flight transactions
    // exist that would still need the reservations.
    m_pending_spends.clear();
    m_mempool_notes.clear();
    m_mempool_note_index.clear();

    WalletBatch batch(m_parent_wallet.GetDatabase());
    std::vector<unsigned char> blob;
    uint256 state_iv;
    std::vector<unsigned char> encrypted_blob;
    const bool have_encrypted_state =
        batch.ReadCryptedShieldedState(state_iv, encrypted_blob) && !encrypted_blob.empty();
    bool using_locked_plaintext_fallback{false};
    bool encrypted_state_was_authenticated{false};
    m_locked_state_incomplete = have_encrypted_state && m_parent_wallet.IsCrypted() && m_parent_wallet.IsLocked();
    if (have_encrypted_state) {
        if (!m_parent_wallet.IsCrypted()) {
            throw std::runtime_error("Shielded state is encrypted but the wallet is not marked encrypted");
        }
        if (m_parent_wallet.IsLocked()) {
            if (!DecryptWithWalletKey(m_parent_wallet,
                                      Span<const unsigned char>{encrypted_blob.data(), encrypted_blob.size()},
                                      state_iv,
                                      blob,
                                      WALLET_SECRET_PURPOSE_SHIELDED_STATE,
                                      &encrypted_state_was_authenticated)) {
                using_locked_plaintext_fallback = true;
                LogPrintf("CShieldedWallet::LoadPersistedState cannot decrypt encrypted shielded state while wallet is locked; trying plaintext tree-only fallback\n");
            }
        } else if (!DecryptWithWalletKey(m_parent_wallet,
                                         Span<const unsigned char>{encrypted_blob.data(), encrypted_blob.size()},
                                         state_iv,
                                         blob,
                                         WALLET_SECRET_PURPOSE_SHIELDED_STATE,
                                         &encrypted_state_was_authenticated)) {
            throw std::runtime_error("Shielded encrypted state is unreadable or corrupted");
        }
    }
    if (blob.empty()) {
        if (!batch.ReadShieldedState(blob)) {
            return;
        }
        if (using_locked_plaintext_fallback) {
            m_locked_state_incomplete = true;
            LogPrintf("CShieldedWallet::LoadPersistedState loaded plaintext tree-only fallback while encrypted state is locked\n");
        } else if (m_parent_wallet.IsCrypted() && !m_parent_wallet.IsLocked()) {
            uint256 iv;
            std::vector<unsigned char> encrypted_state;
            if (EncryptWithWalletKey(m_parent_wallet,
                                     Span<const unsigned char>{blob.data(), blob.size()},
                                     iv,
                                     encrypted_state,
                                     WALLET_SECRET_PURPOSE_SHIELDED_STATE)) {
                if (!batch.WriteCryptedShieldedState(iv, encrypted_state)) {
                    LogPrintf("CShieldedWallet::LoadPersistedState failed to persist encrypted shielded state copy\n");
                } else if (!batch.EraseShieldedState()) {
                    LogPrintf("CShieldedWallet::LoadPersistedState failed to erase plaintext shielded state after migration\n");
                }
            }
        }
    }

    PersistedShieldedState state;
    bool rewrite_unencrypted_tree_only{false};
    try {
        DataStream ss{blob};
        ss >> state;
        if (!ss.empty()) {
            if (have_encrypted_state && !using_locked_plaintext_fallback) {
                throw std::runtime_error("Persisted encrypted shielded state has trailing bytes");
            }
            LogPrintf("CShieldedWallet: persisted state decode had trailing bytes; ignoring persisted state\n");
            return;
        }
    } catch (const std::exception& e) {
        if (have_encrypted_state && !using_locked_plaintext_fallback) {
            throw std::runtime_error(strprintf("Persisted encrypted shielded state is unreadable: %s", e.what()));
        }
        LogPrintf("CShieldedWallet: failed to decode persisted state: %s\n", e.what());
        return;
    }

    if (have_encrypted_state && !using_locked_plaintext_fallback && !encrypted_state_was_authenticated &&
        m_parent_wallet.IsCrypted() && !m_parent_wallet.IsLocked()) {
        uint256 migrated_iv;
        std::vector<unsigned char> migrated_blob;
        if (EncryptWithWalletKey(m_parent_wallet,
                                 Span<const unsigned char>{blob.data(), blob.size()},
                                 migrated_iv,
                                 migrated_blob,
                                 WALLET_SECRET_PURPOSE_SHIELDED_STATE) &&
            batch.WriteCryptedShieldedState(migrated_iv, migrated_blob)) {
            LogDebug(BCLog::WALLETDB, "CShieldedWallet::LoadPersistedState migrated legacy encrypted state to authenticated format\n");
        }
    }

    if (state.version == 0 || state.version > SHIELDED_STATE_VERSION) {
        LogPrintf("CShieldedWallet: unsupported persisted state version %u (expected %u); ignoring persisted state\n",
                  state.version,
                  SHIELDED_STATE_VERSION);
        return;
    }

    if (!m_parent_wallet.IsCrypted()) {
        rewrite_unencrypted_tree_only =
            ScrubPersistedShieldedSecrets(batch, "CShieldedWallet::LoadPersistedState");
        if (!state.key_sets.empty() || !state.notes.empty() || !state.witnesses.empty()) {
            LogPrintf("CShieldedWallet::LoadPersistedState: ignoring plaintext shielded secrets from unencrypted wallet state\n");
            rewrite_unencrypted_tree_only = true;
        }
        state.key_sets.clear();
        state.notes.clear();
        state.note_classes.clear();
        state.witnesses.clear();
    }

    m_key_sets.clear();
    m_address_lifecycles.clear();
    m_notes.clear();
    m_spent_nullifiers.clear();
    m_witnesses.clear();
    m_smile_public_accounts.clear();
    m_account_leaf_commitments.clear();
    m_mempool_notes.clear();
    m_mempool_note_index.clear();
    m_pending_spends.clear();
    m_recent_ring_exclusions.clear();
    m_tx_view_cache.clear();
    m_tree = shielded::ShieldedMerkleTree{shielded::ShieldedMerkleTree::IndexStorageMode::MEMORY_ONLY};
    m_next_spending_index = 0;
    m_next_kem_index = 0;
    m_last_scanned_height = -1;
    m_last_scanned_hash.SetNull();

    std::vector<unsigned char> master_seed;
    if (m_parent_wallet.IsCrypted() && !state.key_sets.empty()) {
        master_seed = GetMasterSeed();
    }
    ScopedByteVectorCleanse master_seed_cleanse_load(master_seed);
    for (const auto& in : state.key_sets) {
        if (in.addr.algo_byte != SHIELDED_ADDRESS_ALGO_BYTE) continue;
        if (in.addr.pk_hash.IsNull() || in.addr.kem_pk_hash.IsNull()) continue;
        if (in.addr.version != SHIELDED_ADDRESS_VERSION_LEGACY_HASH_ONLY &&
            in.addr.version != SHIELDED_ADDRESS_VERSION_WITH_KEM_PUBKEY) {
            continue;
        }
        if (in.kem_pk.size() != mlkem::PUBLICKEYBYTES || in.kem_sk.size() != mlkem::SECRETKEYBYTES) continue;

        ShieldedKeySet keyset;
        keyset.account = in.account;
        keyset.index = in.index;
        keyset.has_spending_key = in.has_spending_key;
        keyset.spending_key_loaded = false;
        keyset.spending_pk_hash = in.addr.pk_hash;
        keyset.kem_pk_hash = in.addr.kem_pk_hash;
        std::copy(in.kem_pk.begin(), in.kem_pk.end(), keyset.kem_key.pk.begin());
        keyset.kem_key.sk.assign(in.kem_sk.begin(), in.kem_sk.end());

        const uint256 recomputed_kem_hash = HashBytes(Span<const unsigned char>{keyset.kem_key.pk.data(), keyset.kem_key.pk.size()});
        if (recomputed_kem_hash != keyset.kem_pk_hash) {
            LogPrintf("CShieldedWallet: ignoring persisted keyset with mismatched kem hash addr=%s\n", in.addr.Encode());
            continue;
        }

        ShieldedAddress hydrated_addr = in.addr;
        hydrated_addr.version = SHIELDED_ADDRESS_VERSION_WITH_KEM_PUBKEY;
        hydrated_addr.algo_byte = SHIELDED_ADDRESS_ALGO_BYTE;
        hydrated_addr.kem_pk = keyset.kem_key.pk;
        if (!hydrated_addr.IsValid()) {
            LogPrintf("CShieldedWallet: ignoring persisted keyset with invalid hydrated address\n");
            continue;
        }

        if (keyset.has_spending_key) {
            if (!master_seed.empty()) {
                if (!DeriveSpendingKeyForKeyset(master_seed, keyset)) {
                    LogPrintf("CShieldedWallet: spending key derivation/hash mismatch for persisted addr=%s; loading as view-only\n",
                              in.addr.Encode());
                    keyset.has_spending_key = false;
                }
            } else {
                LogPrintf("CShieldedWallet: deferred spending key derivation for addr=%s until wallet unlock\n",
                          in.addr.Encode());
            }
        }
        m_key_sets[hydrated_addr] = std::move(keyset);
        m_address_lifecycles[hydrated_addr] = ShieldedAddressLifecycle{};
    }

    if (state.version >= 3) {
        for (const auto& entry : state.address_lifecycles) {
            const auto key_it = m_key_sets.find(entry.addr);
            if (key_it == m_key_sets.end()) {
                continue;
            }

            ShieldedAddressLifecycle hydrated_lifecycle = entry.lifecycle;
            if (hydrated_lifecycle.has_successor) {
                const auto successor_it = m_key_sets.find(hydrated_lifecycle.successor);
                if (successor_it == m_key_sets.end()) {
                    continue;
                }
                hydrated_lifecycle.successor = successor_it->first;
            }
            if (hydrated_lifecycle.has_predecessor) {
                const auto predecessor_it = m_key_sets.find(hydrated_lifecycle.predecessor);
                if (predecessor_it == m_key_sets.end()) {
                    continue;
                }
                hydrated_lifecycle.predecessor = predecessor_it->first;
            }
            if (!hydrated_lifecycle.IsValid()) {
                continue;
            }
            m_address_lifecycles[key_it->first] = std::move(hydrated_lifecycle);
        }
    }

    std::set<uint256> spend_authorized_pk_hashes;
    for (const auto& [_, keyset] : m_key_sets) {
        if (keyset.has_spending_key && keyset.spending_key_loaded) {
            spend_authorized_pk_hashes.insert(keyset.spending_pk_hash);
        }
    }

    std::map<Nullifier, shielded::v2::NoteClass> persisted_note_classes;
    for (const auto& entry : state.note_classes) {
        const auto note_class = static_cast<shielded::v2::NoteClass>(entry.note_class);
        if (!shielded::v2::IsValidNoteClass(note_class)) {
            LogPrintf("CShieldedWallet::LoadPersistedState: ignoring invalid persisted note class %u\n",
                      static_cast<unsigned int>(entry.note_class));
            continue;
        }
        persisted_note_classes[entry.nullifier] = note_class;
    }

    for (const auto& coin : state.notes) {
        // Reject corrupt notes with out-of-range values to prevent downstream
        // overflow in coin selection and balance calculations.
        if (!MoneyRange(coin.note.value)) {
            LogPrintf("CShieldedWallet::LoadPersistedState: skipping note with invalid value %lld\n",
                      static_cast<long long>(coin.note.value));
            continue;
        }
        ShieldedCoin restored = coin;
        restored.note_class = shielded::v2::NoteClass::USER;
        if (const auto note_class_it = persisted_note_classes.find(restored.nullifier);
            note_class_it != persisted_note_classes.end()) {
            restored.note_class = note_class_it->second;
        }
        restored.is_mine_spend = spend_authorized_pk_hashes.count(restored.note.recipient_pk_hash) > 0;
        m_notes[restored.nullifier] = restored;
        if (restored.is_spent) {
            m_spent_nullifiers.insert(restored.nullifier);
        }
    }
    for (const auto& [commitment, witness] : state.witnesses) {
        m_witnesses[commitment] = witness;
    }

    m_tree = state.tree;

    // Restore the commitment position index from the separately persisted
    // plaintext blob.  If the count matches the tree size and replaying the
    // commitments produces the same root, swap in the indexed tree so that
    // CatchUpToChainTip can skip the expensive RebuildCommitmentIndex.
    {
        std::vector<uint256> persisted_commitments;
        if (batch.ReadShieldedCommitments(persisted_commitments) &&
            persisted_commitments.size() == static_cast<size_t>(m_tree.Size())) {
            shielded::ShieldedMerkleTree indexed{shielded::ShieldedMerkleTree::IndexStorageMode::MEMORY_ONLY};
            for (const auto& c : persisted_commitments) {
                indexed.Append(c);
            }
            if (indexed.Root() == m_tree.Root()) {
                m_tree = std::move(indexed);
                LogPrintf("CShieldedWallet::LoadPersistedState restored commitment index (%u entries)\n",
                          static_cast<unsigned int>(m_tree.Size()));
            } else {
                LogPrintf("CShieldedWallet::LoadPersistedState commitment index root mismatch; will rebuild from chain\n");
            }
        }
    }

    m_next_spending_index = state.next_spending_index;
    m_next_kem_index = state.next_kem_index;
    m_last_scanned_height = state.last_scanned_height;
    m_last_scanned_hash = state.last_scanned_hash;
    m_recent_ring_exclusions = state.recent_ring_exclusions;
    const uint64_t restored_tree_size = m_tree.Size();
    m_recent_ring_exclusions.erase(
        std::remove_if(m_recent_ring_exclusions.begin(),
                       m_recent_ring_exclusions.end(),
                       [restored_tree_size](uint64_t pos) { return pos >= restored_tree_size; }),
        m_recent_ring_exclusions.end());
    LogPrintf("CShieldedWallet::LoadPersistedState loaded: keys=%u notes=%u tree_size=%u last_height=%d next_spend_idx=%u next_kem_idx=%u last_hash=%s root=%s\n",
              static_cast<unsigned int>(m_key_sets.size()),
              static_cast<unsigned int>(m_notes.size()),
              static_cast<unsigned int>(m_tree.Size()),
              m_last_scanned_height,
              m_next_spending_index,
              m_next_kem_index,
              m_last_scanned_hash.ToString(),
              m_tree.Root().ToString());

    uint32_t max_index{0};
    for (const auto& [_, keyset] : m_key_sets) {
        if (keyset.index < std::numeric_limits<uint32_t>::max()) {
            max_index = std::max(max_index, keyset.index + 1);
        } else {
            LogPrintf("CShieldedWallet::LoadPersistedState: keyset index at max, cannot increment\n");
            max_index = std::max(max_index, keyset.index);
        }
    }
    m_next_spending_index = std::max(m_next_spending_index, max_index);
    m_next_kem_index = std::max(m_next_kem_index, max_index);

    if (!m_parent_wallet.IsCrypted() && rewrite_unencrypted_tree_only && !PersistState()) {
        LogPrintf("CShieldedWallet::LoadPersistedState: failed to persist sanitized tree-only state\n");
    }
}

bool CShieldedWallet::MaybeRehydrateSpendingKeys()
{
    AssertLockHeld(cs_shielded);

    if (!m_parent_wallet.IsCrypted() || m_parent_wallet.IsLocked()) {
        return false;
    }

    bool rehydrated{false};

    if (m_key_sets.empty() && m_notes.empty()) {
        const int previous_height = m_last_scanned_height;
        LoadPersistedState();
        if (!m_key_sets.empty() || !m_notes.empty() || m_last_scanned_height != previous_height) {
            CatchUpToChainTip();
            rehydrated = true;
        }
    }

    // If the persisted state lost its key_sets AND indices (e.g. tree-only
    // fallback was later overwritten by an unlocked PersistState with empty
    // state), attempt to recover by re-deriving keys from the master seed
    // using a gap-limit scan.  We derive keys at successive indices and scan
    // the chain; if a derived key decrypts at least one note we know the
    // index was in use.  We stop after GAP_LIMIT consecutive indices that
    // produce no on-chain notes.
    if (m_key_sets.empty()) {
        std::vector<unsigned char> master_seed = GetMasterSeed();
        ScopedByteVectorCleanse master_seed_cleanse_rederive(master_seed);
        if (!master_seed.empty()) {
            constexpr uint32_t GAP_LIMIT = 20;
            const uint32_t coin_type = 0;
            const uint32_t account = 0;
            uint32_t max_used_index = 0;
            bool found_any{false};

            // Derive up to m_next_spending_index (if known) plus GAP_LIMIT
            // additional indices to discover keys whose indices were lost.
            const uint32_t search_limit = m_next_spending_index + GAP_LIMIT;

            for (uint32_t i = 0; i < search_limit; ++i) {
                ShieldedKeySet keyset;
                keyset.account = account;
                keyset.index = i;
                keyset.has_spending_key = true;
                keyset.spending_key_loaded = false;

                auto spending_key = DerivePQKeyFromBIP39(master_seed,
                                                         PQAlgorithm::ML_DSA_44,
                                                         coin_type,
                                                         account,
                                                         /*change=*/0,
                                                         i);
                if (!spending_key.has_value()) {
                    LogPrintf("CShieldedWallet::MaybeRehydrateSpendingKeys spending key derivation failed index=%u\n", i);
                    continue;
                }
                keyset.spending_key = std::move(*spending_key);
                keyset.spending_key_loaded = true;

                keyset.kem_key = DeriveMLKEMKeyFromBIP39(master_seed,
                                                         coin_type,
                                                         account,
                                                         /*change=*/0,
                                                         i);
                if (std::all_of(keyset.kem_key.pk.begin(), keyset.kem_key.pk.end(), [](uint8_t b) { return b == 0; }) ||
                    !ValidateMLKEMKeyPair(keyset.kem_key)) {
                    LogPrintf("CShieldedWallet::MaybeRehydrateSpendingKeys invalid derived ML-KEM keypair at index=%u; skipping\n", i);
                    continue;
                }

                const auto spending_pk = keyset.spending_key.GetPubKey();
                keyset.spending_pk_hash = HashBytes(spending_pk);
                keyset.kem_pk_hash = HashBytes(Span<const unsigned char>{keyset.kem_key.pk.data(), keyset.kem_key.pk.size()});

                ShieldedAddress addr;
                addr.version = SHIELDED_ADDRESS_VERSION_WITH_KEM_PUBKEY;
                addr.algo_byte = SHIELDED_ADDRESS_ALGO_BYTE;
                addr.pk_hash = keyset.spending_pk_hash;
                addr.kem_pk_hash = keyset.kem_pk_hash;
                addr.kem_pk = keyset.kem_key.pk;

                m_key_sets[addr] = std::move(keyset);
                found_any = true;
                max_used_index = i;
            }
            if (found_any) {
                m_next_spending_index = max_used_index + 1;
                m_next_kem_index = max_used_index + 1;
                LogPrintf("CShieldedWallet::MaybeRehydrateSpendingKeys re-derived %u key(s) from master seed (gap_limit=%u); rebuilding from active chain\n",
                          static_cast<unsigned int>(m_key_sets.size()), GAP_LIMIT);
                RebuildFromActiveChain();
                m_locked_state_incomplete = false;
                return true;
            }
        }
    }

    bool have_missing_spending_keys{false};
    for (const auto& [_, keyset] : m_key_sets) {
        if (keyset.has_spending_key && !keyset.spending_key_loaded) {
            have_missing_spending_keys = true;
            break;
        }
    }
    if (!have_missing_spending_keys) {
        return rehydrated;
    }

    std::vector<unsigned char> master_seed = GetMasterSeed();
    ScopedByteVectorCleanse master_seed_cleanse_rehydrate(master_seed);
    if (master_seed.empty()) {
        return rehydrated;
    }

    bool loaded_any{false};
    for (auto& [addr, keyset] : m_key_sets) {
        if (!keyset.has_spending_key || keyset.spending_key_loaded) {
            continue;
        }
        if (!DeriveSpendingKeyForKeyset(master_seed, keyset)) {
            LogPrintf("CShieldedWallet::MaybeRehydrateSpendingKeys dropping invalid spending authority for addr=%s\n",
                      addr.Encode());
            keyset.has_spending_key = false;
            continue;
        }
        loaded_any = true;
    }

    if (loaded_any) {
        LogPrintf("CShieldedWallet::MaybeRehydrateSpendingKeys rebuilt spend authorities; rescanning active chain\n");
        RebuildFromActiveChain();
        m_locked_state_incomplete = false;
        rehydrated = true;
    }

    return rehydrated;
}

void CShieldedWallet::CatchUpToChainTip()
{
    AssertLockHeld(cs_shielded);

    if (m_key_sets.empty()) {
        return;
    }

    const auto tip_height = m_parent_wallet.chain().getHeight();
    if (!tip_height.has_value() || *tip_height < 0) return;
    LogPrintf("CShieldedWallet::CatchUpToChainTip begin: tip_height=%d last_height=%d tree_size=%u root=%s\n",
              *tip_height,
              m_last_scanned_height,
              static_cast<unsigned int>(m_tree.Size()),
              m_tree.Root().ToString());

    bool rebuild{false};
    if (m_last_scanned_height < 0 || m_last_scanned_height > *tip_height) {
        rebuild = true;
    } else {
        const uint256 expected_hash = m_parent_wallet.chain().getBlockHash(m_last_scanned_height);
        rebuild = expected_hash != m_last_scanned_hash;
        if (rebuild) {
            LogPrintf("CShieldedWallet::CatchUpToChainTip detected hash mismatch at height %d expected=%s loaded=%s\n",
                      m_last_scanned_height,
                      expected_hash.ToString(),
                      m_last_scanned_hash.ToString());
        }
    }

    // Even if height/hash match, verify the wallet tree root against the
    // consensus tree.  A diverged tree (e.g. from stale encrypted state
    // overwriting the live tree on unlock) causes every shielded transaction
    // to fail with bad-shielded-anchor.
    if (!rebuild) {
        const auto consensus_info = m_parent_wallet.chain().getShieldedTreeInfo();
        if (consensus_info.has_value()) {
            const auto& [consensus_root, consensus_size] = *consensus_info;
            if (m_last_scanned_height == *tip_height &&
                (m_tree.Root() != consensus_root || m_tree.Size() != consensus_size)) {
                LogPrintf("CShieldedWallet::CatchUpToChainTip tree root mismatch at tip: "
                          "wallet_root=%s wallet_size=%u consensus_root=%s consensus_size=%u — rebuilding\n",
                          m_tree.Root().ToString(),
                          static_cast<unsigned int>(m_tree.Size()),
                          consensus_root.ToString(),
                          static_cast<unsigned int>(consensus_size));
                rebuild = true;
            }
        }
    }

    if (rebuild) {
        RebuildFromActiveChain();
        return;
    }

    // The commitment position index is not serialized, so after loading
    // persisted state the tree frontier is correct but position lookups are
    // unavailable.  If the tree root and scan cursor are valid we can
    // rebuild just the index by replaying output commitments from the chain
    // without wiping/re-scanning notes.
    if (!m_tree.HasCommitmentIndex()) {
        LogPrintf("CShieldedWallet::CatchUpToChainTip rebuilding commitment index only (notes already loaded)\n");
        RebuildCommitmentIndex();
        return;
    }

    if ((m_smile_public_accounts.empty() ||
         m_account_leaf_commitments.empty() ||
         m_smile_public_accounts.size() != m_account_leaf_commitments.size()) &&
        m_tree.Size() > 0) {
        LogPrintf("CShieldedWallet::CatchUpToChainTip rebuilding SMILE public-account and account-leaf indexes only\n");
        RebuildSmilePublicAccountIndex();
    }

    if (m_last_scanned_height == *tip_height) {
        LogPrintf("CShieldedWallet::CatchUpToChainTip no-op: already at tip with root=%s tree_size=%u\n",
                  m_tree.Root().ToString(),
                  static_cast<unsigned int>(m_tree.Size()));
        return;
    }

    m_defer_persist = true;
    for (int height = m_last_scanned_height + 1; height <= *tip_height; ++height) {
        const uint256 block_hash = m_parent_wallet.chain().getBlockHash(height);
        CBlock block;
        m_parent_wallet.chain().findBlock(block_hash, interfaces::FoundBlock().data(block));
        if (block.IsNull()) {
            m_defer_persist = false;
            RebuildFromActiveChain();
            return;
        }
        ScanBlock(block, height);
    }
    m_defer_persist = false;

    // After incremental scan, verify the resulting tree matches consensus.
    // If the starting tree was wrong, the incremental scan will produce a
    // wrong result too — fall back to a full rebuild.
    const auto consensus_info_post = m_parent_wallet.chain().getShieldedTreeInfo();
    if (consensus_info_post.has_value()) {
        const auto& [consensus_root, consensus_size] = *consensus_info_post;
        if (m_tree.Root() != consensus_root || m_tree.Size() != consensus_size) {
            LogPrintf("CShieldedWallet::CatchUpToChainTip post-scan tree mismatch: "
                      "wallet_root=%s wallet_size=%u consensus_root=%s consensus_size=%u — rebuilding\n",
                      m_tree.Root().ToString(),
                      static_cast<unsigned int>(m_tree.Size()),
                      consensus_root.ToString(),
                      static_cast<unsigned int>(consensus_size));
            RebuildFromActiveChain();
            return;
        }
    }

    if (!PersistState()) {
        LogPrintf("CShieldedWallet: failed to persist state after tip catch-up\n");
    } else {
        LogPrintf("CShieldedWallet::CatchUpToChainTip complete: last_height=%d tree_size=%u root=%s\n",
                  m_last_scanned_height,
                  static_cast<unsigned int>(m_tree.Size()),
                  m_tree.Root().ToString());
    }
}

void CShieldedWallet::RebuildCommitmentIndex()
{
    AssertLockHeld(cs_shielded);

    // Walk the chain and collect all shielded output commitments to rebuild
    // the position index.  The existing tree frontier, notes, and witnesses
    // are preserved — only the commitment index is populated.
    const auto tip_height = m_parent_wallet.chain().getHeight();
    if (!tip_height.has_value() || *tip_height < 0) return;

    shielded::ShieldedMerkleTree index_tree{shielded::ShieldedMerkleTree::IndexStorageMode::MEMORY_ONLY};
    for (int height = 0; height <= *tip_height; ++height) {
        const uint256 block_hash = m_parent_wallet.chain().getBlockHash(height);
        CBlock block;
        m_parent_wallet.chain().findBlock(block_hash, interfaces::FoundBlock().data(block));
        if (block.IsNull()) {
            LogPrintf("CShieldedWallet::RebuildCommitmentIndex aborted: missing block at height %d\n", height);
            // Fall back to full rebuild if a block is unavailable.
            RebuildFromActiveChain();
            return;
        }
        for (const auto& txref : block.vtx) {
            if (!txref->HasShieldedBundle()) continue;
            for (const uint256& commitment : CollectShieldedOutputCommitments(txref->GetShieldedBundle())) {
                index_tree.Append(commitment);
            }
        }
    }

    // Verify the rebuilt tree matches the loaded frontier.
    if (index_tree.Size() != m_tree.Size() || index_tree.Root() != m_tree.Root()) {
        LogPrintf("CShieldedWallet::RebuildCommitmentIndex mismatch: index tree_size=%u root=%s vs loaded tree_size=%u root=%s; falling back to full rebuild\n",
                  static_cast<unsigned int>(index_tree.Size()),
                  index_tree.Root().ToString(),
                  static_cast<unsigned int>(m_tree.Size()),
                  m_tree.Root().ToString());
        RebuildFromActiveChain();
        return;
    }

    m_tree = std::move(index_tree);
    LogPrintf("CShieldedWallet::RebuildCommitmentIndex complete: tree_size=%u root=%s\n",
              static_cast<unsigned int>(m_tree.Size()),
              m_tree.Root().ToString());
    if (!PersistState()) {
        LogPrintf("CShieldedWallet: failed to persist state after commitment index rebuild\n");
    }
}

void CShieldedWallet::RebuildSmilePublicAccountIndex()
{
    AssertLockHeld(cs_shielded);

    const auto tip_height = m_parent_wallet.chain().getHeight();
    if (!tip_height.has_value() || *tip_height < 0) return;

    m_smile_public_accounts.clear();
    m_account_leaf_commitments.clear();
    for (int height = 0; height <= *tip_height; ++height) {
        const uint256 block_hash = m_parent_wallet.chain().getBlockHash(height);
        CBlock block;
        m_parent_wallet.chain().findBlock(block_hash, interfaces::FoundBlock().data(block));
        if (block.IsNull()) {
            LogPrintf("CShieldedWallet::RebuildSmilePublicAccountIndex aborted: missing block at height %d\n",
                      height);
            m_smile_public_accounts.clear();
            m_account_leaf_commitments.clear();
            return;
        }
        for (const auto& txref : block.vtx) {
            if (!txref->HasShieldedBundle()) continue;
            const CShieldedBundle& bundle = txref->GetShieldedBundle();
            for (const auto& [commitment, account] :
                 CollectShieldedOutputSmileAccounts(bundle)) {
                m_smile_public_accounts[commitment] = account;
            }
            const auto account_leaf_entries =
                CollectShieldedOutputAccountLeafEntries(bundle, UseNoncedBridgeTagsAtHeight(height));
            if (!account_leaf_entries.has_value()) {
                LogPrintf("CShieldedWallet::RebuildSmilePublicAccountIndex failed to rebuild account-leaf index at height %d\n",
                          height);
                m_smile_public_accounts.clear();
                m_account_leaf_commitments.clear();
                return;
            }
            for (const auto& [commitment, account_leaf_commitment] : *account_leaf_entries) {
                m_account_leaf_commitments[commitment] = account_leaf_commitment;
            }
        }
    }

    LogPrintf("CShieldedWallet::RebuildSmilePublicAccountIndex complete: accounts=%u account_leaf_commitments=%u\n",
              static_cast<unsigned int>(m_smile_public_accounts.size()),
              static_cast<unsigned int>(m_account_leaf_commitments.size()));
}

void CShieldedWallet::RebuildFromActiveChain()
{
    AssertLockHeld(cs_shielded);
    const auto tip_height = m_parent_wallet.chain().getHeight();
    if (!tip_height.has_value() || *tip_height < 0) {
        return;
    }

    // Pre-flight: verify that ALL blocks from genesis to tip are available on
    // disk before wiping wallet state.  A shielded Merkle tree must be built
    // sequentially from genesis — missing blocks in the middle make a correct
    // rebuild impossible.  On pruned nodes the early blocks are typically gone,
    // so we refuse the destructive wipe and warn loudly instead.
    for (int height = 0; height <= *tip_height; ++height) {
        if (!m_parent_wallet.chain().haveBlockOnDisk(height)) {
            LogPrintf("ERROR: CShieldedWallet::RebuildFromActiveChain cannot proceed — "
                      "block at height %d has been pruned. A full shielded rebuild "
                      "requires all blocks from genesis. Either disable pruning and "
                      "use -reindex to re-download the full chain, or restore wallet "
                      "state from a backup taken on an unpruned node.\n", height);
            m_scan_incomplete = true;
            return;
        }
    }

    const bool previous_defer = m_defer_persist;
    m_defer_persist = true;
    m_scan_incomplete = false;
    Rescan(/*start_height=*/0);

    for (int height = 0; height <= *tip_height; ++height) {
        const uint256 block_hash = m_parent_wallet.chain().getBlockHash(height);
        CBlock block;
        m_parent_wallet.chain().findBlock(block_hash, interfaces::FoundBlock().data(block));
        if (block.IsNull()) {
            // Should not happen given the pre-flight check, but handle
            // gracefully if a block disappears between check and read
            // (e.g. background pruner race).
            LogPrintf("CShieldedWallet: rebuild aborted — block at height %d (%s) "
                      "became unavailable during scan. Shielded balances are incomplete.\n",
                      height, block_hash.ToString());
            m_scan_incomplete = true;
            break;
        }
        ScanBlock(block, height);
    }
    m_defer_persist = previous_defer;
    if (!m_defer_persist && !PersistState()) {
        LogPrintf("CShieldedWallet: failed to persist state after rebuild\n");
    }
}

CShieldedWallet::KeyIntegrityReport CShieldedWallet::VerifyKeyIntegrity()
{
    AssertLockHeld(cs_shielded);
    MaybeRehydrateSpendingKeys();

    KeyIntegrityReport report;
    report.total_keys = static_cast<int>(m_key_sets.size());
    for (const auto& [addr, ks] : m_key_sets) {
        if (ks.spending_key_loaded) {
            ++report.spending_keys_loaded;
        } else if (ks.has_spending_key) {
            ++report.spending_keys_missing;
        }
        // Every key set has a KEM keypair if it was loaded at all
        ++report.viewing_keys_loaded;
    }
    std::vector<unsigned char> seed;
    if (m_parent_wallet.IsCrypted() && !m_parent_wallet.IsLocked()) {
        seed = GetMasterSeed();
    }
    report.master_seed_available = !seed.empty();
    // Cleanse seed immediately
    if (!seed.empty()) {
        memory_cleanse(const_cast<unsigned char*>(seed.data()), seed.size());
    }

    report.notes_total = static_cast<int>(m_notes.size());
    for (const auto& [nf, coin] : m_notes) {
        if (!coin.is_spent) ++report.notes_unspent;
    }
    report.tree_size = static_cast<int>(m_tree.Size());
    report.scan_height = m_last_scanned_height;
    report.scan_incomplete = m_scan_incomplete;
    return report;
}

// R5-520: Note reservation to prevent double-selection in concurrent RPCs.
void CShieldedWallet::ReservePendingSpends(const std::vector<Nullifier>& nullifiers)
{
    AssertLockHeld(cs_shielded);
    for (const auto& nf : nullifiers) {
        m_pending_spends.insert(nf);
    }
}

void CShieldedWallet::ReleasePendingSpends(const std::vector<Nullifier>& nullifiers)
{
    AssertLockHeld(cs_shielded);
    for (const auto& nf : nullifiers) {
        m_pending_spends.erase(nf);
    }
}

} // namespace wallet

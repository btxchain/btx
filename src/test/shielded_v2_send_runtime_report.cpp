// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_v2_send_runtime_report.h>

#include <consensus/consensus.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <chainparams.h>
#include <crypto/ml_kem.h>
#include <hash.h>
#include <policy/policy.h>
#include <shielded/account_registry.h>
#include <shielded/bundle.h>
#include <shielded/lattice/params.h>
#include <shielded/merkle_tree.h>
#include <shielded/note.h>
#include <shielded/note_encryption.h>
#include <shielded/smile2/verify_dispatch.h>
#include <shielded/validation.h>
#include <shielded/v2_bundle.h>
#include <shielded/v2_send.h>
#include <test/util/shielded_account_registry_test_util.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <map>
#include <numeric>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace btx::test::shieldedv2send {
namespace {

using shielded::ShieldedMerkleTree;
using shielded::v2::MAX_DIRECT_OUTPUTS;
using shielded::v2::MAX_DIRECT_SPENDS;
using shielded::v2::V2SendOutputInput;
using shielded::v2::V2SendSpendInput;

struct ScenarioFixture
{
    RuntimeScenarioConfig config;
    int32_t validation_height{0};
    ShieldedMerkleTree tree;
    std::shared_ptr<const std::map<uint256, smile2::CompactPublicAccount>> smile_public_accounts;
    std::shared_ptr<const std::map<uint256, uint256>> account_leaf_commitments;
    CMutableTransaction tx_template;
    std::vector<V2SendSpendInput> spend_inputs;
    std::vector<V2SendOutputInput> output_inputs;
    std::vector<unsigned char> spending_key;
    std::array<unsigned char, 32> rng_entropy{};
    CAmount fee_sat{0};
    CAmount total_input_value{0};
    CAmount total_output_value{0};
};

struct ScenarioMetrics
{
    uint64_t serialized_size_bytes{0};
    uint64_t tx_weight{0};
    int64_t policy_weight{0};
    uint64_t proof_payload_bytes{0};
    ShieldedResourceUsage usage;
    uint64_t max_transactions_by_serialized_size{0};
    uint64_t max_transactions_by_weight{0};
    uint64_t max_transactions_by_verify{0};
    uint64_t max_transactions_by_scan{0};
    uint64_t max_transactions_by_tree_updates{0};
    uint64_t max_transactions_per_block{0};
    uint64_t max_spend_notes_per_block{0};
    uint64_t max_output_notes_per_block{0};
    std::string block_binding_limit;
    bool within_standard_policy_weight{false};
    int64_t standard_policy_weight_headroom{0};
    uint64_t max_transactions_by_standard_policy{0};
};

template <size_t N>
std::array<uint8_t, N> DeriveSeed(std::string_view tag, uint32_t scenario_id, uint32_t index)
{
    std::array<uint8_t, N> seed{};
    size_t offset{0};
    uint32_t counter{0};
    while (offset < seed.size()) {
        HashWriter hw;
        hw << std::string{tag} << scenario_id << index << counter;
        const uint256 digest = hw.GetSHA256();
        const size_t copy_len = std::min(seed.size() - offset, static_cast<size_t>(uint256::size()));
        std::copy_n(digest.begin(), copy_len, seed.begin() + offset);
        offset += copy_len;
        ++counter;
    }
    return seed;
}

uint256 DeterministicUint256(std::string_view tag, uint32_t scenario_id, uint32_t index)
{
    HashWriter hw;
    hw << std::string{tag} << scenario_id << index;
    return hw.GetSHA256();
}

uint32_t ScenarioId(const RuntimeScenarioConfig& config)
{
    return (static_cast<uint32_t>(config.spend_count) << 16) |
           static_cast<uint32_t>(config.output_count);
}

bool IsProoflessDepositScenario(const RuntimeScenarioConfig& config)
{
    return config.spend_count == 0;
}

const char* ValidationSurfaceName(RuntimeValidationSurface surface)
{
    return surface == RuntimeValidationSurface::PREFORK ? "prefork" : "postfork";
}

const char* ScenarioKindName(const RuntimeScenarioConfig& config)
{
    return IsProoflessDepositScenario(config)
        ? "proofless_transparent_deposit"
        : "direct_smile_send";
}

int32_t ResolveValidationHeight(RuntimeValidationSurface surface, const Consensus::Params& consensus)
{
    if (surface == RuntimeValidationSurface::POSTFORK) {
        return consensus.nShieldedMatRiCTDisableHeight;
    }
    if (consensus.nShieldedMatRiCTDisableHeight <= 0) {
        return 0;
    }
    return consensus.nShieldedMatRiCTDisableHeight - 1;
}

ShieldedNote BuildInputNote(uint32_t scenario_id, uint32_t index)
{
    ShieldedNote note;
    note.value = 10 * COIN + static_cast<CAmount>(index) * 1000;
    note.recipient_pk_hash = DeterministicUint256("BTX_ShieldedV2_SendRuntime_InputPkh", scenario_id, index);
    note.rho = DeterministicUint256("BTX_ShieldedV2_SendRuntime_InputRho", scenario_id, index);
    note.rcm = DeterministicUint256("BTX_ShieldedV2_SendRuntime_InputRcm", scenario_id, index);
    if (!note.IsValid()) {
        throw std::runtime_error("constructed invalid direct-send input note");
    }
    return note;
}

ShieldedNote BuildRingDecoyNote(uint32_t scenario_id, uint32_t index)
{
    return BuildInputNote(scenario_id ^ 0xA5A5U, index + 1024);
}

ShieldedNote BuildOutputNote(uint32_t scenario_id, uint32_t index, CAmount value)
{
    ShieldedNote note;
    note.value = value;
    note.recipient_pk_hash = DeterministicUint256("BTX_ShieldedV2_SendRuntime_OutputPkh", scenario_id, index);
    note.rho = DeterministicUint256("BTX_ShieldedV2_SendRuntime_OutputRho", scenario_id, index);
    note.rcm = DeterministicUint256("BTX_ShieldedV2_SendRuntime_OutputRcm", scenario_id, index);
    if (!note.IsValid()) {
        throw std::runtime_error("constructed invalid direct-send output note");
    }
    return note;
}

mlkem::KeyPair BuildRecipientKeyPair(uint32_t scenario_id, uint32_t index)
{
    return mlkem::KeyGenDerand(
        DeriveSeed<mlkem::KEYGEN_SEEDBYTES>("BTX_ShieldedV2_SendRuntime_OutputRecipient", scenario_id, index));
}

shielded::BoundEncryptedNoteResult EncryptNote(const ShieldedNote& note,
                                               const mlkem::PublicKey& recipient_pk,
                                               uint32_t scenario_id,
                                               uint32_t index)
{
    return shielded::NoteEncryption::EncryptBoundNoteDeterministic(
        note,
        recipient_pk,
        DeriveSeed<mlkem::ENCAPS_SEEDBYTES>("BTX_ShieldedV2_SendRuntime_KEM", scenario_id, index),
        DeriveSeed<12>("BTX_ShieldedV2_SendRuntime_Nonce", scenario_id, index));
}

std::vector<uint64_t> BuildRingPositions()
{
    std::vector<uint64_t> positions;
    positions.reserve(shielded::lattice::RING_SIZE);
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        positions.push_back(i);
    }
    return positions;
}

std::vector<uint256> BuildRingMembers(const ShieldedMerkleTree& tree,
                                      const std::vector<uint64_t>& positions)
{
    std::vector<uint256> members;
    members.reserve(positions.size());
    for (const uint64_t position : positions) {
        const auto commitment = tree.CommitmentAt(position);
        if (!commitment.has_value()) {
            throw std::runtime_error("missing direct-send ring member");
        }
        members.push_back(*commitment);
    }
    return members;
}

bool SmileRingMatches(const std::vector<smile2::wallet::SmileRingMember>& lhs,
                      const std::vector<smile2::wallet::SmileRingMember>& rhs)
{
    if (lhs.size() != rhs.size()) {
        return false;
    }
    for (size_t i = 0; i < lhs.size(); ++i) {
        if (lhs[i].note_commitment != rhs[i].note_commitment ||
            lhs[i].account_leaf_commitment != rhs[i].account_leaf_commitment ||
            lhs[i].public_key.pk != rhs[i].public_key.pk ||
            lhs[i].public_key.A != rhs[i].public_key.A ||
            lhs[i].public_coin.t0 != rhs[i].public_coin.t0 ||
            lhs[i].public_coin.t_msg != rhs[i].public_coin.t_msg) {
            return false;
        }
    }
    return true;
}

std::vector<std::vector<smile2::CTPublicAccount>> BuildAccountRings(
    Span<const smile2::wallet::SmileRingMember> ring_members,
    Span<const shielded::v2::SpendDescription> spends)
{
    std::vector<std::vector<smile2::CTPublicAccount>> account_rings;
    account_rings.reserve(spends.size());
    for (const auto& spend : spends) {
        std::vector<smile2::CTPublicAccount> ring;
        ring.reserve(ring_members.size());
        for (const auto& member : ring_members) {
            ring.push_back({member.note_commitment,
                            member.public_key,
                            member.public_coin,
                            spend.account_leaf_commitment});
        }
        account_rings.push_back(std::move(ring));
    }
    return account_rings;
}

std::vector<CAmount> DistributeOutputValues(CAmount total_output_value, size_t output_count)
{
    if (output_count == 0) {
        throw std::runtime_error("output_count must be non-zero");
    }
    const CAmount quotient = total_output_value / static_cast<CAmount>(output_count);
    const CAmount remainder = total_output_value % static_cast<CAmount>(output_count);
    if (quotient <= 0) {
        throw std::runtime_error("output values underflowed below positive note amounts");
    }

    std::vector<CAmount> values(output_count, quotient);
    for (size_t i = 0; i < static_cast<size_t>(remainder); ++i) {
        values[i] += 1;
    }
    return values;
}

ScenarioFixture BuildScenarioFixture(const RuntimeScenarioConfig& config,
                                     CAmount fee_sat,
                                     int32_t validation_height)
{
    if (config.spend_count > MAX_DIRECT_SPENDS) {
        throw std::runtime_error("spend_count must be within MAX_DIRECT_SPENDS");
    }
    if (config.output_count == 0 || config.output_count > MAX_DIRECT_OUTPUTS) {
        throw std::runtime_error("output_count must be within MAX_DIRECT_OUTPUTS");
    }
    if (fee_sat < 0 || !MoneyRange(fee_sat)) {
        throw std::runtime_error("fee_sat must be a valid non-negative amount");
    }
    if (config.spend_count > shielded::lattice::RING_SIZE) {
        throw std::runtime_error("spend_count exceeds ring size");
    }

    const uint32_t scenario_id = ScenarioId(config);
    ScenarioFixture fixture;
    fixture.config = config;
    fixture.validation_height = validation_height;
    fixture.fee_sat = fee_sat;
    fixture.spending_key.assign(32, 0x42);
    fixture.rng_entropy = DeriveSeed<32>("BTX_ShieldedV2_SendRuntime_Rng", scenario_id, 0);
    fixture.tx_template.version = CTransaction::CURRENT_VERSION;
    fixture.tx_template.nLockTime = 17 + static_cast<uint32_t>(config.spend_count + config.output_count);

    if (IsProoflessDepositScenario(config)) {
        fixture.tx_template.vin.emplace_back(
            COutPoint{Txid::FromUint256(DeterministicUint256("BTX_ShieldedV2_SendRuntime_DepositInput",
                                                            scenario_id,
                                                            0)),
                      0});
    }

    std::vector<ShieldedNote> input_notes;
    input_notes.reserve(config.spend_count);
    for (size_t i = 0; i < config.spend_count; ++i) {
        input_notes.push_back(BuildInputNote(scenario_id, static_cast<uint32_t>(i)));
        fixture.total_input_value += input_notes.back().value;
    }
    if (!IsProoflessDepositScenario(config) && fixture.total_input_value <= fee_sat) {
        throw std::runtime_error("input value does not cover fee");
    }
    if (!IsProoflessDepositScenario(config)) {
        fixture.total_output_value = fixture.total_input_value - fee_sat;
    }

    std::vector<uint256> input_chain_commitments(config.spend_count);
    std::map<uint256, smile2::CompactPublicAccount> smile_public_accounts;
    std::map<uint256, uint256> account_leaf_commitments;
    if (!IsProoflessDepositScenario(config)) {
        for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
            const ShieldedNote& ring_note = i < input_notes.size()
                ? input_notes[i]
                : BuildRingDecoyNote(scenario_id, static_cast<uint32_t>(i));
            auto account = smile2::wallet::BuildCompactPublicAccountFromNote(
                smile2::wallet::SMILE_GLOBAL_SEED,
                ring_note);
            if (!account.has_value()) {
                throw std::runtime_error("failed to build SMILE compact public account for ring member");
            }
            const uint256 chain_commitment = smile2::ComputeCompactPublicAccountHash(*account);
            const auto account_leaf_commitment = shielded::registry::ComputeAccountLeafCommitmentFromNote(
                ring_note,
                chain_commitment,
                shielded::registry::MakeDirectSendAccountLeafHint());
            if (!account_leaf_commitment.has_value()) {
                throw std::runtime_error("failed to build direct-send account leaf commitment for ring member");
            }
            fixture.tree.Append(chain_commitment);
            smile_public_accounts.emplace(chain_commitment, *account);
            account_leaf_commitments.emplace(chain_commitment, *account_leaf_commitment);
            if (i < input_chain_commitments.size()) {
                input_chain_commitments[i] = chain_commitment;
            }
        }
    }
    fixture.smile_public_accounts =
        std::make_shared<const std::map<uint256, smile2::CompactPublicAccount>>(std::move(smile_public_accounts));
    fixture.account_leaf_commitments =
        std::make_shared<const std::map<uint256, uint256>>(std::move(account_leaf_commitments));

    std::vector<smile2::wallet::SmileRingMember> shared_smile_ring_members;
    std::vector<uint64_t> ring_positions;
    std::vector<uint256> ring_members;
    if (!IsProoflessDepositScenario(config)) {
        ring_positions = BuildRingPositions();
        ring_members = BuildRingMembers(fixture.tree, ring_positions);
        shared_smile_ring_members.reserve(ring_members.size());
        for (const uint256& commitment : ring_members) {
            const auto account_it = fixture.smile_public_accounts->find(commitment);
            if (account_it == fixture.smile_public_accounts->end()) {
                throw std::runtime_error("missing SMILE public account for ring member");
            }
            const auto leaf_it = fixture.account_leaf_commitments->find(commitment);
            if (leaf_it == fixture.account_leaf_commitments->end()) {
                throw std::runtime_error("missing account leaf commitment for ring member");
            }
            auto member = smile2::wallet::BuildRingMemberFromCompactPublicAccount(
                smile2::wallet::SMILE_GLOBAL_SEED,
                commitment,
                account_it->second,
                leaf_it->second);
            if (!member.has_value()) {
                throw std::runtime_error("failed to build canonical SMILE ring member");
            }
            shared_smile_ring_members.push_back(std::move(*member));
        }
    }

    fixture.spend_inputs.reserve(config.spend_count);
    for (size_t i = 0; i < config.spend_count; ++i) {
        V2SendSpendInput spend_input;
        spend_input.note = input_notes[i];
        spend_input.note_commitment = input_chain_commitments[i];
        spend_input.account_leaf_hint = shielded::registry::MakeDirectSendAccountLeafHint();
        spend_input.ring_positions = ring_positions;
        spend_input.ring_members = ring_members;
        spend_input.smile_ring_members = shared_smile_ring_members;
        spend_input.real_index = static_cast<uint32_t>(i);
        fixture.spend_inputs.push_back(std::move(spend_input));
    }
    if (!fixture.spend_inputs.empty()) {
        if (!::test::shielded::AttachAccountRegistryWitnesses(fixture.spend_inputs)) {
            throw std::runtime_error("failed to attach direct-send account registry witnesses");
        }
        if (!std::all_of(fixture.spend_inputs.begin(), fixture.spend_inputs.end(), [](const V2SendSpendInput& spend) {
                return spend.IsValid();
            })) {
            throw std::runtime_error("constructed invalid direct-send spend input");
        }
    }

    if (IsProoflessDepositScenario(config)) {
        fixture.total_output_value =
            static_cast<CAmount>(config.output_count) * (3 * COIN) +
            static_cast<CAmount>(config.output_count) * 1000;
    }
    const std::vector<CAmount> output_values =
        DistributeOutputValues(fixture.total_output_value, config.output_count);
    fixture.output_inputs.reserve(config.output_count);
    for (size_t i = 0; i < config.output_count; ++i) {
        const ShieldedNote note_template = BuildOutputNote(scenario_id, static_cast<uint32_t>(i), output_values[i]);
        const mlkem::KeyPair recipient = BuildRecipientKeyPair(scenario_id, static_cast<uint32_t>(i));
        const auto bound_note =
            EncryptNote(note_template, recipient.pk, scenario_id, static_cast<uint32_t>(i));
        const auto payload =
            shielded::v2::EncodeLegacyEncryptedNotePayload(bound_note.encrypted_note,
                                                           recipient.pk,
                                                           shielded::v2::ScanDomain::USER);
        if (!payload.has_value()) {
            throw std::runtime_error("failed to encode direct-send output payload");
        }

        V2SendOutputInput output_input;
        output_input.note_class = shielded::v2::NoteClass::USER;
        output_input.note = bound_note.note;
        output_input.encrypted_note = *payload;
        if (!output_input.IsValid()) {
            throw std::runtime_error("constructed invalid direct-send output input");
        }
        fixture.output_inputs.push_back(std::move(output_input));
    }

    return fixture;
}

uint64_t MeasureNanoseconds(const std::function<void()>& fn)
{
    const auto start = std::chrono::steady_clock::now();
    fn();
    const auto end = std::chrono::steady_clock::now();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
}

uint64_t Average(const std::vector<uint64_t>& values)
{
    if (values.empty()) return 0;
    const uint64_t total = std::accumulate(values.begin(), values.end(), uint64_t{0});
    return total / values.size();
}

uint64_t Median(std::vector<uint64_t> values)
{
    if (values.empty()) return 0;
    std::sort(values.begin(), values.end());
    const size_t mid = values.size() / 2;
    if ((values.size() % 2) == 1) {
        return values[mid];
    }
    return (values[mid - 1] + values[mid]) / 2;
}

UniValue BuildSummary(const std::vector<uint64_t>& values)
{
    UniValue summary(UniValue::VOBJ);
    summary.pushKV("count", static_cast<uint64_t>(values.size()));
    summary.pushKV("min_ns", values.empty() ? 0 : *std::min_element(values.begin(), values.end()));
    summary.pushKV("median_ns", Median(values));
    summary.pushKV("average_ns", Average(values));
    summary.pushKV("max_ns", values.empty() ? 0 : *std::max_element(values.begin(), values.end()));
    return summary;
}

std::optional<shielded::v2::V2SendBuildResult> BuildTransaction(const ScenarioFixture& fixture,
                                                                std::string& reject_reason)
{
    const auto& consensus = Params().GetConsensus();
    return shielded::v2::BuildV2SendTransaction(
        fixture.tx_template,
        fixture.tree.Root(),
        fixture.spend_inputs,
        fixture.output_inputs,
        fixture.fee_sat,
        fixture.spending_key,
        reject_reason,
        Span<const unsigned char>{fixture.rng_entropy.data(), fixture.rng_entropy.size()},
        &consensus,
        fixture.validation_height);
}

ScenarioMetrics MeasureScenarioMetrics(const CTransaction& tx, const RuntimeScenarioConfig& config)
{
    const auto* bundle = tx.shielded_bundle.GetV2Bundle();
    if (bundle == nullptr) {
        throw std::runtime_error("missing direct-send bundle");
    }

    ScenarioMetrics metrics;
    metrics.serialized_size_bytes = tx.GetTotalSize();
    metrics.tx_weight = GetTransactionWeight(tx);
    metrics.policy_weight = GetShieldedPolicyWeight(tx);
    metrics.proof_payload_bytes = bundle->proof_payload.size();
    metrics.usage = GetShieldedResourceUsage(tx.GetShieldedBundle());
    metrics.within_standard_policy_weight =
        metrics.policy_weight <= MAX_STANDARD_SHIELDED_POLICY_WEIGHT;
    metrics.standard_policy_weight_headroom = metrics.within_standard_policy_weight
        ? static_cast<uint64_t>(MAX_STANDARD_SHIELDED_POLICY_WEIGHT) -
              static_cast<uint64_t>(metrics.policy_weight)
        : 0;
    metrics.max_transactions_by_standard_policy =
        metrics.policy_weight > 0
            ? static_cast<uint64_t>(MAX_STANDARD_SHIELDED_POLICY_WEIGHT) /
                  static_cast<uint64_t>(metrics.policy_weight)
            : 0;

    metrics.max_transactions_by_serialized_size =
        metrics.serialized_size_bytes > 0 ? MAX_BLOCK_SERIALIZED_SIZE / metrics.serialized_size_bytes : 0;
    metrics.max_transactions_by_weight =
        metrics.tx_weight > 0 ? MAX_BLOCK_WEIGHT / metrics.tx_weight : 0;
    metrics.max_transactions_by_verify =
        metrics.usage.verify_units > 0
            ? ::Consensus::DEFAULT_MAX_BLOCK_SHIELDED_VERIFY_COST / metrics.usage.verify_units
            : 0;
    metrics.max_transactions_by_scan =
        metrics.usage.scan_units > 0
            ? ::Consensus::DEFAULT_MAX_BLOCK_SHIELDED_SCAN_UNITS / metrics.usage.scan_units
            : 0;
    metrics.max_transactions_by_tree_updates =
        metrics.usage.tree_update_units > 0
            ? ::Consensus::DEFAULT_MAX_BLOCK_SHIELDED_TREE_UPDATE_UNITS / metrics.usage.tree_update_units
            : 0;

    std::vector<std::pair<std::string, uint64_t>> limits{
        {"serialized_size", metrics.max_transactions_by_serialized_size},
        {"weight", metrics.max_transactions_by_weight},
    };
    if (metrics.usage.verify_units > 0) {
        limits.emplace_back("shielded_verify_units", metrics.max_transactions_by_verify);
    }
    if (metrics.usage.scan_units > 0) {
        limits.emplace_back("shielded_scan_units", metrics.max_transactions_by_scan);
    }
    if (metrics.usage.tree_update_units > 0) {
        limits.emplace_back("shielded_tree_update_units", metrics.max_transactions_by_tree_updates);
    }
    const auto best = std::min_element(limits.begin(),
                                       limits.end(),
                                       [](const auto& lhs, const auto& rhs) {
                                           return lhs.second < rhs.second;
                                       });
    metrics.block_binding_limit = best->first;
    metrics.max_transactions_per_block = best->second;
    metrics.max_spend_notes_per_block = metrics.max_transactions_per_block * config.spend_count;
    metrics.max_output_notes_per_block = metrics.max_transactions_per_block * config.output_count;
    return metrics;
}

void VerifyBuiltTransaction(const ScenarioFixture& fixture,
                           const shielded::v2::V2SendBuildResult& built,
                           const CTransaction& tx)
{
    const auto* bundle = tx.shielded_bundle.GetV2Bundle();
    if (bundle == nullptr || !std::holds_alternative<shielded::v2::SendPayload>(bundle->payload)) {
        throw std::runtime_error("direct-send proof check missing v2_send bundle");
    }

    const auto& consensus = Params().GetConsensus();
    const auto statement = shielded::v2::proof::DescribeV2SendStatement(tx,
                                                                        consensus,
                                                                        fixture.validation_height);
    std::string reject_reason;
    auto context = shielded::v2::proof::ParseV2SendProof(*bundle, statement, reject_reason);
    if (!context.has_value()) {
        throw std::runtime_error("direct-send proof parse failed: " + reject_reason);
    }
    const auto& payload = std::get<shielded::v2::SendPayload>(bundle->payload);
    if (payload.spends.empty()) {
        if (bundle->header.proof_envelope.proof_kind != shielded::v2::ProofKind::NONE ||
            !bundle->proof_payload.empty() ||
            payload.value_balance >= 0) {
            throw std::runtime_error("proofless deposit unexpectedly carried a spend proof");
        }
        if (!shielded::v2::proof::VerifyV2SendProof(*bundle, *context, std::vector<std::vector<uint256>>{})) {
            throw std::runtime_error("proofless deposit semantic verification failed");
        }
        for (size_t i = 0; i < payload.outputs.size(); ++i) {
            if (!payload.outputs[i].smile_account.has_value()) {
                throw std::runtime_error(strprintf("deposit output %u missing smile account",
                                                   static_cast<unsigned int>(i)));
            }
            const auto decoded = shielded::v2::DecodeLegacyEncryptedNotePayload(payload.outputs[i].encrypted_note);
            if (!decoded.has_value()) {
                throw std::runtime_error(strprintf("deposit output %u failed payload decode",
                                                   static_cast<unsigned int>(i)));
            }
            if (smile2::ComputeCompactPublicAccountHash(*payload.outputs[i].smile_account) !=
                    payload.outputs[i].note_commitment ||
                smile2::ComputeSmileOutputCoinHash(payload.outputs[i].smile_account->public_coin) !=
                    payload.outputs[i].value_commitment) {
                throw std::runtime_error(strprintf("deposit output/account binding mismatch at output=%u",
                                                   static_cast<unsigned int>(i)));
            }
        }
        return;
    }
    if (!context->witness.use_smile) {
        throw std::runtime_error("direct-send proof context regressed to non-SMILE witness");
    }
    if (context->witness.smile_proof_bytes != built.witness.smile_proof_bytes) {
        throw std::runtime_error("direct-send SMILE proof bytes changed across witness serialization");
    }
    auto bound_nullifiers = shielded::v2::proof::ExtractBoundNullifiers(*context,
                                                                        payload.spends.size(),
                                                                        payload.outputs.size(),
                                                                        reject_reason);
    if (!bound_nullifiers.has_value()) {
        throw std::runtime_error("direct-send nullifier extraction failed: " + reject_reason);
    }
    for (size_t i = 0; i < payload.spends.size(); ++i) {
        if ((*bound_nullifiers)[i] != payload.spends[i].nullifier) {
            throw std::runtime_error(strprintf("direct-send bound nullifier mismatch at spend=%u",
                                               static_cast<unsigned int>(i)));
        }
    }
    for (size_t i = 0; i < payload.outputs.size(); ++i) {
        if (!payload.outputs[i].smile_account.has_value()) {
            throw std::runtime_error(strprintf("direct-send output %u missing smile account",
                                               static_cast<unsigned int>(i)));
        }
        const auto output_coin_hash =
            smile2::ComputeSmileOutputCoinHash(payload.outputs[i].smile_account->public_coin);
        if (smile2::ComputeCompactPublicAccountHash(*payload.outputs[i].smile_account) !=
                payload.outputs[i].note_commitment ||
            output_coin_hash != payload.outputs[i].value_commitment) {
            throw std::runtime_error(strprintf("direct-send output/account binding mismatch at output=%u",
                                               static_cast<unsigned int>(i)));
        }
    }

    auto smile_ring_members = shielded::v2::proof::BuildV2SendSmileRingMembers(*bundle,
                                                                                *context,
                                                                                fixture.tree,
                                                                                *fixture.smile_public_accounts,
                                                                                *fixture.account_leaf_commitments,
                                                                                reject_reason);
    if (!smile_ring_members.has_value()) {
        throw std::runtime_error("direct-send SMILE ring reconstruction failed: " + reject_reason);
    }
    if (smile_ring_members->empty() || smile_ring_members->front().empty()) {
        throw std::runtime_error("direct-send reconstructed empty SMILE ring");
    }
    if (!SmileRingMatches((*smile_ring_members)[0], fixture.spend_inputs[0].smile_ring_members)) {
        throw std::runtime_error("direct-send reconstructed SMILE ring differs from builder ring");
    }

    const auto& reference_ring = smile_ring_members->front();
    std::vector<smile2::BDLOPCommitment> shared_coin_ring;
    shared_coin_ring.reserve(reference_ring.size());
    for (const auto& member : reference_ring) {
        if (!member.IsValid()) {
            throw std::runtime_error("direct-send reconstructed invalid SMILE ring member");
        }
        shared_coin_ring.push_back(member.public_coin);
    }
    for (size_t spend_index = 1; spend_index < smile_ring_members->size(); ++spend_index) {
        if ((*smile_ring_members)[spend_index].size() != reference_ring.size()) {
            throw std::runtime_error("direct-send reconstructed non-shared SMILE ring size");
        }
        for (size_t i = 0; i < reference_ring.size(); ++i) {
            if ((*smile_ring_members)[spend_index][i].note_commitment != reference_ring[i].note_commitment ||
                (*smile_ring_members)[spend_index][i].account_leaf_commitment !=
                    reference_ring[i].account_leaf_commitment) {
                throw std::runtime_error("direct-send reconstructed non-shared SMILE ring commitment");
            }
        }
    }

    smile2::CTPublicData pub;
    pub.anon_set = smile2::wallet::BuildAnonymitySet(
        Span<const smile2::wallet::SmileRingMember>{reference_ring.data(), reference_ring.size()});
    pub.coin_rings.assign(payload.spends.size(), shared_coin_ring);
    pub.account_rings = BuildAccountRings(
        Span<const smile2::wallet::SmileRingMember>{reference_ring.data(), reference_ring.size()},
        Span<const shielded::v2::SpendDescription>{payload.spends.data(), payload.spends.size()});

    std::vector<smile2::BDLOPCommitment> output_coins;
    output_coins.reserve(payload.outputs.size());
    for (const auto& output : payload.outputs) {
        output_coins.push_back(output.smile_account->public_coin);
    }

    const bool bind_anonset_context = consensus.IsShieldedMatRiCTDisabled(fixture.validation_height);
    if (auto verify_err = smile2::VerifySmile2CTFromBytes(context->witness.smile_proof_bytes,
                                                          payload.spends.size(),
                                                          payload.outputs.size(),
                                                          output_coins,
                                                          pub,
                                                          payload.fee,
                                                          /*reject_rice_codec=*/false,
                                                          bind_anonset_context);
        verify_err.has_value()) {
        throw std::runtime_error("direct-send SMILE proof verification failed: " + *verify_err);
    }
}

UniValue BuildRuntimeConfigJson(const RuntimeReportConfig& config)
{
    UniValue runtime_config(UniValue::VOBJ);
    runtime_config.pushKV("warmup_iterations", static_cast<uint64_t>(config.warmup_iterations));
    runtime_config.pushKV("measured_iterations", static_cast<uint64_t>(config.measured_iterations));
    runtime_config.pushKV("fee_sat", static_cast<int64_t>(config.fee_sat));
    runtime_config.pushKV("validation_surface", ValidationSurfaceName(config.validation_surface));
    runtime_config.pushKV("duration_unit", "nanoseconds");
    runtime_config.pushKV("clock", "steady_clock");

    UniValue requested(UniValue::VARR);
    for (const auto& scenario : config.scenarios) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("scenario_kind", ScenarioKindName(scenario));
        entry.pushKV("spend_count", static_cast<uint64_t>(scenario.spend_count));
        entry.pushKV("output_count", static_cast<uint64_t>(scenario.output_count));
        requested.push_back(std::move(entry));
    }
    runtime_config.pushKV("requested_scenarios", std::move(requested));
    return runtime_config;
}

UniValue BuildLimitsJson()
{
    UniValue limits(UniValue::VOBJ);
    limits.pushKV("ring_size", static_cast<uint64_t>(shielded::lattice::RING_SIZE));
    limits.pushKV("max_direct_spends", static_cast<uint64_t>(MAX_DIRECT_SPENDS));
    limits.pushKV("max_direct_outputs", static_cast<uint64_t>(MAX_DIRECT_OUTPUTS));
    limits.pushKV("max_block_serialized_size", static_cast<uint64_t>(MAX_BLOCK_SERIALIZED_SIZE));
    limits.pushKV("max_block_weight", static_cast<uint64_t>(MAX_BLOCK_WEIGHT));
    limits.pushKV("max_block_shielded_verify_units",
                  static_cast<uint64_t>(::Consensus::DEFAULT_MAX_BLOCK_SHIELDED_VERIFY_COST));
    limits.pushKV("max_block_shielded_scan_units",
                  static_cast<uint64_t>(::Consensus::DEFAULT_MAX_BLOCK_SHIELDED_SCAN_UNITS));
    limits.pushKV("max_block_shielded_tree_update_units",
                  static_cast<uint64_t>(::Consensus::DEFAULT_MAX_BLOCK_SHIELDED_TREE_UPDATE_UNITS));
    limits.pushKV("max_standard_shielded_policy_weight",
                  static_cast<uint64_t>(MAX_STANDARD_SHIELDED_POLICY_WEIGHT));
    return limits;
}

} // namespace

UniValue BuildRuntimeReport(const RuntimeReportConfig& config)
{
    if (config.measured_iterations == 0) {
        throw std::runtime_error("measured_iterations must be non-zero");
    }
    if (config.scenarios.empty()) {
        throw std::runtime_error("scenarios must be non-empty");
    }
    if (config.fee_sat < 0 || !MoneyRange(config.fee_sat)) {
        throw std::runtime_error("fee_sat must be a valid non-negative amount");
    }

    const auto& consensus = Params().GetConsensus();
    const int32_t validation_height = ResolveValidationHeight(config.validation_surface, consensus);

    UniValue scenarios(UniValue::VARR);
    for (const auto& scenario_config : config.scenarios) {
        if (config.validation_surface == RuntimeValidationSurface::POSTFORK &&
            IsProoflessDepositScenario(scenario_config)) {
            throw std::runtime_error("proofless transparent deposit scenarios are prefork-only");
        }
        const ScenarioFixture fixture = BuildScenarioFixture(scenario_config,
                                                             config.fee_sat,
                                                             validation_height);

        for (size_t i = 0; i < config.warmup_iterations; ++i) {
            std::string reject_reason;
            const auto built = BuildTransaction(fixture, reject_reason);
            if (!built.has_value()) {
                throw std::runtime_error("direct-send warmup build failed: " + reject_reason);
            }
            if (!IsProoflessDepositScenario(scenario_config) && !built->witness.use_smile) {
                throw std::runtime_error("direct-send warmup regressed to non-SMILE proof path");
            }
            VerifyBuiltTransaction(fixture, *built, CTransaction{built->tx});
        }

        std::vector<uint64_t> build_times_ns;
        std::vector<uint64_t> proof_check_times_ns;
        build_times_ns.reserve(config.measured_iterations);
        proof_check_times_ns.reserve(config.measured_iterations);

        UniValue measurements(UniValue::VARR);
        std::optional<ScenarioMetrics> metrics;

        for (size_t i = 0; i < config.measured_iterations; ++i) {
            std::optional<shielded::v2::V2SendBuildResult> built;
            std::string build_reject_reason;
            const uint64_t build_ns = MeasureNanoseconds([&] {
                built = BuildTransaction(fixture, build_reject_reason);
                if (!built.has_value()) {
                    throw std::runtime_error("direct-send build failed: " + build_reject_reason);
                }
                if (!IsProoflessDepositScenario(scenario_config) && !built->witness.use_smile) {
                    throw std::runtime_error("direct-send benchmark regressed to non-SMILE proof path");
                }
            });

            const CTransaction tx{built->tx};
            if (!metrics.has_value()) {
                metrics = MeasureScenarioMetrics(tx, scenario_config);
            }

            const uint64_t proof_check_ns = MeasureNanoseconds([&] {
                VerifyBuiltTransaction(fixture, *built, tx);
            });

            build_times_ns.push_back(build_ns);
            proof_check_times_ns.push_back(proof_check_ns);

            UniValue measurement(UniValue::VOBJ);
            measurement.pushKV("sample_index", static_cast<uint64_t>(i));
            measurement.pushKV("build_ns", build_ns);
            measurement.pushKV("proof_check_ns", proof_check_ns);
            measurement.pushKV("full_pipeline_ns", build_ns + proof_check_ns);
            measurement.pushKV("serialized_size_bytes", static_cast<uint64_t>(tx.GetTotalSize()));
            measurement.pushKV("proof_payload_bytes",
                               static_cast<uint64_t>(tx.shielded_bundle.GetV2Bundle()->proof_payload.size()));
            measurements.push_back(std::move(measurement));
        }

        if (!metrics.has_value()) {
            throw std::runtime_error("no measurements were recorded");
        }

        UniValue scenario(UniValue::VOBJ);
        scenario.pushKV("scenario_kind", ScenarioKindName(scenario_config));
        scenario.pushKV("spend_count", static_cast<uint64_t>(scenario_config.spend_count));
        scenario.pushKV("output_count", static_cast<uint64_t>(scenario_config.output_count));
        scenario.pushKV("transparent_input_count", static_cast<uint64_t>(fixture.tx_template.vin.size()));
        scenario.pushKV("transparent_output_count", static_cast<uint64_t>(fixture.tx_template.vout.size()));
        scenario.pushKV("ring_size", static_cast<uint64_t>(shielded::lattice::RING_SIZE));
        scenario.pushKV("tree_size", fixture.tree.Size());
        scenario.pushKV("total_input_value_sat", static_cast<int64_t>(fixture.total_input_value));
        scenario.pushKV("total_output_value_sat", static_cast<int64_t>(fixture.total_output_value));
        scenario.pushKV("fee_sat", static_cast<int64_t>(fixture.fee_sat));

        UniValue tx_shape(UniValue::VOBJ);
        tx_shape.pushKV("serialized_size_bytes", metrics->serialized_size_bytes);
        tx_shape.pushKV("tx_weight", metrics->tx_weight);
        tx_shape.pushKV("shielded_policy_weight", metrics->policy_weight);
        tx_shape.pushKV("proof_payload_bytes", metrics->proof_payload_bytes);
        scenario.pushKV("tx_shape", std::move(tx_shape));

        UniValue usage(UniValue::VOBJ);
        usage.pushKV("verify_units", metrics->usage.verify_units);
        usage.pushKV("scan_units", metrics->usage.scan_units);
        usage.pushKV("tree_update_units", metrics->usage.tree_update_units);
        scenario.pushKV("resource_usage", std::move(usage));

        UniValue relay_policy(UniValue::VOBJ);
        relay_policy.pushKV("within_standard_policy_weight", metrics->within_standard_policy_weight);
        relay_policy.pushKV("standard_policy_weight_headroom", metrics->standard_policy_weight_headroom);
        relay_policy.pushKV("max_transactions_by_standard_policy_weight",
                            metrics->max_transactions_by_standard_policy);
        scenario.pushKV("relay_policy", std::move(relay_policy));

        UniValue block_capacity(UniValue::VOBJ);
        block_capacity.pushKV("binding_limit", metrics->block_binding_limit);
        block_capacity.pushKV("max_transactions_by_serialized_size",
                              metrics->max_transactions_by_serialized_size);
        block_capacity.pushKV("max_transactions_by_weight", metrics->max_transactions_by_weight);
        block_capacity.pushKV("max_transactions_by_shielded_verify_units",
                              metrics->max_transactions_by_verify);
        block_capacity.pushKV("max_transactions_by_shielded_scan_units",
                              metrics->max_transactions_by_scan);
        block_capacity.pushKV("max_transactions_by_shielded_tree_update_units",
                              metrics->max_transactions_by_tree_updates);
        block_capacity.pushKV("max_transactions_per_block", metrics->max_transactions_per_block);
        block_capacity.pushKV("max_spend_notes_per_block", metrics->max_spend_notes_per_block);
        block_capacity.pushKV("max_output_notes_per_block", metrics->max_output_notes_per_block);
        scenario.pushKV("block_capacity", std::move(block_capacity));

        scenario.pushKV("build_summary", BuildSummary(build_times_ns));
        scenario.pushKV("proof_check_summary", BuildSummary(proof_check_times_ns));
        scenario.pushKV("measurements", std::move(measurements));
        scenarios.push_back(std::move(scenario));
    }

    UniValue report(UniValue::VOBJ);
    report.pushKV("format_version", 1);
    report.pushKV("report_kind", "v2_send_throughput_runtime");
    report.pushKV("runtime_config", BuildRuntimeConfigJson(config));
    report.pushKV("limits", BuildLimitsJson());
    report.pushKV("scenarios", std::move(scenarios));
    return report;
}

} // namespace btx::test::shieldedv2send

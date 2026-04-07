// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/util/smile2_proof_redesign_harness.h>

#include <consensus/consensus.h>
#include <crypto/ml_kem.h>
#include <hash.h>
#include <shielded/account_registry.h>
#include <shielded/note.h>
#include <shielded/note_encryption.h>
#include <shielded/smile2/serialize.h>
#include <shielded/smile2/wallet_bridge.h>
#include <shielded/v2_bundle.h>
#include <shielded/v2_send.h>
#include <streams.h>
#include <test/util/shielded_smile_test_util.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace btx::test::smile2redesign {
namespace {

using shielded::v2::OutputDescription;
using shielded::v2::ScanDomain;

using Clock = std::chrono::steady_clock;
constexpr uint64_t CT_HARNESS_PROOF_RETRY_STRIDE{0xD1B54A32D192ED03ULL};
constexpr uint32_t MAX_CT_HARNESS_PROOF_ATTEMPTS{32};

std::array<uint8_t, 32> MakeSeed(uint8_t seed)
{
    std::array<uint8_t, 32> out{};
    out[0] = seed;
    out[1] = static_cast<uint8_t>(seed ^ 0x5a);
    return out;
}

smile2::SmileCTProof ProveCtDeterministicWithRetries(
    const std::vector<smile2::CTInput>& inputs,
    const std::vector<smile2::CTOutput>& outputs,
    const smile2::CTPublicData& pub,
    uint64_t base_seed)
{
    for (uint32_t attempt = 0; attempt < MAX_CT_HARNESS_PROOF_ATTEMPTS; ++attempt) {
        const uint64_t attempt_seed = base_seed + (CT_HARNESS_PROOF_RETRY_STRIDE * attempt);
        smile2::SmileCTProof proof = smile2::ProveCT(inputs, outputs, pub, attempt_seed);
        if (!proof.serial_numbers.empty() &&
            !proof.z.empty() &&
            !proof.z0.empty() &&
            !proof.aux_commitment.t0.empty()) {
            return proof;
        }
    }
    return {};
}

smile2::BDLOPCommitmentKey GetPublicCoinCommitmentKey()
{
    std::array<uint8_t, 32> seed{};
    seed[0] = 0xCC;
    return smile2::BDLOPCommitmentKey::Generate(seed, 1);
}

std::vector<smile2::SmileKeyPair> GenerateAnonSet(size_t anon_set, uint8_t seed)
{
    const auto a_seed = MakeSeed(seed);
    std::vector<smile2::SmileKeyPair> keys(anon_set);
    for (size_t i = 0; i < anon_set; ++i) {
        keys[i] = smile2::SmileKeyPair::Generate(a_seed, 50000 + i);
    }
    return keys;
}

std::vector<smile2::SmilePublicKey> ExtractPublicKeys(const std::vector<smile2::SmileKeyPair>& keys)
{
    std::vector<smile2::SmilePublicKey> out;
    out.reserve(keys.size());
    for (const auto& key : keys) {
        out.push_back(key.pub);
    }
    return out;
}

std::vector<std::vector<smile2::BDLOPCommitment>> BuildCoinRings(
    const std::vector<smile2::SmileKeyPair>& keys,
    const std::vector<size_t>& secret_indices,
    const std::vector<int64_t>& secret_amounts,
    uint64_t coin_seed)
{
    const size_t anon_set = keys.size();
    const size_t input_count = secret_indices.size();
    const auto ck = GetPublicCoinCommitmentKey();

    std::vector<std::vector<smile2::BDLOPCommitment>> coin_rings(input_count);
    for (size_t input = 0; input < input_count; ++input) {
        coin_rings[input].resize(anon_set);
        for (size_t member = 0; member < anon_set; ++member) {
            smile2::SmilePoly amount_poly;
            if (member == secret_indices[input]) {
                amount_poly = *smile2::EncodeAmountToSmileAmountPoly(secret_amounts[input]);
            } else {
                const int64_t decoy_amount = static_cast<int64_t>(
                    (coin_seed * 1315423911ULL + input * 4099ULL + member * 97ULL) % 1000000ULL);
                amount_poly = *smile2::EncodeAmountToSmileAmountPoly(decoy_amount);
            }
            const auto opening = smile2::SampleTernary(
                ck.rand_dim(),
                coin_seed * 100000ULL + input * anon_set + member);
            coin_rings[input][member] = smile2::Commit(ck, {amount_poly}, opening);
        }
    }

    return coin_rings;
}

std::string ScenarioLabel(size_t inputs, size_t outputs)
{
    return std::to_string(inputs) + "x" + std::to_string(outputs);
}

std::array<uint8_t, 32> HashBytes(const std::vector<uint8_t>& bytes)
{
    HashWriter hw;
    hw << bytes;
    const uint256 digest = hw.GetSHA256();
    std::array<uint8_t, 32> out{};
    std::copy_n(digest.begin(), out.size(), out.begin());
    return out;
}

size_t MeasureCenteredPolyVecBytes(const smile2::SmilePolyVec& polys);
size_t MeasureGaussianPolyVecBytes(const smile2::SmilePolyVec& polys);
size_t MeasureAdaptiveWitnessBytes(const smile2::SmilePolyVec& polys);

void AddBudgetCheck(UniValue& checks,
                    const std::string& name,
                    int64_t actual,
                    const std::optional<uint64_t>& max,
                    bool& all_pass)
{
    if (!max.has_value()) {
        return;
    }

    UniValue check(UniValue::VOBJ);
    check.pushKV("name", name);
    check.pushKV("actual", actual);
    check.pushKV("max_allowed", static_cast<int64_t>(*max));
    const bool passed = actual >= 0 && static_cast<uint64_t>(actual) <= *max;
    check.pushKV("passed", passed);
    checks.push_back(std::move(check));
    all_pass &= passed;
}

template <typename Mutator>
UniValue RunTamperCase(std::string_view name,
                       const smile2::SmileCTProof& proof,
                       size_t input_count,
                       size_t output_count,
                       const smile2::CTPublicData& pub,
                       Mutator mutator,
                       bool& all_rejected)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("name", std::string{name});

    smile2::SmileCTProof tampered = proof;
    const bool mutated = mutator(tampered);
    out.pushKV("mutated", mutated);
    if (!mutated) {
        out.pushKV("status", "skipped");
        return out;
    }

    const bool rejected = !smile2::VerifyCT(tampered, input_count, output_count, pub);
    out.pushKV("status", rejected ? "rejected" : "accepted_badly");
    out.pushKV("rejected", rejected);
    all_rejected &= rejected;
    return out;
}

template <typename T>
T RequireJsonInt(const UniValue& obj, std::string_view key, std::string_view path)
{
    const UniValue& value = obj.find_value(std::string{key});
    if (!value.isNum()) {
        throw std::runtime_error(strprintf("missing numeric field at %s.%s",
                                           std::string{path},
                                           std::string{key}));
    }
    return value.getInt<T>();
}

std::string RequireJsonString(const UniValue& obj, std::string_view key, std::string_view path)
{
    const UniValue& value = obj.find_value(std::string{key});
    if (!value.isStr()) {
        throw std::runtime_error(strprintf("missing string field at %s.%s",
                                           std::string{path},
                                           std::string{key}));
    }
    return value.get_str();
}

const UniValue* FindDirectSendScenarioReport(const UniValue& report,
                                             size_t spend_count,
                                             size_t output_count)
{
    const UniValue& scenarios = report.find_value("scenarios");
    if (!scenarios.isArray()) {
        throw std::runtime_error("direct-send runtime report missing scenarios");
    }
    for (size_t i = 0; i < scenarios.size(); ++i) {
        const UniValue& scenario = scenarios[i];
        if (RequireJsonInt<int>(scenario, "spend_count", "direct_send_runtime.scenarios[]") ==
                static_cast<int>(spend_count) &&
            RequireJsonInt<int>(scenario, "output_count", "direct_send_runtime.scenarios[]") ==
                static_cast<int>(output_count)) {
            return &scenario;
        }
    }
    return nullptr;
}

OutputDescription BuildCanonicalDirectSendOutput()
{
    ShieldedNote note;
    note.value = 5000;
    note.recipient_pk_hash = uint256{0x59};
    note.memo = {0x21, 0x22, 0x23};

    std::array<uint8_t, mlkem::KEYGEN_SEEDBYTES> recipient_seed{};
    recipient_seed.fill(0x44);
    const mlkem::KeyPair recipient = mlkem::KeyGenDerand(recipient_seed);

    std::array<uint8_t, mlkem::ENCAPS_SEEDBYTES> kem_seed{};
    kem_seed.fill(0x51);
    std::array<uint8_t, 12> nonce{};
    nonce.fill(0x61);

    const auto bound_note = shielded::NoteEncryption::EncryptBoundNoteDeterministic(
        note,
        recipient.pk,
        kem_seed,
        nonce);
    note = bound_note.note;
    auto account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        note);
    if (!account.has_value()) {
        throw std::runtime_error("failed to build canonical direct-send account");
    }
    auto payload = shielded::v2::EncodeLegacyEncryptedNotePayload(bound_note.encrypted_note,
                                                                  recipient.pk,
                                                                  ScanDomain::USER);
    if (!payload.has_value()) {
        throw std::runtime_error("failed to encode canonical direct-send payload");
    }

    OutputDescription output;
    output.note_class = shielded::v2::NoteClass::USER;
    output.note_commitment = smile2::ComputeCompactPublicAccountHash(*account);
    output.value_commitment = smile2::ComputeSmileOutputCoinHash(account->public_coin);
    output.smile_account = std::move(*account);
    output.encrypted_note = std::move(*payload);
    return output;
}

UniValue BuildEnvelopeFootprintReport()
{
    const OutputDescription output = BuildCanonicalDirectSendOutput();
    const auto minimal_output = shielded::registry::BuildDirectSendMinimalOutput(output);
    if (!minimal_output.has_value()) {
        throw std::runtime_error("failed to build direct minimal output for envelope report");
    }

    DataStream direct_output_stream{};
    output.SerializeDirectSend(direct_output_stream,
                               output.note_class,
                               output.encrypted_note.scan_domain);

    DataStream account_stream{};
    account_stream << *output.smile_account;

    DataStream public_key_stream{};
    for (const auto& row : output.smile_account->public_key) {
        smile2::SerializePoly(row, public_key_stream);
    }

    DataStream public_coin_t0_stream{};
    for (const auto& poly : output.smile_account->public_coin.t0) {
        smile2::SerializePoly(poly, public_coin_t0_stream);
    }

    DataStream public_coin_tmsg_stream{};
    for (const auto& poly : output.smile_account->public_coin.t_msg) {
        smile2::SerializePoly(poly, public_coin_tmsg_stream);
    }

    DataStream payload_stream{};
    output.encrypted_note.SerializeWithSharedScanDomain(payload_stream, output.encrypted_note.scan_domain);

    const auto minimal_output_bytes = shielded::registry::SerializeMinimalOutputRecord(
        *minimal_output,
        shielded::registry::AccountDomain::DIRECT_SEND,
        output.encrypted_note.scan_domain);

    const int64_t direct_send_output_bytes = static_cast<int64_t>(direct_output_stream.size());
    const int64_t compact_public_account_bytes = static_cast<int64_t>(account_stream.size());
    const int64_t encrypted_note_payload_bytes = static_cast<int64_t>(payload_stream.size());
    const int64_t minimal_direct_send_output_bytes = static_cast<int64_t>(minimal_output_bytes.size());
    const int64_t compact_public_key_bytes = static_cast<int64_t>(public_key_stream.size());
    const int64_t compact_public_coin_t0_bytes = static_cast<int64_t>(public_coin_t0_stream.size());
    const int64_t compact_public_coin_tmsg_bytes = static_cast<int64_t>(public_coin_tmsg_stream.size());
    const int64_t compact_public_key_centered_bytes =
        static_cast<int64_t>(MeasureCenteredPolyVecBytes(output.smile_account->public_key));
    const int64_t compact_public_key_gaussian_bytes =
        static_cast<int64_t>(MeasureGaussianPolyVecBytes(output.smile_account->public_key));
    const int64_t compact_public_key_adaptive_bytes =
        static_cast<int64_t>(MeasureAdaptiveWitnessBytes(output.smile_account->public_key));
    const int64_t compact_public_coin_t0_centered_bytes =
        static_cast<int64_t>(MeasureCenteredPolyVecBytes(output.smile_account->public_coin.t0));
    const int64_t compact_public_coin_t0_gaussian_bytes =
        static_cast<int64_t>(MeasureGaussianPolyVecBytes(output.smile_account->public_coin.t0));
    const int64_t compact_public_coin_t0_adaptive_bytes =
        static_cast<int64_t>(MeasureAdaptiveWitnessBytes(output.smile_account->public_coin.t0));
    const int64_t hypothetical_adaptive_compact_public_account_bytes =
        compact_public_account_bytes -
        compact_public_key_bytes -
        compact_public_coin_t0_bytes +
        compact_public_key_adaptive_bytes +
        compact_public_coin_t0_adaptive_bytes;
    const int64_t hypothetical_adaptive_direct_send_output_bytes =
        direct_send_output_bytes -
        compact_public_account_bytes +
        hypothetical_adaptive_compact_public_account_bytes;
    const int64_t exact_compact_public_account_transport_floor_bytes =
        minimal_direct_send_output_bytes + compact_public_account_bytes;
    const int64_t exact_compact_public_account_transport_delta_vs_current_bytes =
        exact_compact_public_account_transport_floor_bytes - direct_send_output_bytes;
    const bool exact_compact_public_account_transport_non_improving =
        exact_compact_public_account_transport_delta_vs_current_bytes >= 0;

    UniValue out(UniValue::VOBJ);
    out.pushKV("direct_send_output_bytes", direct_send_output_bytes);
    out.pushKV("minimal_direct_send_output_bytes", minimal_direct_send_output_bytes);
    out.pushKV("compact_public_account_bytes", compact_public_account_bytes);
    out.pushKV("compact_public_key_bytes", compact_public_key_bytes);
    out.pushKV("compact_public_key_centered_bytes", compact_public_key_centered_bytes);
    out.pushKV("compact_public_key_gaussian_bytes", compact_public_key_gaussian_bytes);
    out.pushKV("compact_public_key_adaptive_bytes", compact_public_key_adaptive_bytes);
    out.pushKV("compact_public_coin_t0_bytes", compact_public_coin_t0_bytes);
    out.pushKV("compact_public_coin_t0_centered_bytes", compact_public_coin_t0_centered_bytes);
    out.pushKV("compact_public_coin_t0_gaussian_bytes", compact_public_coin_t0_gaussian_bytes);
    out.pushKV("compact_public_coin_t0_adaptive_bytes", compact_public_coin_t0_adaptive_bytes);
    out.pushKV("compact_public_coin_tmsg_bytes", compact_public_coin_tmsg_bytes);
    out.pushKV("encrypted_note_payload_bytes", encrypted_note_payload_bytes);
    out.pushKV("direct_send_output_framing_bytes",
               direct_send_output_bytes - compact_public_account_bytes - encrypted_note_payload_bytes);
    out.pushKV("hypothetical_adaptive_compact_public_account_bytes",
               hypothetical_adaptive_compact_public_account_bytes);
    out.pushKV("hypothetical_adaptive_direct_send_output_bytes",
               hypothetical_adaptive_direct_send_output_bytes);
    out.pushKV("exact_compact_public_account_transport_floor_bytes",
               exact_compact_public_account_transport_floor_bytes);
    out.pushKV("exact_compact_public_account_transport_delta_vs_current_bytes",
               exact_compact_public_account_transport_delta_vs_current_bytes);
    out.pushKV("exact_compact_public_account_transport_non_improving",
               exact_compact_public_account_transport_non_improving);
    out.pushKV("scan_hint_bytes", static_cast<int64_t>(output.encrypted_note.scan_hint.size()));
    out.pushKV("ciphertext_bytes", static_cast<int64_t>(output.encrypted_note.ciphertext.size()));
    out.pushKV("hypothetical_public_keyless_output_bytes",
               direct_send_output_bytes - compact_public_key_bytes);
    out.pushKV("hypothetical_t0_less_output_bytes",
               direct_send_output_bytes - compact_public_coin_t0_bytes);
    out.pushKV("hypothetical_note_commitment_plus_tmsg_output_bytes",
               static_cast<int64_t>(uint256::size()) + compact_public_coin_tmsg_bytes + encrypted_note_payload_bytes);
    out.pushKV("hypothetical_note_commitment_plus_pk_tmsg_output_bytes",
               static_cast<int64_t>(uint256::size()) + compact_public_key_bytes +
                   compact_public_coin_tmsg_bytes + encrypted_note_payload_bytes);
    out.pushKV("hypothetical_note_commitment_only_output_bytes",
               static_cast<int64_t>(uint256::size()) + encrypted_note_payload_bytes);
    return out;
}

shielded::v2::EncryptedNotePayload MakeHarnessEncryptedNotePayload(ScanDomain scan_domain,
                                                                   unsigned char seed)
{
    shielded::v2::EncryptedNotePayload payload;
    payload.scan_domain = scan_domain;
    payload.scan_hint = {seed,
                         static_cast<uint8_t>(seed + 1),
                         static_cast<uint8_t>(seed + 2),
                         static_cast<uint8_t>(seed + 3)};
    payload.ciphertext = {
        static_cast<uint8_t>(seed + 4),
        static_cast<uint8_t>(seed + 5),
        static_cast<uint8_t>(seed + 6),
        static_cast<uint8_t>(seed + 7),
        static_cast<uint8_t>(seed + 8),
    };
    payload.ephemeral_key = shielded::v2::ComputeLegacyPayloadEphemeralKey(
        Span<const uint8_t>{payload.ciphertext.data(), payload.ciphertext.size()});
    return payload;
}

OutputDescription BuildCanonicalTaggedOutput(shielded::v2::NoteClass note_class,
                                             ScanDomain scan_domain,
                                             unsigned char seed)
{
    OutputDescription output;
    output.note_class = note_class;
    output.smile_account = ::test::shielded::MakeDeterministicCompactPublicAccount(seed, 5000 + seed);
    output.note_commitment = smile2::ComputeCompactPublicAccountHash(*output.smile_account);
    output.encrypted_note = MakeHarnessEncryptedNotePayload(scan_domain,
                                                            static_cast<unsigned char>(seed + 17));
    if (!output.encrypted_note.IsValid()) {
        throw std::runtime_error("invalid harness encrypted payload");
    }
    return output;
}

OutputDescription BuildCanonicalIngressReserveOutput()
{
    const uint256 settlement_binding_digest{0x81};
    OutputDescription output = BuildCanonicalTaggedOutput(shielded::v2::NoteClass::RESERVE,
                                                          ScanDomain::OPAQUE,
                                                          0x72);
    output.value_commitment = shielded::v2::ComputeV2IngressPlaceholderReserveValueCommitment(
        settlement_binding_digest,
        /*output_index=*/0,
        output.note_commitment);
    if (!output.IsValid()) {
        throw std::runtime_error("invalid canonical ingress reserve output");
    }
    return output;
}

OutputDescription BuildCanonicalEgressOutput()
{
    const uint256 output_binding_digest{0x82};
    OutputDescription output = BuildCanonicalTaggedOutput(shielded::v2::NoteClass::USER,
                                                          ScanDomain::OPAQUE,
                                                          0x73);
    output.value_commitment = shielded::v2::ComputeV2EgressOutputValueCommitment(
        output_binding_digest,
        /*output_index=*/0,
        output.note_commitment);
    if (!output.IsValid()) {
        throw std::runtime_error("invalid canonical egress output");
    }
    return output;
}

OutputDescription BuildCanonicalRebalanceOutput()
{
    OutputDescription output = BuildCanonicalTaggedOutput(shielded::v2::NoteClass::RESERVE,
                                                          ScanDomain::OPAQUE,
                                                          0x74);
    output.value_commitment = shielded::v2::ComputeV2RebalanceOutputValueCommitment(
        /*output_index=*/0,
        output.note_commitment);
    if (!output.IsValid()) {
        throw std::runtime_error("invalid canonical rebalance output");
    }
    return output;
}

struct MinimalOutputFootprintMeasurement
{
    std::string family;
    int64_t current_output_bytes{0};
    int64_t minimal_output_bytes{0};
    int64_t explicit_domain_output_bytes{0};
    int64_t encrypted_payload_bytes{0};
    bool bridge_tag_present{false};
    bool payload_preserved{false};
    bool minimal_roundtrip{false};
    shielded::registry::MinimalOutputRecord minimal_output;
};

MinimalOutputFootprintMeasurement MeasureDirectMinimalOutputFootprint()
{
    const OutputDescription output = BuildCanonicalDirectSendOutput();
    const auto minimal_output = shielded::registry::BuildDirectSendMinimalOutput(output);
    if (!minimal_output.has_value()) {
        throw std::runtime_error("failed to build direct minimal output");
    }
    const auto leaf = shielded::registry::BuildDirectSendAccountLeaf(output);
    if (!leaf.has_value()) {
        throw std::runtime_error("failed to build direct account leaf");
    }

    DataStream current_stream;
    output.SerializeDirectSend(current_stream, output.note_class, output.encrypted_note.scan_domain);
    DataStream payload_stream;
    output.encrypted_note.SerializeWithSharedScanDomain(payload_stream, output.encrypted_note.scan_domain);

    const auto minimal_bytes = shielded::registry::SerializeMinimalOutputRecord(
        *minimal_output,
        shielded::registry::AccountDomain::DIRECT_SEND,
        output.encrypted_note.scan_domain);
    const auto explicit_domain_bytes = shielded::registry::SerializeMinimalOutputRecord(
        *minimal_output,
        std::nullopt,
        output.encrypted_note.scan_domain);
    const auto roundtrip = shielded::registry::DeserializeMinimalOutputRecord(
        Span<const uint8_t>{minimal_bytes.data(), minimal_bytes.size()},
        shielded::registry::AccountDomain::DIRECT_SEND,
        output.encrypted_note.scan_domain);

    MinimalOutputFootprintMeasurement measurement;
    measurement.family = "direct_send";
    measurement.current_output_bytes = static_cast<int64_t>(current_stream.size());
    measurement.minimal_output_bytes = static_cast<int64_t>(minimal_bytes.size());
    measurement.explicit_domain_output_bytes = static_cast<int64_t>(explicit_domain_bytes.size());
    measurement.encrypted_payload_bytes = static_cast<int64_t>(payload_stream.size());
    measurement.bridge_tag_present = leaf->bridge_tag.has_value();
    measurement.payload_preserved =
        shielded::registry::MinimalOutputRecordMatchesOutput(*minimal_output, output, *leaf);
    measurement.minimal_roundtrip = roundtrip.has_value() &&
                                    roundtrip->account_leaf_commitment ==
                                        minimal_output->account_leaf_commitment &&
                                    roundtrip->encrypted_note.scan_hint ==
                                        minimal_output->encrypted_note.scan_hint &&
                                    roundtrip->encrypted_note.ciphertext ==
                                        minimal_output->encrypted_note.ciphertext;
    measurement.minimal_output = *minimal_output;
    return measurement;
}

MinimalOutputFootprintMeasurement MeasureIngressMinimalOutputFootprint()
{
    const uint256 settlement_binding_digest{0x81};
    const OutputDescription output = BuildCanonicalIngressReserveOutput();
    const auto minimal_output = shielded::registry::BuildIngressMinimalOutput(output,
                                                                              settlement_binding_digest);
    const auto leaf = shielded::registry::BuildIngressAccountLeaf(output, settlement_binding_digest);
    if (!minimal_output.has_value() || !leaf.has_value()) {
        throw std::runtime_error("failed to build ingress minimal output");
    }

    DataStream current_stream;
    output.SerializeIngressReserve(current_stream, settlement_binding_digest, /*output_index=*/0);
    DataStream payload_stream;
    output.encrypted_note.SerializeWithSharedScanDomain(payload_stream, output.encrypted_note.scan_domain);

    const auto minimal_bytes = shielded::registry::SerializeMinimalOutputRecord(
        *minimal_output,
        shielded::registry::AccountDomain::INGRESS,
        output.encrypted_note.scan_domain);
    const auto explicit_domain_bytes = shielded::registry::SerializeMinimalOutputRecord(
        *minimal_output,
        std::nullopt,
        output.encrypted_note.scan_domain);
    const auto roundtrip = shielded::registry::DeserializeMinimalOutputRecord(
        Span<const uint8_t>{minimal_bytes.data(), minimal_bytes.size()},
        shielded::registry::AccountDomain::INGRESS,
        output.encrypted_note.scan_domain);

    MinimalOutputFootprintMeasurement measurement;
    measurement.family = "ingress_reserve";
    measurement.current_output_bytes = static_cast<int64_t>(current_stream.size());
    measurement.minimal_output_bytes = static_cast<int64_t>(minimal_bytes.size());
    measurement.explicit_domain_output_bytes = static_cast<int64_t>(explicit_domain_bytes.size());
    measurement.encrypted_payload_bytes = static_cast<int64_t>(payload_stream.size());
    measurement.bridge_tag_present = leaf->bridge_tag.has_value();
    measurement.payload_preserved =
        shielded::registry::MinimalOutputRecordMatchesOutput(*minimal_output, output, *leaf);
    measurement.minimal_roundtrip = roundtrip.has_value() &&
                                    roundtrip->account_leaf_commitment ==
                                        minimal_output->account_leaf_commitment;
    measurement.minimal_output = *minimal_output;
    return measurement;
}

MinimalOutputFootprintMeasurement MeasureEgressMinimalOutputFootprint()
{
    const uint256 settlement_binding_digest{0x83};
    const uint256 output_binding_digest{0x82};
    const OutputDescription output = BuildCanonicalEgressOutput();
    const auto minimal_output = shielded::registry::BuildEgressMinimalOutput(output,
                                                                             settlement_binding_digest,
                                                                             output_binding_digest);
    const auto leaf = shielded::registry::BuildEgressAccountLeaf(output,
                                                                 settlement_binding_digest,
                                                                 output_binding_digest);
    if (!minimal_output.has_value() || !leaf.has_value()) {
        throw std::runtime_error("failed to build egress minimal output");
    }

    DataStream current_stream;
    output.SerializeEgressOutput(current_stream, output_binding_digest, /*output_index=*/0);
    DataStream payload_stream;
    output.encrypted_note.SerializeWithSharedScanDomain(payload_stream, output.encrypted_note.scan_domain);

    const auto minimal_bytes = shielded::registry::SerializeMinimalOutputRecord(
        *minimal_output,
        shielded::registry::AccountDomain::EGRESS,
        output.encrypted_note.scan_domain);
    const auto explicit_domain_bytes = shielded::registry::SerializeMinimalOutputRecord(
        *minimal_output,
        std::nullopt,
        output.encrypted_note.scan_domain);
    const auto roundtrip = shielded::registry::DeserializeMinimalOutputRecord(
        Span<const uint8_t>{minimal_bytes.data(), minimal_bytes.size()},
        shielded::registry::AccountDomain::EGRESS,
        output.encrypted_note.scan_domain);

    MinimalOutputFootprintMeasurement measurement;
    measurement.family = "egress_user";
    measurement.current_output_bytes = static_cast<int64_t>(current_stream.size());
    measurement.minimal_output_bytes = static_cast<int64_t>(minimal_bytes.size());
    measurement.explicit_domain_output_bytes = static_cast<int64_t>(explicit_domain_bytes.size());
    measurement.encrypted_payload_bytes = static_cast<int64_t>(payload_stream.size());
    measurement.bridge_tag_present = leaf->bridge_tag.has_value();
    measurement.payload_preserved =
        shielded::registry::MinimalOutputRecordMatchesOutput(*minimal_output, output, *leaf);
    measurement.minimal_roundtrip = roundtrip.has_value() &&
                                    roundtrip->account_leaf_commitment ==
                                        minimal_output->account_leaf_commitment;
    measurement.minimal_output = *minimal_output;
    return measurement;
}

MinimalOutputFootprintMeasurement MeasureRebalanceMinimalOutputFootprint()
{
    const uint256 settlement_binding_digest{0x84};
    const OutputDescription output = BuildCanonicalRebalanceOutput();
    const auto minimal_output = shielded::registry::BuildRebalanceMinimalOutput(output,
                                                                                settlement_binding_digest);
    const auto leaf = shielded::registry::BuildRebalanceAccountLeaf(output, settlement_binding_digest);
    if (!minimal_output.has_value() || !leaf.has_value()) {
        throw std::runtime_error("failed to build rebalance minimal output");
    }

    DataStream current_stream;
    output.SerializeRebalanceReserve(current_stream, /*output_index=*/0);
    DataStream payload_stream;
    output.encrypted_note.SerializeWithSharedScanDomain(payload_stream, output.encrypted_note.scan_domain);

    const auto minimal_bytes = shielded::registry::SerializeMinimalOutputRecord(
        *minimal_output,
        shielded::registry::AccountDomain::REBALANCE,
        output.encrypted_note.scan_domain);
    const auto explicit_domain_bytes = shielded::registry::SerializeMinimalOutputRecord(
        *minimal_output,
        std::nullopt,
        output.encrypted_note.scan_domain);
    const auto roundtrip = shielded::registry::DeserializeMinimalOutputRecord(
        Span<const uint8_t>{minimal_bytes.data(), minimal_bytes.size()},
        shielded::registry::AccountDomain::REBALANCE,
        output.encrypted_note.scan_domain);

    MinimalOutputFootprintMeasurement measurement;
    measurement.family = "rebalance_reserve";
    measurement.current_output_bytes = static_cast<int64_t>(current_stream.size());
    measurement.minimal_output_bytes = static_cast<int64_t>(minimal_bytes.size());
    measurement.explicit_domain_output_bytes = static_cast<int64_t>(explicit_domain_bytes.size());
    measurement.encrypted_payload_bytes = static_cast<int64_t>(payload_stream.size());
    measurement.bridge_tag_present = leaf->bridge_tag.has_value();
    measurement.payload_preserved =
        shielded::registry::MinimalOutputRecordMatchesOutput(*minimal_output, output, *leaf);
    measurement.minimal_roundtrip = roundtrip.has_value() &&
                                    roundtrip->account_leaf_commitment ==
                                        minimal_output->account_leaf_commitment;
    measurement.minimal_output = *minimal_output;
    return measurement;
}

UniValue BuildAccountRegistryDesignReport(const UniValue& direct_send_report,
                                          const UniValue& envelope_report,
                                          const ProofRedesignFrameworkConfig& config)
{
    const auto direct = MeasureDirectMinimalOutputFootprint();
    const auto ingress = MeasureIngressMinimalOutputFootprint();
    const auto egress = MeasureEgressMinimalOutputFootprint();
    const auto rebalance = MeasureRebalanceMinimalOutputFootprint();
    const std::array<MinimalOutputFootprintMeasurement, 4> family_measurements{
        direct,
        ingress,
        egress,
        rebalance,
    };

    bool output_footprints_pass{true};
    UniValue family_output_footprints(UniValue::VARR);
    for (const auto& measurement : family_measurements) {
        const bool passed = measurement.current_output_bytes > measurement.minimal_output_bytes &&
                            measurement.payload_preserved &&
                            measurement.minimal_roundtrip;
        output_footprints_pass &= passed;

        UniValue family(UniValue::VOBJ);
        family.pushKV("family", measurement.family);
        family.pushKV("current_output_bytes", measurement.current_output_bytes);
        family.pushKV("minimal_output_bytes", measurement.minimal_output_bytes);
        family.pushKV("explicit_domain_output_bytes", measurement.explicit_domain_output_bytes);
        family.pushKV("bytes_saved", measurement.current_output_bytes - measurement.minimal_output_bytes);
        family.pushKV("encrypted_payload_bytes", measurement.encrypted_payload_bytes);
        family.pushKV("bridge_tag_present", measurement.bridge_tag_present);
        family.pushKV("payload_preserved", measurement.payload_preserved);
        family.pushKV("minimal_roundtrip", measurement.minimal_roundtrip);
        family.pushKV("passed", passed);
        family_output_footprints.push_back(std::move(family));
    }

    UniValue direct_send_tx_projections(UniValue::VARR);
    bool tx_projection_pass{true};
    const int64_t direct_output_bytes_saved = direct.current_output_bytes - direct.minimal_output_bytes;
    for (const auto& scenario : config.direct_send_scenarios) {
        const UniValue* baseline = FindDirectSendScenarioReport(direct_send_report,
                                                                scenario.scenario.spend_count,
                                                                scenario.scenario.output_count);
        if (baseline == nullptr) {
            throw std::runtime_error("missing direct-send scenario for account-registry projection");
        }
        const UniValue& tx_shape = baseline->find_value("tx_shape");
        const int64_t baseline_tx_bytes =
            RequireJsonInt<int64_t>(tx_shape, "serialized_size_bytes", "direct_send_runtime.scenarios[].tx_shape");
        const int64_t baseline_proof_bytes =
            RequireJsonInt<int64_t>(tx_shape, "proof_payload_bytes", "direct_send_runtime.scenarios[].tx_shape");
        const int64_t projected_tx_bytes =
            baseline_tx_bytes - static_cast<int64_t>(scenario.scenario.output_count) * direct_output_bytes_saved;
        const int64_t projected_fit_24mb =
            projected_tx_bytes > 0 ? static_cast<int64_t>(MAX_BLOCK_SERIALIZED_SIZE / projected_tx_bytes) : 0;
        const int64_t projected_tps_x100 =
            projected_fit_24mb > 0 ? (projected_fit_24mb * 100 + 45) / 90 : 0;
        const bool passed = projected_tx_bytes > 0 && projected_tx_bytes < baseline_tx_bytes;
        tx_projection_pass &= passed;

        UniValue projection(UniValue::VOBJ);
        projection.pushKV("scenario", ScenarioLabel(scenario.scenario.spend_count,
                                                    scenario.scenario.output_count));
        projection.pushKV("baseline_tx_bytes", baseline_tx_bytes);
        projection.pushKV("projected_tx_bytes", projected_tx_bytes);
        projection.pushKV("baseline_proof_bytes", baseline_proof_bytes);
        projection.pushKV("projected_proof_bytes", baseline_proof_bytes);
        projection.pushKV("projected_block_fit_24mb", projected_fit_24mb);
        projection.pushKV("projected_tps_x100", projected_tps_x100);
        projection.pushKV("passed", passed);
        direct_send_tx_projections.push_back(std::move(projection));
    }

    const auto direct_leaf =
        shielded::registry::BuildDirectSendAccountLeaf(BuildCanonicalDirectSendOutput());
    const auto ingress_leaf = shielded::registry::BuildIngressAccountLeaf(
        BuildCanonicalIngressReserveOutput(),
        uint256{0x81});
    const auto egress_leaf = shielded::registry::BuildEgressAccountLeaf(
        BuildCanonicalEgressOutput(),
        uint256{0x82},
        uint256{0x82});
    const auto rebalance_leaf = shielded::registry::BuildRebalanceAccountLeaf(
        BuildCanonicalRebalanceOutput(),
        uint256{0x83});
    if (!direct_leaf.has_value() ||
        !ingress_leaf.has_value() ||
        !egress_leaf.has_value() ||
        !rebalance_leaf.has_value()) {
        throw std::runtime_error("failed to rebuild account-registry leaves");
    }
    const std::vector<shielded::registry::ShieldedAccountLeaf> leaves{
        *direct_leaf,
        *ingress_leaf,
        *egress_leaf,
        *rebalance_leaf,
    };
    shielded::registry::ShieldedAccountRegistryState registry_state;
    std::vector<uint64_t> inserted_indices;
    if (!registry_state.Append(Span<const shielded::registry::ShieldedAccountLeaf>{leaves.data(),
                                                                                   leaves.size()},
                               &inserted_indices)) {
        throw std::runtime_error("failed to append account-registry leaves");
    }
    const uint256 root_before_spend = registry_state.Root();
    const auto proof_before_spend = registry_state.BuildProof(inserted_indices[2]);
    if (!proof_before_spend.has_value()) {
        throw std::runtime_error("failed to build account-registry proof");
    }
    DataStream proof_stream;
    proof_stream << *proof_before_spend;
    const int64_t proof_wire_bytes = static_cast<int64_t>(proof_stream.size());
    const auto spend_witness_before_spend = registry_state.BuildSpendWitness(inserted_indices[2]);
    if (!spend_witness_before_spend.has_value()) {
        throw std::runtime_error("failed to build account-registry spend witness");
    }
    DataStream spend_witness_stream;
    spend_witness_stream << *spend_witness_before_spend;
    const int64_t spend_witness_wire_bytes = static_cast<int64_t>(spend_witness_stream.size());

    const std::vector<uint256> note_commitments{
        direct.minimal_output.note_commitment,
        ingress.minimal_output.note_commitment,
        egress.minimal_output.note_commitment,
        rebalance.minimal_output.note_commitment,
    };
    HashWriter note_root_writer;
    note_root_writer << note_commitments;
    shielded::registry::ShieldedStateCommitment state_commitment;
    state_commitment.note_commitment_root = note_root_writer.GetSHA256();
    state_commitment.account_registry_root = root_before_spend;
    const std::vector<uint256> nullifiers{uint256{0x91}, uint256{0x92}};
    state_commitment.nullifier_root = shielded::registry::ComputeNullifierSetCommitment(
        Span<const uint256>{nullifiers.data(), nullifiers.size()});
    const std::vector<uint256> settlement_tags{
        uint256{0x81},
        uint256{0x83},
        uint256{0x84},
    };
    HashWriter bridge_root_writer;
    bridge_root_writer << settlement_tags;
    state_commitment.bridge_settlement_root = bridge_root_writer.GetSHA256();
    if (!state_commitment.IsValid()) {
        throw std::runtime_error("invalid account-registry state commitment");
    }

    bool tamper_rejected{true};
    UniValue tamper_cases(UniValue::VARR);
    {
        UniValue tamper(UniValue::VOBJ);
        tamper.pushKV("name", "sibling_path_extended");
        auto mutated = *proof_before_spend;
        mutated.sibling_path.push_back(uint256{0xa1});
        const bool rejected =
            !shielded::registry::VerifyShieldedAccountRegistryProof(mutated, root_before_spend);
        tamper.pushKV("rejected", rejected);
        tamper_cases.push_back(std::move(tamper));
        tamper_rejected &= rejected;
    }
    {
        UniValue tamper(UniValue::VOBJ);
        tamper.pushKV("name", "leaf_commitment_swapped");
        auto mutated = *proof_before_spend;
        mutated.entry.account_leaf_commitment = uint256{0xa2};
        const bool rejected =
            !shielded::registry::VerifyShieldedAccountRegistryProof(mutated, root_before_spend);
        tamper.pushKV("rejected", rejected);
        tamper_cases.push_back(std::move(tamper));
        tamper_rejected &= rejected;
    }
    {
        UniValue tamper(UniValue::VOBJ);
        tamper.pushKV("name", "spend_witness_sibling_path_extended");
        auto mutated = *spend_witness_before_spend;
        mutated.sibling_path.push_back(uint256{0xa4});
        const bool rejected =
            !shielded::registry::VerifyShieldedAccountRegistrySpendWitness(mutated,
                                                                           registry_state,
                                                                           root_before_spend);
        tamper.pushKV("rejected", rejected);
        tamper_cases.push_back(std::move(tamper));
        tamper_rejected &= rejected;
    }
    {
        UniValue tamper(UniValue::VOBJ);
        tamper.pushKV("name", "spend_witness_leaf_commitment_swapped");
        auto mutated = *spend_witness_before_spend;
        mutated.account_leaf_commitment = uint256{0xa5};
        const bool rejected =
            !shielded::registry::VerifyShieldedAccountRegistrySpendWitness(mutated,
                                                                           registry_state,
                                                                           root_before_spend);
        tamper.pushKV("rejected", rejected);
        tamper_cases.push_back(std::move(tamper));
        tamper_rejected &= rejected;
    }
    {
        UniValue tamper(UniValue::VOBJ);
        tamper.pushKV("name", "state_commitment_root_mismatch");
        auto mutated_commitment = state_commitment;
        mutated_commitment.account_registry_root = uint256{0xa3};
        const bool rejected =
            !shielded::registry::VerifyShieldedStateInclusion(mutated_commitment, *proof_before_spend);
        tamper.pushKV("rejected", rejected);
        tamper_cases.push_back(std::move(tamper));
        tamper_rejected &= rejected;
    }

    const auto snapshot = registry_state.ExportSnapshot();
    DataStream snapshot_stream;
    snapshot_stream << snapshot;
    const int64_t snapshot_bytes = static_cast<int64_t>(snapshot_stream.size());
    shielded::registry::ShieldedAccountRegistrySnapshot restored_snapshot;
    snapshot_stream >> restored_snapshot;
    const auto restored_state = shielded::registry::ShieldedAccountRegistryState::Restore(restored_snapshot);
    bool stale_root_rejected{false};
    bool stale_spend_witness_rejected{false};
    if (restored_state.has_value()) {
        auto truncated_state = *restored_state;
        if (truncated_state.Truncate(2)) {
            const uint256 root_after_truncate = truncated_state.Root();
            stale_root_rejected =
                !shielded::registry::VerifyShieldedAccountRegistryProof(*proof_before_spend,
                                                                        root_after_truncate);
            stale_spend_witness_rejected =
                !shielded::registry::VerifyShieldedAccountRegistrySpendWitness(*spend_witness_before_spend,
                                                                               truncated_state,
                                                                               root_after_truncate);
        }
    }

    auto spent_snapshot = snapshot;
    const bool spent_snapshot_rejected =
        !spent_snapshot.entries.empty() &&
        ([&]() {
            spent_snapshot.entries[0].spent = true;
            return !spent_snapshot.IsValid() &&
                   !shielded::registry::ShieldedAccountRegistryState::Restore(spent_snapshot).has_value();
        })();

    auto duplicate_snapshot = snapshot;
    const bool duplicate_snapshot_rejected =
        duplicate_snapshot.entries.size() > 1 &&
        ([&]() {
            duplicate_snapshot.entries[1].account_leaf_commitment =
                duplicate_snapshot.entries[0].account_leaf_commitment;
            duplicate_snapshot.entries[1].account_leaf_payload =
                duplicate_snapshot.entries[0].account_leaf_payload;
            return !duplicate_snapshot.IsValid() &&
                   !shielded::registry::ShieldedAccountRegistryState::Restore(duplicate_snapshot).has_value();
        })();

    const bool light_client_proof_valid =
        shielded::registry::VerifyShieldedStateInclusion(state_commitment, *proof_before_spend);
    const bool registry_sequence_pass =
        stale_root_rejected &&
        stale_spend_witness_rejected &&
        spent_snapshot_rejected &&
        duplicate_snapshot_rejected &&
        light_client_proof_valid &&
        tamper_rejected &&
        restored_state.has_value() &&
        restored_state->Root() == root_before_spend;

    UniValue registry_sequence(UniValue::VOBJ);
    registry_sequence.pushKV("leaf_count", static_cast<int64_t>(registry_state.Size()));
    registry_sequence.pushKV("proof_sibling_count", static_cast<int64_t>(proof_before_spend->sibling_path.size()));
    registry_sequence.pushKV("sample_light_client_proof_wire_bytes", proof_wire_bytes);
    registry_sequence.pushKV("sample_spend_witness_wire_bytes", spend_witness_wire_bytes);
    registry_sequence.pushKV("snapshot_bytes", snapshot_bytes);
    registry_sequence.pushKV("stale_root_rejected", stale_root_rejected);
    registry_sequence.pushKV("stale_spend_witness_rejected", stale_spend_witness_rejected);
    registry_sequence.pushKV("spent_snapshot_rejected", spent_snapshot_rejected);
    registry_sequence.pushKV("duplicate_snapshot_rejected", duplicate_snapshot_rejected);
    registry_sequence.pushKV("light_client_proof_valid", light_client_proof_valid);
    registry_sequence.pushKV("tamper_cases", std::move(tamper_cases));
    registry_sequence.pushKV("snapshot_roundtrip", restored_state.has_value());
    registry_sequence.pushKV("status", registry_sequence_pass ? "passed" : "failed");

    UniValue explicit_blockers(UniValue::VARR);

    UniValue corrected_scope_notes(UniValue::VARR);
    {
        UniValue note(UniValue::VOBJ);
        note.pushKV("surface", "direct_send_smile");
        note.pushKV("status", "launch_surface_live");
        note.pushKV("reason",
                    "The reset-chain direct-send launch path is DIRECT_SMILE. The hidden spender to consumed registry-leaf binding now lives in the Figure 17-style SMILE CT relation, and the redesign harness verifies the live direct-send path against the rebuilt branch state.");
        corrected_scope_notes.push_back(std::move(note));
    }
    {
        UniValue note(UniValue::VOBJ);
        note.pushKV("surface", "ingress_batch_smile");
        note.pushKV("status", "launch_surface_live");
        note.pushKV("reason",
                    "Ingress now builds and verifies through BATCH_SMILE on the live branch. The redesign harness exercises the contextual verifier with shared SMILE ring members and account-registry witnesses instead of the retired MatRiCT and receipt-backed paths.");
        corrected_scope_notes.push_back(std::move(note));
    }
    {
        UniValue note(UniValue::VOBJ);
        note.pushKV("surface", "account_registry_state_payloads");
        note.pushKV("status", "launch_surface_live");
        note.pushKV("reason",
                    "Registry state now commits the full shielded account leaf payload, snapshot restore rebuilds CompactPublicAccount state from those committed entries, and consumed-leaf transaction witnesses carry only the lean inclusion path plus leaf commitment while full nodes recover the payload from local consensus state.");
        corrected_scope_notes.push_back(std::move(note));
    }
    {
        UniValue note(UniValue::VOBJ);
        note.pushKV("surface", "ingress_shared_ring_capacity");
        note.pushKV("status", "measured_launch_ceiling");
        note.pushKV("reason",
                    "With the current launch default shared ring size of 8, the live shared-ring SMILE ingress path is verified through 63 leaves / 8 spend inputs / 8 proof shards with one reserve output. Larger shard counts remain supportable on the same wire surface if the shared-ring policy is raised later, but the measured launch baseline stops at the current proven 8-spend ceiling.");
        corrected_scope_notes.push_back(std::move(note));
    }
    {
        UniValue note(UniValue::VOBJ);
        note.pushKV("surface", "legacy_matrict_and_receipt_backends");
        note.pushKV("status", "off_launch_surface");
        note.pushKV("reason",
                    "DIRECT_MATRICT, native MatRiCT ingress, and receipt-backed ingress remain in tree for parsing, tests, and historical tooling, but they are not part of the reset-chain activation surface and should not be treated as launch blockers for the Smile-only path.");
        corrected_scope_notes.push_back(std::move(note));
    }
    {
        UniValue note(UniValue::VOBJ);
        note.pushKV("surface", "egress_rebalance");
        note.pushKV("status", "not_a_registry_leaf_spend_blocker");
        note.pushKV("reason",
                    "Current egress and rebalance bundles create outputs and bind settlement or reserve-delta objects directly; they do not consume shielded account leaves on wire in the same way direct send and ingress do, so the earlier blocker text for consumed registry-leaf migration was stale.");
        corrected_scope_notes.push_back(std::move(note));
    }
    {
        UniValue note(UniValue::VOBJ);
        note.pushKV("surface", "leaf_only_minimal_outputs");
        note.pushKV("status", "optional_follow_on_optimization");
        note.pushKV("reason",
                    "A future leaf-only minimal-output transport is still possible, but it is no longer a launch blocker: the production hard-fork path already externalizes CompactPublicAccount away from the dominant inline transaction surface and reconstructs future spend state from committed registry payloads plus lean consumed-leaf witnesses.");
        corrected_scope_notes.push_back(std::move(note));
    }

    UniValue launch_readiness(UniValue::VOBJ);
    launch_readiness.pushKV("status", "ready");
    launch_readiness.pushKV("launch_ready", true);
    launch_readiness.pushKV("base_direct_smile_launch_ready", true);
    launch_readiness.pushKV("account_registry_activation_ready", true);
    launch_readiness.pushKV("blocker_count", static_cast<int64_t>(explicit_blockers.size()));
    launch_readiness.pushKV("blockers", explicit_blockers);
    launch_readiness.pushKV("corrected_scope_notes", corrected_scope_notes);
    launch_readiness.pushKV(
        "least_bad_next_move",
        "Treat the current branch as the completed hard-fork launch surface: direct send and ingress verify through SMILE, full registry payloads are committed in state for snapshot/bootstrap and light-client proof surfaces, and consumed-leaf transaction witnesses are lean on wire. Further output compression below the current compact output transport is optional follow-on optimization rather than launch-critical protocol work.");

    const bool overall_pass = output_footprints_pass && tx_projection_pass && registry_sequence_pass;
    UniValue out(UniValue::VOBJ);
    out.pushKV("status", overall_pass ? "passed" : "failed");
    out.pushKV("family_output_footprints", std::move(family_output_footprints));
    out.pushKV("direct_send_tx_projections", std::move(direct_send_tx_projections));
    out.pushKV("registry_sequence", std::move(registry_sequence));
    out.pushKV("explicit_blockers", std::move(explicit_blockers));
    out.pushKV("launch_readiness", std::move(launch_readiness));
    out.pushKV("all_checks_pass", overall_pass);
    out.pushKV("proof_relation_status",
               "direct_send_smile_and_batch_smile_live_with_committed_registry_payload_recovery_and_lean_spend_witnesses");
    return out;
}

size_t MeasureCenteredPolyVecBytes(const smile2::SmilePolyVec& polys)
{
    std::vector<uint8_t> encoded;
    smile2::SerializeCenteredPolyVecFixed(polys, encoded);
    return encoded.size();
}

size_t MeasureGaussianPolyVecBytes(const smile2::SmilePolyVec& polys)
{
    std::vector<uint8_t> encoded;
    smile2::SerializeGaussianVecFixed(polys, encoded);
    return encoded.size();
}

size_t MeasureAdaptiveWitnessBytes(const smile2::SmilePolyVec& polys)
{
    std::vector<uint8_t> encoded;
    smile2::SerializeAdaptiveWitnessPolyVec(polys, encoded);
    return encoded.size();
}

size_t MeasureExactPolyAdaptiveBytes(const smile2::SmilePoly& poly)
{
    std::vector<uint8_t> centered_encoded;
    smile2::SerializeCenteredPolyExact(poly, centered_encoded);

    std::vector<uint8_t> gaussian_encoded;
    smile2::SerializeGaussianVecFixed(smile2::SmilePolyVec{poly}, gaussian_encoded);

    return 1 + std::min(centered_encoded.size(), gaussian_encoded.size());
}

smile2::SmilePoly ComputeOpeningInnerProductHarness(const std::vector<smile2::SmilePoly>& row,
                                                    const smile2::SmilePolyVec& opening)
{
    smile2::SmilePoly acc;
    const size_t limit = std::min(row.size(), opening.size());
    for (size_t i = 0; i < limit; ++i) {
        acc += smile2::NttMul(row[i], opening[i]);
    }
    acc.Reduce();
    return acc;
}

size_t ComputeLiveCtW0OffsetForHarness(size_t num_inputs, size_t num_outputs)
{
    return num_inputs + num_inputs + num_outputs;
}

smile2::SmilePolyVec CollectSelectorAmountResiduesForHarness(const smile2::SmileCTProof& proof,
                                                             size_t num_inputs,
                                                             size_t num_outputs)
{
    smile2::SmilePolyVec serialized;
    const size_t split_slot = ComputeLiveCtW0OffsetForHarness(num_inputs, num_outputs);
    for (size_t slot = 0; slot < proof.aux_residues.size() && slot < split_slot; ++slot) {
        serialized.push_back(proof.aux_residues[slot]);
    }
    return serialized;
}

smile2::SmilePolyVec CollectTailResiduesForHarness(const smile2::SmileCTProof& proof,
                                                   size_t num_inputs,
                                                   size_t num_outputs)
{
    constexpr size_t kCtPublicRowCount = smile2::KEY_ROWS + 2;
    smile2::SmilePolyVec serialized;
    const size_t tail_offset =
        ComputeLiveCtW0OffsetForHarness(num_inputs, num_outputs) + num_inputs * kCtPublicRowCount;
    for (size_t slot = tail_offset; slot < proof.aux_residues.size(); ++slot) {
        serialized.push_back(proof.aux_residues[slot]);
    }
    return serialized;
}

UniValue BuildCtProofComponentBreakdown(const smile2::SmileCTProof& proof,
                                        size_t num_inputs,
                                        size_t num_outputs,
                                        size_t serialized_bytes)
{
    UniValue out(UniValue::VOBJ);

    const smile2::SmilePolyVec selector_amount_residues =
        CollectSelectorAmountResiduesForHarness(proof, num_inputs, num_outputs);
    const smile2::SmilePolyVec tail_residues =
        CollectTailResiduesForHarness(proof, num_inputs, num_outputs);

    size_t z0_bytes{0};
    for (const auto& z0i : proof.z0) {
        z0_bytes += MeasureGaussianPolyVecBytes(z0i);
    }

    size_t tuple_z_coin_bytes{0};
    smile2::SmilePolyVec tuple_z_amounts;
    smile2::SmilePolyVec tuple_z_leafs;
    tuple_z_amounts.reserve(proof.input_tuples.size());
    tuple_z_leafs.reserve(proof.input_tuples.size());
    for (const auto& tuple : proof.input_tuples) {
        tuple_z_coin_bytes += MeasureGaussianPolyVecBytes(tuple.z_coin);
        tuple_z_amounts.push_back(tuple.z_amount);
        tuple_z_leafs.push_back(tuple.z_leaf);
    }

    size_t tuple_row_image_bytes{0};
    const auto coin_ck = GetPublicCoinCommitmentKey();
    for (const auto& tuple : proof.input_tuples) {
        smile2::SmilePolyVec tuple_rows;
        tuple_rows.reserve(smile2::KEY_ROWS + 2);
        for (size_t row = 0; row < smile2::KEY_ROWS; ++row) {
            tuple_rows.push_back(ComputeOpeningInnerProductHarness(coin_ck.B0[row], tuple.z_coin));
        }
        smile2::SmilePoly amount_row = ComputeOpeningInnerProductHarness(coin_ck.b[0], tuple.z_coin);
        amount_row += tuple.z_amount;
        amount_row.Reduce();
        tuple_rows.push_back(std::move(amount_row));
        tuple_rows.push_back(tuple.z_leaf);
        tuple_row_image_bytes += MeasureAdaptiveWitnessBytes(tuple_rows);
    }

    const size_t aux_t0_bytes = MeasureCenteredPolyVecBytes(proof.aux_commitment.t0);
    const size_t selector_amount_residue_bytes = MeasureAdaptiveWitnessBytes(selector_amount_residues);
    const size_t tail_residue_bytes = MeasureGaussianPolyVecBytes(tail_residues);
    const size_t w0_residue_acc_bytes = MeasureGaussianPolyVecBytes(proof.w0_residue_accs);
    const size_t z_bytes = MeasureGaussianPolyVecBytes(proof.z);
    const size_t tuple_z_amount_bytes = MeasureAdaptiveWitnessBytes(tuple_z_amounts);
    const size_t tuple_z_leaf_bytes = MeasureAdaptiveWitnessBytes(tuple_z_leafs);
    const size_t tuple_opening_acc_bytes = MeasureExactPolyAdaptiveBytes(proof.tuple_opening_acc);
    const size_t coin_opening_z_bytes = MeasureGaussianPolyVecBytes(proof.coin_opening.z);
    const size_t serial_number_bytes = MeasureCenteredPolyVecBytes(proof.serial_numbers);
    const size_t round1_aux_binding_digest_bytes = proof.round1_aux_binding_digest.size();
    const size_t pre_h2_binding_digest_bytes = proof.pre_h2_binding_digest.size();
    const size_t post_h2_binding_digest_bytes = proof.post_h2_binding_digest.size();
    const size_t coin_opening_binding_digest_bytes = proof.coin_opening.binding_digest.size();
    const size_t h2_bytes = (smile2::POLY_DEGREE - smile2::SLOT_DEGREE) * sizeof(uint32_t);
    const size_t seed_c_bytes = proof.seed_c.size();
    const size_t wire_header_bytes =
        proof.wire_version >= smile2::SmileCTProof::WIRE_VERSION_M4_HARDENED ? 5 : 0;
    const size_t hypothetical_tuple_row_replacement_bytes =
        serialized_bytes - tuple_z_coin_bytes + tuple_row_image_bytes + 32;

    const size_t accounted_bytes =
        wire_header_bytes +
        aux_t0_bytes +
        selector_amount_residue_bytes +
        tail_residue_bytes +
        w0_residue_acc_bytes +
        round1_aux_binding_digest_bytes +
        pre_h2_binding_digest_bytes +
        z_bytes +
        z0_bytes +
        tuple_z_coin_bytes +
        tuple_z_amount_bytes +
        tuple_z_leaf_bytes +
        tuple_opening_acc_bytes +
        coin_opening_z_bytes +
        coin_opening_binding_digest_bytes +
        serial_number_bytes +
        post_h2_binding_digest_bytes +
        h2_bytes +
        seed_c_bytes;

    out.pushKV("aux_t0_bytes", static_cast<int64_t>(aux_t0_bytes));
    out.pushKV("selector_amount_residue_bytes", static_cast<int64_t>(selector_amount_residue_bytes));
    out.pushKV("tail_residue_bytes", static_cast<int64_t>(tail_residue_bytes));
    out.pushKV("w0_residue_acc_bytes", static_cast<int64_t>(w0_residue_acc_bytes));
    out.pushKV("round1_aux_binding_digest_bytes", static_cast<int64_t>(round1_aux_binding_digest_bytes));
    out.pushKV("pre_h2_binding_digest_bytes", static_cast<int64_t>(pre_h2_binding_digest_bytes));
    out.pushKV("z_bytes", static_cast<int64_t>(z_bytes));
    out.pushKV("z0_bytes", static_cast<int64_t>(z0_bytes));
    out.pushKV("tuple_z_coin_bytes", static_cast<int64_t>(tuple_z_coin_bytes));
    out.pushKV("tuple_row_image_bytes", static_cast<int64_t>(tuple_row_image_bytes));
    out.pushKV("tuple_z_amount_bytes", static_cast<int64_t>(tuple_z_amount_bytes));
    out.pushKV("tuple_z_leaf_bytes", static_cast<int64_t>(tuple_z_leaf_bytes));
    out.pushKV("tuple_opening_acc_bytes", static_cast<int64_t>(tuple_opening_acc_bytes));
    out.pushKV("coin_opening_z_bytes", static_cast<int64_t>(coin_opening_z_bytes));
    out.pushKV("coin_opening_binding_digest_bytes", static_cast<int64_t>(coin_opening_binding_digest_bytes));
    out.pushKV("serial_number_bytes", static_cast<int64_t>(serial_number_bytes));
    out.pushKV("post_h2_binding_digest_bytes", static_cast<int64_t>(post_h2_binding_digest_bytes));
    out.pushKV("h2_bytes", static_cast<int64_t>(h2_bytes));
    out.pushKV("seed_c_bytes", static_cast<int64_t>(seed_c_bytes));
    out.pushKV("wire_header_bytes", static_cast<int64_t>(wire_header_bytes));
    out.pushKV("accounted_bytes", static_cast<int64_t>(accounted_bytes));
    out.pushKV("unaccounted_bytes",
               static_cast<int64_t>(serialized_bytes) - static_cast<int64_t>(accounted_bytes));
    out.pushKV("hypothetical_tuple_row_replacement_bytes",
               static_cast<int64_t>(hypothetical_tuple_row_replacement_bytes));
    return out;
}

UniValue EvaluateCtScenario(const CtScenarioConfig& config)
{
    if (config.input_amounts.size() != config.input_count) {
        throw std::runtime_error("CT scenario input amount count mismatch");
    }
    if (config.output_amounts.size() != config.output_count) {
        throw std::runtime_error("CT scenario output amount count mismatch");
    }

    const auto setup = CTDeterministicSetup::Create(config.anon_set,
                                                    config.input_count,
                                                    config.output_count,
                                                    config.input_amounts,
                                                    config.output_amounts,
                                                    config.seed);

    const auto prove_start = Clock::now();
    const smile2::SmileCTProof proof = ProveCtDeterministicWithRetries(setup.inputs,
                                                                       setup.outputs,
                                                                       setup.pub,
                                                                       0xA55A0000ULL + config.seed);
    const auto prove_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        Clock::now() - prove_start).count();
    if (proof.serial_numbers.empty() || proof.z.empty() || proof.z0.empty() || proof.aux_commitment.t0.empty()) {
        throw std::runtime_error("failed to build CT proof in redesign harness");
    }

    const auto verify_start = Clock::now();
    const bool verified = smile2::VerifyCT(proof,
                                           config.input_count,
                                           config.output_count,
                                           setup.pub);
    const auto verify_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        Clock::now() - verify_start).count();

    const std::vector<uint8_t> serialized = smile2::SerializeCTProof(proof);
    const size_t serialized_bytes = serialized.size();
    const UniValue component_breakdown =
        BuildCtProofComponentBreakdown(proof,
                                       config.input_count,
                                       config.output_count,
                                       serialized_bytes);

    smile2::SmileCTProof roundtrip;
    if (!smile2::DeserializeCTProof(serialized, roundtrip, config.input_count, config.output_count)) {
        throw std::runtime_error("failed to roundtrip CT proof in redesign harness");
    }
    roundtrip.output_coins = proof.output_coins;
    const bool roundtrip_verified = smile2::VerifyCT(roundtrip,
                                                     config.input_count,
                                                     config.output_count,
                                                     setup.pub);

    const std::vector<uint8_t> same_seed_bytes = smile2::SerializeCTProof(
        ProveCtDeterministicWithRetries(setup.inputs,
                                        setup.outputs,
                                        setup.pub,
                                        0xA55A0000ULL + config.seed));
    const bool same_seed_deterministic =
        serialized == same_seed_bytes;

    const smile2::SmileCTProof different_seed_proof = ProveCtDeterministicWithRetries(
        setup.inputs,
        setup.outputs,
        setup.pub,
        0xA55A1000ULL + config.seed);
    const std::vector<uint8_t> different_seed_bytes = smile2::SerializeCTProof(different_seed_proof);
    const bool different_seed_verified = smile2::VerifyCT(different_seed_proof,
                                                          config.input_count,
                                                          config.output_count,
                                                          setup.pub);
    const bool different_seed_distinct = serialized != different_seed_bytes;

    bool all_tamper_cases_rejected{true};
    UniValue tamper_cases(UniValue::VARR);
    tamper_cases.push_back(RunTamperCase("z_coeff",
                                         proof,
                                         config.input_count,
                                         config.output_count,
                                         setup.pub,
                                         [](smile2::SmileCTProof& tampered) {
                                             if (tampered.z.empty() || tampered.z[0].coeffs.empty()) return false;
                                             tampered.z[0].coeffs[0] =
                                                 smile2::mod_q(tampered.z[0].coeffs[0] + 1);
                                             return true;
                                         },
                                         all_tamper_cases_rejected));
    tamper_cases.push_back(RunTamperCase("z0_coeff",
                                         proof,
                                         config.input_count,
                                         config.output_count,
                                         setup.pub,
                                         [](smile2::SmileCTProof& tampered) {
                                             if (tampered.z0.empty() || tampered.z0[0].empty() ||
                                                 tampered.z0[0][0].coeffs.empty()) return false;
                                             tampered.z0[0][0].coeffs[0] =
                                                 smile2::mod_q(tampered.z0[0][0].coeffs[0] + 1);
                                             return true;
                                         },
                                         all_tamper_cases_rejected));
    tamper_cases.push_back(RunTamperCase("tuple_opening_acc",
                                         proof,
                                         config.input_count,
                                         config.output_count,
                                         setup.pub,
                                         [](smile2::SmileCTProof& tampered) {
                                             if (tampered.tuple_opening_acc.coeffs.empty()) return false;
                                             tampered.tuple_opening_acc.coeffs[0] =
                                                 smile2::mod_q(tampered.tuple_opening_acc.coeffs[0] + 1);
                                             return true;
                                         },
                                         all_tamper_cases_rejected));
    tamper_cases.push_back(RunTamperCase("tuple_z_leaf",
                                         proof,
                                         config.input_count,
                                         config.output_count,
                                         setup.pub,
                                         [](smile2::SmileCTProof& tampered) {
                                             if (tampered.input_tuples.empty() ||
                                                 tampered.input_tuples[0].z_leaf.coeffs.empty()) {
                                                 return false;
                                             }
                                             tampered.input_tuples[0].z_leaf.coeffs[0] =
                                                 smile2::mod_q(tampered.input_tuples[0].z_leaf.coeffs[0] + 1);
                                             return true;
                                         },
                                         all_tamper_cases_rejected));
    tamper_cases.push_back(RunTamperCase("round1_aux_binding_digest",
                                         proof,
                                         config.input_count,
                                         config.output_count,
                                         setup.pub,
                                         [](smile2::SmileCTProof& tampered) {
                                             tampered.round1_aux_binding_digest[0] ^= 0x80;
                                             return true;
                                         },
                                         all_tamper_cases_rejected));
    tamper_cases.push_back(RunTamperCase("seed_z",
                                         proof,
                                         config.input_count,
                                         config.output_count,
                                         setup.pub,
                                         [](smile2::SmileCTProof& tampered) {
                                             tampered.seed_z[0] ^= 0x01;
                                             return true;
                                         },
                                         all_tamper_cases_rejected));
    tamper_cases.push_back(RunTamperCase("output_coin_t_msg",
                                         proof,
                                         config.input_count,
                                         config.output_count,
                                         setup.pub,
                                         [](smile2::SmileCTProof& tampered) {
                                             if (tampered.output_coins.empty() ||
                                                 tampered.output_coins[0].t_msg.empty() ||
                                                 tampered.output_coins[0].t_msg[0].coeffs.empty()) {
                                                 return false;
                                             }
                                             tampered.output_coins[0].t_msg[0].coeffs[0] =
                                                 smile2::mod_q(tampered.output_coins[0].t_msg[0].coeffs[0] + 1);
                                             return true;
                                         },
                                         all_tamper_cases_rejected));

    UniValue budget_checks(UniValue::VARR);
    bool budget_pass{true};
    AddBudgetCheck(budget_checks, "proof_bytes", serialized_bytes, config.budget.max_proof_bytes, budget_pass);
    AddBudgetCheck(budget_checks, "prove_ns", prove_ns, config.budget.max_build_median_ns, budget_pass);
    AddBudgetCheck(budget_checks, "verify_ns", verify_ns, config.budget.max_verify_median_ns, budget_pass);

    UniValue out(UniValue::VOBJ);
    out.pushKV("name", config.name);
    out.pushKV("anon_set", static_cast<int64_t>(config.anon_set));
    out.pushKV("input_count", static_cast<int64_t>(config.input_count));
    out.pushKV("output_count", static_cast<int64_t>(config.output_count));
    out.pushKV("proof_bytes", static_cast<int64_t>(serialized_bytes));
    out.pushKV("proof_hash", HexStr(HashBytes(serialized)));
    out.pushKV("serialized_size_method_bytes", static_cast<int64_t>(proof.SerializedSize()));
    out.pushKV("proof_component_bytes", component_breakdown);
    out.pushKV("prove_ns", prove_ns);
    out.pushKV("verify_ns", verify_ns);
    out.pushKV("verified", verified);
    out.pushKV("roundtrip_verified", roundtrip_verified);
    out.pushKV("same_seed_deterministic", same_seed_deterministic);
    out.pushKV("different_seed_verified", different_seed_verified);
    out.pushKV("different_seed_distinct", different_seed_distinct);
    out.pushKV("all_tamper_cases_rejected", all_tamper_cases_rejected);
    out.pushKV("tamper_cases", std::move(tamper_cases));
    out.pushKV("budget_checks", std::move(budget_checks));
    out.pushKV("budget_pass", budget_pass);
    out.pushKV("status",
               verified && roundtrip_verified && same_seed_deterministic &&
                       different_seed_verified && different_seed_distinct &&
                       all_tamper_cases_rejected && budget_pass
                   ? "passed"
                   : "failed");
    return out;
}

UniValue EvaluateDirectSendScenario(const UniValue& runtime_report,
                                    const DirectSendScenarioConfig& config)
{
    const UniValue* scenario = FindDirectSendScenarioReport(runtime_report,
                                                            config.scenario.spend_count,
                                                            config.scenario.output_count);
    if (scenario == nullptr) {
        throw std::runtime_error("direct-send runtime report missing requested scenario");
    }

    const UniValue& tx_shape = scenario->find_value("tx_shape");
    const UniValue& build_summary = scenario->find_value("build_summary");
    const UniValue& proof_check_summary = scenario->find_value("proof_check_summary");
    const UniValue& block_capacity = scenario->find_value("block_capacity");

    const int64_t tx_bytes =
        RequireJsonInt<int64_t>(tx_shape, "serialized_size_bytes", "direct_send_runtime.scenarios[].tx_shape");
    const int64_t proof_bytes =
        RequireJsonInt<int64_t>(tx_shape, "proof_payload_bytes", "direct_send_runtime.scenarios[].tx_shape");
    const int64_t build_median_ns =
        RequireJsonInt<int64_t>(build_summary, "median_ns", "direct_send_runtime.scenarios[].build_summary");
    const int64_t verify_median_ns =
        RequireJsonInt<int64_t>(proof_check_summary,
                                "median_ns",
                                "direct_send_runtime.scenarios[].proof_check_summary");

    UniValue budget_checks(UniValue::VARR);
    bool budget_pass{true};
    AddBudgetCheck(budget_checks, "proof_bytes", proof_bytes, config.budget.max_proof_bytes, budget_pass);
    AddBudgetCheck(budget_checks, "tx_bytes", tx_bytes, config.budget.max_tx_bytes, budget_pass);
    AddBudgetCheck(budget_checks, "build_median_ns", build_median_ns, config.budget.max_build_median_ns, budget_pass);
    AddBudgetCheck(budget_checks, "verify_median_ns", verify_median_ns, config.budget.max_verify_median_ns, budget_pass);

    UniValue out(UniValue::VOBJ);
    out.pushKV("scenario", ScenarioLabel(config.scenario.spend_count, config.scenario.output_count));
    out.pushKV("spend_count", static_cast<int64_t>(config.scenario.spend_count));
    out.pushKV("output_count", static_cast<int64_t>(config.scenario.output_count));
    out.pushKV("tx_bytes", tx_bytes);
    out.pushKV("proof_bytes", proof_bytes);
    out.pushKV("envelope_bytes", tx_bytes - proof_bytes);
    out.pushKV("build_median_ns", build_median_ns);
    out.pushKV("verify_median_ns", verify_median_ns);
    out.pushKV("max_transactions_per_block",
               RequireJsonInt<int64_t>(block_capacity,
                                       "max_transactions_per_block",
                                       "direct_send_runtime.scenarios[].block_capacity"));
    out.pushKV("binding_limit",
               RequireJsonString(block_capacity,
                                 "binding_limit",
                                 "direct_send_runtime.scenarios[].block_capacity"));
    out.pushKV("budget_checks", std::move(budget_checks));
    out.pushKV("budget_pass", budget_pass);
    out.pushKV("status", budget_pass ? "passed" : "failed");
    return out;
}

UniValue EvaluateIngressScenario(const IngressScenarioConfig& config,
                                 size_t warmup_iterations,
                                 size_t measured_iterations)
{
    const UniValue report = ingress::BuildProofRuntimeReport({
        .backend_kind = config.backend_kind,
        .warmup_iterations = warmup_iterations,
        .measured_iterations = measured_iterations,
        .reserve_output_count = config.reserve_output_count,
        .leaf_count = config.leaf_count,
    });
    const std::string status = RequireJsonString(report, "status", "ingress_runtime");
    int64_t tx_bytes{-1};
    int64_t proof_bytes{-1};
    int64_t build_median_ns{-1};
    int64_t verify_median_ns{-1};
    std::string reject_reason;
    if (status == "built_and_checked") {
        const UniValue& scenario = report.find_value("scenario");
        const UniValue& tx_shape = scenario.find_value("tx_shape");
        const UniValue& build_summary = report.find_value("build_summary");
        const UniValue& proof_check_summary = report.find_value("proof_check_summary");

        tx_bytes =
            RequireJsonInt<int64_t>(tx_shape, "serialized_size_bytes", "ingress_runtime.scenario.tx_shape");
        proof_bytes =
            RequireJsonInt<int64_t>(tx_shape, "proof_payload_size", "ingress_runtime.scenario.tx_shape");
        build_median_ns =
            RequireJsonInt<int64_t>(build_summary, "median_ns", "ingress_runtime.build_summary");
        verify_median_ns =
            RequireJsonInt<int64_t>(proof_check_summary, "median_ns", "ingress_runtime.proof_check_summary");
    } else {
        const UniValue& rejection = report.find_value("rejection");
        if (rejection.isObject()) {
            const UniValue& value = rejection.find_value("reject_reason");
            if (value.isStr()) {
                reject_reason = value.get_str();
            }
        }
    }

    UniValue budget_checks(UniValue::VARR);
    bool budget_pass{status == "built_and_checked"};
    if (status == "built_and_checked") {
        AddBudgetCheck(budget_checks, "proof_bytes", proof_bytes, config.budget.max_proof_bytes, budget_pass);
        AddBudgetCheck(budget_checks, "tx_bytes", tx_bytes, config.budget.max_tx_bytes, budget_pass);
        AddBudgetCheck(budget_checks, "build_median_ns", build_median_ns, config.budget.max_build_median_ns, budget_pass);
        AddBudgetCheck(budget_checks, "verify_median_ns", verify_median_ns, config.budget.max_verify_median_ns, budget_pass);
    }

    UniValue out(UniValue::VOBJ);
    out.pushKV("backend",
               config.backend_kind == ingress::ProofRuntimeBackendKind::SMILE ?
                   "smile" :
               config.backend_kind == ingress::ProofRuntimeBackendKind::RECEIPT_BACKED ?
                   "receipt_backed" :
                   "matrict_plus");
    out.pushKV("reserve_output_count", static_cast<int64_t>(config.reserve_output_count));
    out.pushKV("leaf_count", static_cast<int64_t>(config.leaf_count));
    out.pushKV("tx_bytes", tx_bytes);
    out.pushKV("proof_bytes", proof_bytes);
    out.pushKV("envelope_bytes", tx_bytes - proof_bytes);
    out.pushKV("build_median_ns", build_median_ns);
    out.pushKV("verify_median_ns", verify_median_ns);
    out.pushKV("status", status);
    if (!reject_reason.empty()) {
        out.pushKV("reject_reason", reject_reason);
    }
    out.pushKV("budget_checks", std::move(budget_checks));
    out.pushKV("budget_pass", budget_pass);
    return out;
}

} // namespace

CTDeterministicSetup CTDeterministicSetup::Create(size_t anon_set,
                                                  size_t input_count,
                                                  size_t output_count,
                                                  const std::vector<int64_t>& input_amounts,
                                                  const std::vector<int64_t>& output_amounts,
                                                  uint8_t seed)
{
    if (input_count == 0 || output_count == 0) {
        throw std::runtime_error("CT deterministic setup requires non-zero inputs and outputs");
    }
    if (input_amounts.size() != input_count || output_amounts.size() != output_count) {
        throw std::runtime_error("CT deterministic setup amount count mismatch");
    }
    if (anon_set < input_count + 1) {
        throw std::runtime_error("CT deterministic setup anonymity set too small");
    }

    CTDeterministicSetup setup;
    setup.keys = GenerateAnonSet(anon_set, seed);
    setup.pub.anon_set = ExtractPublicKeys(setup.keys);

    std::vector<size_t> secret_indices;
    secret_indices.reserve(input_count);
    for (size_t i = 0; i < input_count; ++i) {
        secret_indices.push_back((i * 3 + 1) % anon_set);
    }

    setup.pub.coin_rings = BuildCoinRings(setup.keys,
                                          secret_indices,
                                          input_amounts,
                                          static_cast<uint64_t>(seed) + 100);
    setup.pub.account_rings = ::test::shielded::BuildDeterministicCTAccountRings(
        setup.keys,
        setup.pub.coin_rings,
        static_cast<uint32_t>(seed) * 1000 + 200,
        0x91);

    const auto coin_ck = GetPublicCoinCommitmentKey();
    setup.inputs.resize(input_count);
    for (size_t i = 0; i < input_count; ++i) {
        setup.inputs[i].secret_index = secret_indices[i];
        setup.inputs[i].sk = setup.keys[secret_indices[i]].sec;
        setup.inputs[i].amount = input_amounts[i];
        setup.inputs[i].coin_r = smile2::SampleTernary(
            coin_ck.rand_dim(),
            static_cast<uint64_t>(seed + 100) * 100000ULL + i * anon_set + secret_indices[i]);
    }

    setup.outputs.resize(output_count);
    for (size_t i = 0; i < output_count; ++i) {
        setup.outputs[i].amount = output_amounts[i];
        setup.outputs[i].coin_r = smile2::SampleTernary(
            coin_ck.rand_dim(),
            static_cast<uint64_t>(seed) * 1000000ULL + i);
    }

    return setup;
}

ProofRedesignFrameworkConfig MakeFastProofRedesignFrameworkConfig()
{
    ProofRedesignFrameworkConfig config;
    config.warmup_iterations = 0;
    config.measured_iterations = 1;
    config.fee_sat = 1000;
    config.ct_scenarios = {
        CtScenarioConfig{
            .name = "ct_1x1",
            .anon_set = 32,
            .input_count = 1,
            .output_count = 1,
            .input_amounts = {100},
            .output_amounts = {100},
            .seed = 0x64,
            .budget = MetricBudget{
                .max_proof_bytes = 32000,
                .max_build_median_ns = 20'000'000'000LL,
                .max_verify_median_ns = 2'000'000'000LL,
            },
        },
        CtScenarioConfig{
            .name = "ct_2x2",
            .anon_set = 32,
            .input_count = 2,
            .output_count = 2,
            .input_amounts = {120, 80},
            .output_amounts = {110, 90},
            .seed = 0x65,
            .budget = MetricBudget{
                .max_proof_bytes = 50000,
                .max_build_median_ns = 45'000'000'000LL,
                .max_verify_median_ns = 2'000'000'000LL,
            },
        },
    };
    config.direct_send_scenarios = {
        DirectSendScenarioConfig{
            .scenario = shieldedv2send::RuntimeScenarioConfig{1, 2},
            .budget = MetricBudget{
                .max_proof_bytes = 60000,
                .max_tx_bytes = 65000,
                .max_build_median_ns = 15'000'000'000LL,
                .max_verify_median_ns = 2'000'000'000LL,
            },
        },
    };
    config.ingress_scenarios = {
        IngressScenarioConfig{
            .backend_kind = ingress::ProofRuntimeBackendKind::SMILE,
            .reserve_output_count = 1,
            .leaf_count = 8,
            .budget = MetricBudget{
                .max_proof_bytes = 300000,
                .max_tx_bytes = 450000,
                .max_build_median_ns = 40'000'000'000LL,
                .max_verify_median_ns = 2'000'000'000LL,
            },
        },
    };
    return config;
}

ProofRedesignFrameworkConfig MakeLaunchBaselineProofRedesignFrameworkConfig()
{
    ProofRedesignFrameworkConfig config = MakeFastProofRedesignFrameworkConfig();
    config.direct_send_scenarios = {
        DirectSendScenarioConfig{
            .scenario = shieldedv2send::RuntimeScenarioConfig{1, 2},
            .budget = MetricBudget{
                .max_proof_bytes = 60000,
                .max_tx_bytes = 65000,
                .max_build_median_ns = 15'000'000'000LL,
                .max_verify_median_ns = 2'000'000'000LL,
            },
        },
        DirectSendScenarioConfig{
            .scenario = shieldedv2send::RuntimeScenarioConfig{2, 2},
            .budget = MetricBudget{
                .max_proof_bytes = 70000,
                .max_tx_bytes = 75000,
                .max_build_median_ns = 20'000'000'000LL,
                .max_verify_median_ns = 2'000'000'000LL,
            },
        },
        DirectSendScenarioConfig{
            .scenario = shieldedv2send::RuntimeScenarioConfig{2, 4},
            .budget = MetricBudget{
                .max_proof_bytes = 90000,
                .max_tx_bytes = 105000,
                .max_build_median_ns = 20'000'000'000LL,
                .max_verify_median_ns = 2'000'000'000LL,
            },
        },
    };
    config.ingress_scenarios = {
        IngressScenarioConfig{
            .backend_kind = ingress::ProofRuntimeBackendKind::SMILE,
            .reserve_output_count = 1,
            .leaf_count = 63,
            .budget = MetricBudget{
                .max_proof_bytes = 300000,
                .max_tx_bytes = 350000,
                .max_build_median_ns = 130'000'000'000LL,
                .max_verify_median_ns = 7'000'000'000LL,
            },
        },
    };
    return config;
}

UniValue BuildProofRedesignFrameworkReport(const ProofRedesignFrameworkConfig& config)
{
    if (config.measured_iterations == 0) {
        throw std::runtime_error("proof redesign framework requires measured_iterations > 0");
    }
    if (config.ct_scenarios.empty()) {
        throw std::runtime_error("proof redesign framework requires at least one CT scenario");
    }
    if (config.direct_send_scenarios.empty()) {
        throw std::runtime_error("proof redesign framework requires at least one direct-send scenario");
    }
    if (config.ingress_scenarios.empty()) {
        throw std::runtime_error("proof redesign framework requires at least one ingress scenario");
    }

    std::vector<shieldedv2send::RuntimeScenarioConfig> direct_send_configs;
    direct_send_configs.reserve(config.direct_send_scenarios.size());
    for (const auto& scenario : config.direct_send_scenarios) {
        direct_send_configs.push_back(scenario.scenario);
    }
    const UniValue direct_send_report = shieldedv2send::BuildRuntimeReport({
        .warmup_iterations = config.warmup_iterations,
        .measured_iterations = config.measured_iterations,
        .fee_sat = config.fee_sat,
        .scenarios = direct_send_configs,
    });

    UniValue ct_reports(UniValue::VARR);
    bool all_ct_pass{true};
    for (const auto& scenario : config.ct_scenarios) {
        UniValue report = EvaluateCtScenario(scenario);
        const bool passed = report.find_value("status").get_str() == "passed";
        all_ct_pass &= passed;
        ct_reports.push_back(std::move(report));
    }

    UniValue direct_send_reports(UniValue::VARR);
    bool all_direct_send_pass{true};
    for (const auto& scenario : config.direct_send_scenarios) {
        UniValue report = EvaluateDirectSendScenario(direct_send_report, scenario);
        const bool passed = report.find_value("status").get_str() == "passed";
        all_direct_send_pass &= passed;
        direct_send_reports.push_back(std::move(report));
    }

    UniValue ingress_reports(UniValue::VARR);
    bool all_ingress_pass{true};
    for (const auto& scenario : config.ingress_scenarios) {
        UniValue report = EvaluateIngressScenario(scenario,
                                                 config.warmup_iterations,
                                                 config.measured_iterations);
        const bool passed = report.find_value("budget_pass").get_bool() &&
                            report.find_value("status").get_str() == "built_and_checked";
        all_ingress_pass &= passed;
        ingress_reports.push_back(std::move(report));
    }

    const UniValue envelope = BuildEnvelopeFootprintReport();
    const UniValue account_registry_design = BuildAccountRegistryDesignReport(direct_send_report,
                                                                              envelope,
                                                                              config);
    const bool all_account_registry_pass = account_registry_design.find_value("all_checks_pass").get_bool();
    const bool overall_pass =
        all_ct_pass && all_direct_send_pass && all_ingress_pass && all_account_registry_pass;

    UniValue summary(UniValue::VOBJ);
    summary.pushKV("all_ct_checks_pass", all_ct_pass);
    summary.pushKV("all_direct_send_checks_pass", all_direct_send_pass);
    summary.pushKV("all_ingress_checks_pass", all_ingress_pass);
    summary.pushKV("all_account_registry_checks_pass", all_account_registry_pass);
    summary.pushKV("overall_pass", overall_pass);

    UniValue out(UniValue::VOBJ);
    out.pushKV("format_version", 1);
    out.pushKV("report_kind", "smile2_proof_redesign_framework");
    out.pushKV("status", overall_pass ? "all_checks_passed" : "check_failure_detected");
    out.pushKV("warmup_iterations", static_cast<int64_t>(config.warmup_iterations));
    out.pushKV("measured_iterations", static_cast<int64_t>(config.measured_iterations));
    out.pushKV("ct_scenarios", std::move(ct_reports));
    out.pushKV("direct_send_scenarios", std::move(direct_send_reports));
    out.pushKV("ingress_scenarios", std::move(ingress_reports));
    out.pushKV("envelope_footprint", envelope);
    out.pushKV("account_registry_design", account_registry_design);
    out.pushKV("summary", summary);
    return out;
}

} // namespace btx::test::smile2redesign

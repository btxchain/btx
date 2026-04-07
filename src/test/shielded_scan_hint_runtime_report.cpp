// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_scan_hint_runtime_report.h>

#include <crypto/ml_kem.h>
#include <hash.h>
#include <shielded/note_encryption.h>
#include <shielded/v2_send.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <numeric>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace btx::test::shieldedv2scan {
namespace {

struct Fixture
{
    ShieldedNote note;
    mlkem::KeyPair recipient;
    shielded::EncryptedNote encrypted_note;
    shielded::v2::EncryptedNotePayload payload;
    std::vector<mlkem::KeyPair> candidate_keys;
    size_t recipient_index{0};
};

struct LegacyScanMeasurement
{
    uint64_t candidate_key_count{0};
    uint64_t decrypt_attempt_count{0};
    uint64_t successful_decrypt_count{0};
    uint64_t view_tag_match_count{0};
    uint64_t false_positive_view_tag_count{0};
    uint64_t scan_ns{0};
};

struct V2ScanMeasurement
{
    uint64_t candidate_key_count{0};
    uint64_t decrypt_attempt_count{0};
    uint64_t successful_decrypt_count{0};
    uint64_t hint_match_count{0};
    uint64_t false_positive_hint_count{0};
    uint64_t wrong_domain_match_count{0};
    uint64_t hint_only_ns{0};
    uint64_t scan_ns{0};
};

template <size_t N>
std::array<uint8_t, N> DeriveSeed(std::string_view tag, uint32_t index)
{
    std::array<uint8_t, N> seed{};
    size_t offset{0};
    uint32_t counter{0};
    while (offset < seed.size()) {
        HashWriter hw;
        hw << std::string{tag} << index << counter;
        const uint256 digest = hw.GetSHA256();
        const size_t copy_len = std::min(seed.size() - offset, static_cast<size_t>(uint256::size()));
        std::copy_n(digest.begin(), copy_len, seed.begin() + offset);
        offset += copy_len;
        ++counter;
    }
    return seed;
}

ShieldedNote BuildNote()
{
    ShieldedNote note;
    note.value = 1250;
    note.recipient_pk_hash = uint256{0x41};
    note.rho = uint256{0x42};
    note.rcm = uint256{0x43};
    if (!note.IsValid()) {
        throw std::runtime_error("scan-hint runtime note fixture is invalid");
    }
    return note;
}

mlkem::KeyPair BuildKeyPair(std::string_view tag, uint32_t index)
{
    return mlkem::KeyGenDerand(DeriveSeed<mlkem::KEYGEN_SEEDBYTES>(tag, index));
}

shielded::EncryptedNote BuildEncryptedNote(const ShieldedNote& note, const mlkem::PublicKey& recipient_pk)
{
    const auto kem_seed = DeriveSeed<mlkem::ENCAPS_SEEDBYTES>("BTX_ShieldedV2_ScanHint_KEM", 0);
    const auto nonce = DeriveSeed<12>("BTX_ShieldedV2_ScanHint_Nonce", 0);
    return shielded::NoteEncryption::EncryptDeterministic(note, recipient_pk, kem_seed, nonce);
}

Fixture BuildFixture(size_t minimum_candidate_keys)
{
    if (minimum_candidate_keys < 2) {
        throw std::runtime_error("minimum_candidate_keys must be at least two");
    }

    Fixture fixture;
    fixture.note = BuildNote();
    fixture.recipient = BuildKeyPair("BTX_ShieldedV2_ScanHint_Recipient", 0);
    fixture.encrypted_note = BuildEncryptedNote(fixture.note, fixture.recipient.pk);

    auto payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        fixture.encrypted_note,
        fixture.recipient.pk,
        shielded::v2::ScanDomain::OPAQUE);
    if (!payload.has_value()) {
        throw std::runtime_error("failed to encode scan-hint runtime payload");
    }
    fixture.payload = std::move(*payload);

    fixture.recipient_index = minimum_candidate_keys / 3;
    fixture.candidate_keys.reserve(minimum_candidate_keys + 64);
    bool legacy_collision_found{false};
    uint32_t candidate_counter{0};
    while (fixture.candidate_keys.size() < minimum_candidate_keys || !legacy_collision_found) {
        if (fixture.candidate_keys.size() == fixture.recipient_index) {
            fixture.candidate_keys.push_back(fixture.recipient);
            continue;
        }

        const mlkem::KeyPair candidate = BuildKeyPair("BTX_ShieldedV2_ScanHint_Candidate", candidate_counter++);
        if (candidate.pk == fixture.recipient.pk) continue;

        if (shielded::NoteEncryption::ComputeViewTag(fixture.encrypted_note.kem_ciphertext, candidate.pk) ==
            fixture.encrypted_note.view_tag) {
            legacy_collision_found = true;
        }
        fixture.candidate_keys.push_back(candidate);
        if (fixture.candidate_keys.size() > minimum_candidate_keys + 4096 && !legacy_collision_found) {
            throw std::runtime_error("failed to find deterministic legacy view-tag collision");
        }
    }

    if (fixture.recipient_index >= fixture.candidate_keys.size()) {
        throw std::runtime_error("recipient index drifted out of bounds");
    }
    return fixture;
}

template <typename Fn>
uint64_t MeasureNanoseconds(Fn&& fn)
{
    const auto start = std::chrono::steady_clock::now();
    fn();
    const auto end = std::chrono::steady_clock::now();
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count());
}

LegacyScanMeasurement RunLegacyWalletScan(const Fixture& fixture)
{
    LegacyScanMeasurement out;
    out.candidate_key_count = fixture.candidate_keys.size();
    out.decrypt_attempt_count = fixture.candidate_keys.size();

    out.scan_ns = MeasureNanoseconds([&] {
        for (size_t i = 0; i < fixture.candidate_keys.size(); ++i) {
            const auto& candidate = fixture.candidate_keys[i];
            if (shielded::NoteEncryption::ComputeViewTag(fixture.encrypted_note.kem_ciphertext, candidate.pk) ==
                fixture.encrypted_note.view_tag) {
                ++out.view_tag_match_count;
            }

            auto note = shielded::NoteEncryption::TryDecrypt(
                fixture.encrypted_note,
                candidate.pk,
                candidate.sk,
                /*constant_time_scan=*/true);
            if (!note.has_value()) continue;
            if (note->GetCommitment() != fixture.note.GetCommitment()) {
                throw std::runtime_error("legacy scan produced unexpected note commitment");
            }
            ++out.successful_decrypt_count;
        }
    });

    if (out.successful_decrypt_count != 1) {
        throw std::runtime_error("legacy scan did not identify exactly one recipient");
    }
    if (out.view_tag_match_count == 0) {
        throw std::runtime_error("legacy scan lost the real recipient view tag");
    }
    out.false_positive_view_tag_count = out.view_tag_match_count - 1;
    return out;
}

V2ScanMeasurement RunV2WalletScan(const Fixture& fixture)
{
    V2ScanMeasurement out;
    out.candidate_key_count = fixture.candidate_keys.size();

    auto decoded = shielded::v2::DecodeLegacyEncryptedNotePayload(fixture.payload);
    if (!decoded.has_value()) {
        throw std::runtime_error("failed to decode runtime payload");
    }

    out.hint_only_ns = MeasureNanoseconds([&] {
        for (const auto& candidate : fixture.candidate_keys) {
            if (shielded::v2::LegacyEncryptedNotePayloadMatchesRecipient(fixture.payload, *decoded, candidate.pk)) {
                ++out.hint_match_count;
            }
        }
    });

    shielded::v2::EncryptedNotePayload wrong_domain = fixture.payload;
    wrong_domain.scan_domain = shielded::v2::ScanDomain::USER;
    for (const auto& candidate : fixture.candidate_keys) {
        if (shielded::v2::LegacyEncryptedNotePayloadMatchesRecipient(wrong_domain, *decoded, candidate.pk)) {
            ++out.wrong_domain_match_count;
        }
    }

    out.scan_ns = MeasureNanoseconds([&] {
        for (const auto& candidate : fixture.candidate_keys) {
            ++out.decrypt_attempt_count;
            auto note = shielded::NoteEncryption::TryDecrypt(
                *decoded,
                candidate.pk,
                candidate.sk,
                /*constant_time_scan=*/true);
            if (!note.has_value()) continue;
            if (note->GetCommitment() != fixture.note.GetCommitment()) {
                throw std::runtime_error("v2 scan produced unexpected note commitment");
            }
            ++out.successful_decrypt_count;
        }
    });

    if (out.successful_decrypt_count != 1) {
        throw std::runtime_error("v2 scan did not identify exactly one recipient");
    }
    out.false_positive_hint_count = out.hint_match_count;
    return out;
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
    if ((values.size() % 2) == 1) return values[mid];
    return (values[mid - 1] + values[mid]) / 2;
}

UniValue BuildSummary(const std::vector<uint64_t>& values)
{
    UniValue summary(UniValue::VOBJ);
    summary.pushKV("count", static_cast<uint64_t>(values.size()));
    summary.pushKV("min", values.empty() ? 0 : *std::min_element(values.begin(), values.end()));
    summary.pushKV("median", Median(values));
    summary.pushKV("average", Average(values));
    summary.pushKV("max", values.empty() ? 0 : *std::max_element(values.begin(), values.end()));
    return summary;
}

UniValue BuildFixtureJson(const Fixture& fixture)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("candidate_key_count", static_cast<uint64_t>(fixture.candidate_keys.size()));
    out.pushKV("recipient_index", static_cast<uint64_t>(fixture.recipient_index));
    out.pushKV("scan_domain", "opaque");
    out.pushKV("scan_hint_version", static_cast<uint64_t>(shielded::v2::SCAN_HINT_VERSION));
    out.pushKV("ciphertext_bytes", static_cast<uint64_t>(fixture.payload.ciphertext.size()));
    out.pushKV("scan_hint_hex",
               HexStr(Span<const uint8_t>{fixture.payload.scan_hint.data(), fixture.payload.scan_hint.size()}));
    return out;
}

UniValue BuildMeasurement(const LegacyScanMeasurement& legacy, const V2ScanMeasurement& v2, size_t sample_index)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("sample_index", static_cast<uint64_t>(sample_index));
    out.pushKV("candidate_key_count", legacy.candidate_key_count);
    out.pushKV("legacy_scan_ns", legacy.scan_ns);
    out.pushKV("legacy_decrypt_attempt_count", legacy.decrypt_attempt_count);
    out.pushKV("legacy_successful_decrypt_count", legacy.successful_decrypt_count);
    out.pushKV("legacy_view_tag_match_count", legacy.view_tag_match_count);
    out.pushKV("legacy_false_positive_view_tag_count", legacy.false_positive_view_tag_count);
    out.pushKV("v2_hint_only_ns", v2.hint_only_ns);
    out.pushKV("v2_scan_ns", v2.scan_ns);
    out.pushKV("v2_decrypt_attempt_count", v2.decrypt_attempt_count);
    out.pushKV("v2_successful_decrypt_count", v2.successful_decrypt_count);
    out.pushKV("v2_hint_match_count", v2.hint_match_count);
    out.pushKV("v2_false_positive_hint_count", v2.false_positive_hint_count);
    out.pushKV("v2_wrong_domain_match_count", v2.wrong_domain_match_count);
    out.pushKV("avoided_decrypt_attempts", legacy.decrypt_attempt_count - v2.decrypt_attempt_count);
    out.pushKV("legacy_to_v2_scan_speedup",
               v2.scan_ns == 0 ? 0.0 : static_cast<double>(legacy.scan_ns) / static_cast<double>(v2.scan_ns));
    return out;
}

} // namespace

UniValue BuildRuntimeReport(const RuntimeReportConfig& config)
{
    if (config.measured_iterations == 0) {
        throw std::runtime_error("measured_iterations must be non-zero");
    }

    const Fixture fixture = BuildFixture(config.minimum_candidate_keys);
    for (size_t i = 0; i < config.warmup_iterations; ++i) {
        const auto legacy = RunLegacyWalletScan(fixture);
        const auto v2 = RunV2WalletScan(fixture);
        if (legacy.successful_decrypt_count != 1 || v2.successful_decrypt_count != 1) {
            throw std::runtime_error("scan-hint warmup drifted");
        }
    }

    std::vector<uint64_t> legacy_scan_ns;
    std::vector<uint64_t> v2_hint_only_ns;
    std::vector<uint64_t> v2_scan_ns;
    std::vector<uint64_t> legacy_false_positives;
    std::vector<uint64_t> v2_false_positives;
    std::vector<uint64_t> avoided_decryptions;
    legacy_scan_ns.reserve(config.measured_iterations);
    v2_hint_only_ns.reserve(config.measured_iterations);
    v2_scan_ns.reserve(config.measured_iterations);
    legacy_false_positives.reserve(config.measured_iterations);
    v2_false_positives.reserve(config.measured_iterations);
    avoided_decryptions.reserve(config.measured_iterations);

    UniValue measurements(UniValue::VARR);
    for (size_t i = 0; i < config.measured_iterations; ++i) {
        const auto legacy = RunLegacyWalletScan(fixture);
        const auto v2 = RunV2WalletScan(fixture);
        if (v2.wrong_domain_match_count != 0) {
            throw std::runtime_error("scan-hint domain separation failed");
        }

        legacy_scan_ns.push_back(legacy.scan_ns);
        v2_hint_only_ns.push_back(v2.hint_only_ns);
        v2_scan_ns.push_back(v2.scan_ns);
        legacy_false_positives.push_back(legacy.false_positive_view_tag_count);
        v2_false_positives.push_back(v2.false_positive_hint_count);
        avoided_decryptions.push_back(legacy.decrypt_attempt_count - v2.decrypt_attempt_count);
        measurements.push_back(BuildMeasurement(legacy, v2, i));
    }

    UniValue runtime_config(UniValue::VOBJ);
    runtime_config.pushKV("warmup_iterations", static_cast<uint64_t>(config.warmup_iterations));
    runtime_config.pushKV("measured_iterations", static_cast<uint64_t>(config.measured_iterations));
    runtime_config.pushKV("minimum_candidate_keys", static_cast<uint64_t>(config.minimum_candidate_keys));
    runtime_config.pushKV("duration_unit", "nanoseconds");
    runtime_config.pushKV("clock", "steady_clock");

    UniValue out(UniValue::VOBJ);
    out.pushKV("format_version", 1);
    out.pushKV("report_kind", "shielded_v2_scan_hint_runtime");
    out.pushKV("fixture", BuildFixtureJson(fixture));
    out.pushKV("runtime_config", std::move(runtime_config));
    out.pushKV("legacy_scan_ns_summary", BuildSummary(legacy_scan_ns));
    out.pushKV("v2_hint_only_ns_summary", BuildSummary(v2_hint_only_ns));
    out.pushKV("v2_scan_ns_summary", BuildSummary(v2_scan_ns));
    out.pushKV("legacy_false_positive_view_tag_summary", BuildSummary(legacy_false_positives));
    out.pushKV("v2_false_positive_hint_summary", BuildSummary(v2_false_positives));
    out.pushKV("avoided_decrypt_attempt_summary", BuildSummary(avoided_decryptions));
    out.pushKV("measurements", std::move(measurements));
    return out;
}

} // namespace btx::test::shieldedv2scan

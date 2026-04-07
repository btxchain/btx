// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <consensus/amount.h>
#include <hash.h>
#include <shielded/matrict_plus_backend.h>
#include <shielded/ringct/commitment.h>
#include <shielded/ringct/matrict.h>
#include <shielded/ringct/range_proof.h>
#include <shielded/ringct/ring_signature.h>
#include <streams.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace matrictplus = shielded::matrictplus;
namespace ringct = shielded::ringct;
namespace lattice = shielded::lattice;

template <typename Serializable>
std::vector<unsigned char> SerializeToBytes(const Serializable& value)
{
    DataStream stream;
    stream << value;

    std::vector<unsigned char> out;
    out.reserve(stream.size());
    for (const std::byte byte : stream) {
        out.push_back(std::to_integer<unsigned char>(byte));
    }
    return out;
}

template <typename Serializable>
std::string SerializeToHex(const Serializable& value)
{
    return HexStr(SerializeToBytes(value));
}

ringct::Commitment ComputeBalanceStatement(const std::vector<ringct::Commitment>& input_commitments,
                                          const std::vector<ringct::Commitment>& output_commitments,
                                          CAmount fee)
{
    ringct::Commitment statement{lattice::PolyVec(lattice::MODULE_RANK)};
    for (const auto& commitment : input_commitments) {
        statement = ringct::CommitmentAdd(statement, commitment);
    }
    for (const auto& commitment : output_commitments) {
        statement = ringct::CommitmentSub(statement, commitment);
    }
    return ringct::CommitmentSub(statement, ringct::CommitmentForFee(fee));
}

std::vector<int64_t> BuildPow2ScalarsModQ(size_t count)
{
    std::vector<int64_t> out(count, 0);
    if (count == 0) return out;
    out[0] = 1;
    for (size_t i = 1; i < count; ++i) {
        out[i] = (out[i - 1] * 2) % lattice::POLY_Q;
    }
    return out;
}

ringct::Commitment WeightedBitCommitmentSum(const std::vector<ringct::Commitment>& bit_commitments,
                                            const std::vector<int64_t>& pow2_scalars)
{
    ringct::Commitment out{lattice::PolyVec(lattice::MODULE_RANK)};
    for (size_t i = 0; i < bit_commitments.size(); ++i) {
        out = ringct::CommitmentAdd(out, ringct::CommitmentScale(bit_commitments[i], pow2_scalars[i]));
    }
    return out;
}

ringct::Commitment ComputeRangeStatement(const ringct::Commitment& value_commitment,
                                         const std::vector<ringct::Commitment>& bit_commitments)
{
    const auto pow2_scalars = BuildPow2ScalarsModQ(bit_commitments.size());
    return ringct::CommitmentSub(value_commitment, WeightedBitCommitmentSum(bit_commitments, pow2_scalars));
}

UniValue BuildBitProofJson(const ringct::RangeBitProof& bit_proof)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("c0_hex", bit_proof.c0.GetHex());
    out.pushKV("c1_hex", bit_proof.c1.GetHex());
    out.pushKV("z0_serialized_hex", SerializeToHex(bit_proof.z0));
    out.pushKV("z1_serialized_hex", SerializeToHex(bit_proof.z1));
    return out;
}

UniValue BuildRangeProofJson(const ringct::RangeProof& range_proof,
                             const ringct::Commitment& value_commitment)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("value_commitment_serialized_hex", SerializeToHex(value_commitment));

    UniValue bit_commitments(UniValue::VARR);
    for (const auto& commitment : range_proof.bit_commitments) {
        bit_commitments.push_back(SerializeToHex(commitment));
    }
    out.pushKV("bit_commitments_serialized_hex", std::move(bit_commitments));

    UniValue bit_proofs(UniValue::VARR);
    for (const auto& bit_proof : range_proof.bit_proofs) {
        bit_proofs.push_back(BuildBitProofJson(bit_proof));
    }
    out.pushKV("bit_proofs", std::move(bit_proofs));

    out.pushKV("relation_nonce_commitment_serialized_hex",
               SerializeToHex(range_proof.relation_nonce_commitment));
    out.pushKV("statement_commitment_serialized_hex",
               SerializeToHex(ComputeRangeStatement(value_commitment, range_proof.bit_commitments)));
    out.pushKV("expected_bit_proof_binding_hex", range_proof.bit_proof_binding.GetHex());
    out.pushKV("expected_transcript_hash_hex", range_proof.transcript_hash.GetHex());
    return out;
}

UniValue BuildRingSignatureJson(const ringct::MatRiCTProof& proof,
                                const matrictplus::PortableFixture& fixture)
{
    std::vector<std::vector<std::vector<unsigned char>>> transcript_chunks;
    if (!ringct::ExportRingSignatureTranscriptChunks(transcript_chunks,
                                                     proof.ring_signature,
                                                     fixture.ring_members,
                                                     ringct::RingSignatureMessageHash(proof.input_commitments,
                                                                                      proof.output_commitments,
                                                                                      fixture.fee,
                                                                                      fixture.input_nullifiers,
                                                                                      fixture.tx_binding_hash))) {
        throw std::runtime_error("failed to export ring-signature transcript chunks");
    }

    UniValue out(UniValue::VOBJ);
    out.pushKV("message_hash_hex",
               ringct::RingSignatureMessageHash(proof.input_commitments,
                                                proof.output_commitments,
                                                fixture.fee,
                                                fixture.input_nullifiers,
                                                fixture.tx_binding_hash).GetHex());

    UniValue ring_members(UniValue::VARR);
    for (const auto& ring : fixture.ring_members) {
        UniValue row(UniValue::VARR);
        for (const auto& member : ring) {
            row.push_back(member.GetHex());
        }
        ring_members.push_back(std::move(row));
    }
    out.pushKV("ring_members_hex", std::move(ring_members));

    UniValue key_images(UniValue::VARR);
    for (const auto& key_image : proof.ring_signature.key_images) {
        key_images.push_back(SerializeToHex(key_image));
    }
    out.pushKV("key_images_serialized_hex", std::move(key_images));

    UniValue offsets(UniValue::VARR);
    for (const auto& input_offsets : proof.ring_signature.member_public_key_offsets) {
        UniValue row(UniValue::VARR);
        for (const auto& offset : input_offsets) {
            row.push_back(SerializeToHex(offset));
        }
        offsets.push_back(std::move(row));
    }
    out.pushKV("member_public_key_offsets_serialized_hex", std::move(offsets));

    UniValue chunks(UniValue::VARR);
    for (const auto& input_chunks : transcript_chunks) {
        UniValue row(UniValue::VARR);
        for (const auto& chunk : input_chunks) {
            row.push_back(HexStr(chunk));
        }
        chunks.push_back(std::move(row));
    }
    out.pushKV("transcript_chunks_serialized_hex", std::move(chunks));
    out.pushKV("expected_challenge_seed_hex", proof.ring_signature.challenge_seed.GetHex());
    return out;
}

UniValue BuildBalanceProofJson(const ringct::MatRiCTProof& proof,
                               const matrictplus::PortableFixture& fixture)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("nonce_commitment_serialized_hex",
               SerializeToHex(proof.balance_proof.nonce_commitment));

    UniValue input_commitments(UniValue::VARR);
    for (const auto& commitment : proof.input_commitments) {
        input_commitments.push_back(SerializeToHex(commitment));
    }
    out.pushKV("input_commitments_serialized_hex", std::move(input_commitments));

    UniValue output_commitments(UniValue::VARR);
    for (const auto& commitment : proof.output_commitments) {
        output_commitments.push_back(SerializeToHex(commitment));
    }
    out.pushKV("output_commitments_serialized_hex", std::move(output_commitments));

    out.pushKV("statement_commitment_serialized_hex",
               SerializeToHex(ComputeBalanceStatement(proof.input_commitments,
                                                     proof.output_commitments,
                                                     fixture.fee)));
    out.pushKV("expected_transcript_hash_hex", proof.balance_proof.transcript_hash.GetHex());
    return out;
}

UniValue BuildSampleJson(const std::string& label,
                         const matrictplus::PortableFixture& fixture,
                         const ringct::MatRiCTProof& proof,
                         const std::optional<uint256>& seed)
{
    UniValue sample(UniValue::VOBJ);
    sample.pushKV("label", label);
    if (seed.has_value()) {
        sample.pushKV("seed_hex", seed->GetHex());
    }
    sample.pushKV("verification_expected", true);
    sample.pushKV("serialized_proof_hash_hex", matrictplus::SerializeProofHash(proof).GetHex());

    UniValue fixture_json(UniValue::VOBJ);
    UniValue input_nullifiers(UniValue::VARR);
    for (const auto& nullifier : fixture.input_nullifiers) {
        input_nullifiers.push_back(nullifier.GetHex());
    }
    fixture_json.pushKV("input_nullifiers_hex", std::move(input_nullifiers));

    UniValue output_note_commitments(UniValue::VARR);
    for (const auto& commitment : fixture.output_note_commitments) {
        output_note_commitments.push_back(commitment.GetHex());
    }
    fixture_json.pushKV("output_note_commitments_hex", std::move(output_note_commitments));
    fixture_json.pushKV("fee_sat", static_cast<int64_t>(fixture.fee));
    fixture_json.pushKV("tx_binding_hash_hex", fixture.tx_binding_hash.GetHex());
    sample.pushKV("fixture", std::move(fixture_json));

    UniValue transcripts(UniValue::VOBJ);
    transcripts.pushKV("ring_signature", BuildRingSignatureJson(proof, fixture));
    transcripts.pushKV("balance_proof", BuildBalanceProofJson(proof, fixture));

    UniValue range_proofs(UniValue::VARR);
    for (size_t i = 0; i < proof.output_range_proofs.size(); ++i) {
        range_proofs.push_back(BuildRangeProofJson(proof.output_range_proofs[i],
                                                   proof.output_commitments[i]));
    }
    transcripts.pushKV("range_proofs", std::move(range_proofs));

    UniValue top_level(UniValue::VOBJ);
    top_level.pushKV("ring_signature_challenge_seed_hex", proof.ring_signature.challenge_seed.GetHex());
    top_level.pushKV("balance_proof_transcript_hash_hex", proof.balance_proof.transcript_hash.GetHex());
    UniValue range_transcripts(UniValue::VARR);
    for (const auto& range_proof : proof.output_range_proofs) {
        range_transcripts.push_back(range_proof.transcript_hash.GetHex());
    }
    top_level.pushKV("range_proof_transcript_hashes_hex", std::move(range_transcripts));
    UniValue output_note_commitments_top(UniValue::VARR);
    for (const auto& commitment : proof.output_note_commitments) {
        output_note_commitments_top.push_back(commitment.GetHex());
    }
    top_level.pushKV("output_note_commitments_hex", std::move(output_note_commitments_top));
    top_level.pushKV("expected_challenge_seed_hex", proof.challenge_seed.GetHex());
    transcripts.pushKV("top_level_proof", std::move(top_level));

    sample.pushKV("transcripts", std::move(transcripts));
    return sample;
}

uint256 DeriveSampleSeed(const uint256& base_seed, uint32_t index)
{
    HashWriter hw;
    hw << std::string{"BTX_MatRiCTPlus_TranscriptCorpus_V1"};
    hw << base_seed;
    hw << index;
    return hw.GetSHA256();
}

size_t ParsePositiveSize(std::string_view value, std::string_view option_name, bool allow_zero)
{
    const auto parsed = std::stoull(std::string{value});
    if (!allow_zero && parsed == 0) {
        throw std::runtime_error(std::string{option_name} + " must be greater than zero");
    }
    return static_cast<size_t>(parsed);
}

uint256 ParseSeed(std::string_view value)
{
    const auto parsed = uint256::FromHex(std::string{value});
    if (!parsed.has_value()) {
        throw std::runtime_error("--seed must be a valid 32-byte hex string");
    }
    return *parsed;
}

UniValue BuildCorpus(size_t random_samples, const uint256& base_seed)
{
    UniValue out(UniValue::VOBJ);
    out.pushKV("format_version", 1);
    out.pushKV("backend_id_hex", matrictplus::GetBackendId().GetHex());
    out.pushKV("random_sample_count", static_cast<uint64_t>(random_samples));
    out.pushKV("base_seed_hex", base_seed.GetHex());

    UniValue params(UniValue::VOBJ);
    params.pushKV("poly_n", static_cast<uint64_t>(lattice::POLY_N));
    params.pushKV("poly_q", static_cast<int64_t>(lattice::POLY_Q));
    params.pushKV("module_rank", static_cast<uint64_t>(lattice::MODULE_RANK));
    params.pushKV("ring_size", static_cast<uint64_t>(lattice::RING_SIZE));
    params.pushKV("value_bits", static_cast<uint64_t>(lattice::VALUE_BITS));
    out.pushKV("parameters", std::move(params));

    UniValue samples(UniValue::VARR);

    const auto deterministic_fixture = matrictplus::BuildDeterministicFixture();
    ringct::MatRiCTProof deterministic_proof;
    if (!matrictplus::CreateProof(deterministic_proof, deterministic_fixture) ||
        !matrictplus::VerifyProof(deterministic_proof, deterministic_fixture)) {
        throw std::runtime_error("failed to build deterministic MatRiCT+ transcript sample");
    }
    samples.push_back(BuildSampleJson("deterministic", deterministic_fixture, deterministic_proof, std::nullopt));

    for (size_t i = 0; i < random_samples; ++i) {
        const uint256 sample_seed = DeriveSampleSeed(base_seed, static_cast<uint32_t>(i));
        const auto fixture = matrictplus::BuildFixtureFromSeed(sample_seed);
        ringct::MatRiCTProof proof;
        if (!matrictplus::CreateProof(proof, fixture) || !matrictplus::VerifyProof(proof, fixture)) {
            throw std::runtime_error("failed to build randomized MatRiCT+ transcript sample");
        }
        samples.push_back(BuildSampleJson("random-" + std::to_string(i),
                                          fixture,
                                          proof,
                                          sample_seed));
    }

    out.pushKV("samples", std::move(samples));
    return out;
}

} // namespace

int main(int argc, char** argv)
{
    try {
        size_t random_samples{2};
        const auto default_seed = uint256::FromHex("0000000000000000000000000000000000000000000000000000000000005172");
        if (!default_seed.has_value()) {
            throw std::runtime_error("failed to initialize default transcript corpus seed");
        }
        uint256 base_seed = *default_seed;
        fs::path output_path;

        for (int i = 1; i < argc; ++i) {
            const std::string_view arg{argv[i]};
            if (arg == "--help") {
                std::cout << "Usage: gen_shielded_matrict_plus_transcript_corpus "
                             "[--samples=N] [--seed=<32-byte-hex>] [--output=/path/report.json]\n";
                std::exit(0);
            }
            if (arg.starts_with("--samples=")) {
                random_samples = ParsePositiveSize(arg.substr(10), "--samples", /*allow_zero=*/true);
                continue;
            }
            if (arg.starts_with("--seed=")) {
                base_seed = ParseSeed(arg.substr(7));
                continue;
            }
            if (arg.starts_with("--output=")) {
                output_path = fs::PathFromString(std::string{arg.substr(9)});
                continue;
            }
            throw std::runtime_error("unknown argument: " + std::string{arg});
        }

        const std::string json = BuildCorpus(random_samples, base_seed).write(2) + '\n';
        if (output_path.empty()) {
            std::cout << json;
        } else {
            std::ofstream output{output_path};
            if (!output.is_open()) {
                throw std::runtime_error("unable to open output path");
            }
            output << json;
        }
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "gen_shielded_matrict_plus_transcript_corpus: " << e.what() << '\n';
        return 1;
    }
}

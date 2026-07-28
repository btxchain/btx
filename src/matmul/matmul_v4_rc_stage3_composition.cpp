// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_composition.h>

#include <hash.h>

#include <cstdint>
#include <string>

namespace matmul::v4::rc {
namespace {

constexpr char TRANSCRIPT_DOMAIN[] = "BTX_RC_STAGE3_TRANSCRIPT_V2";
constexpr char AGGREGATION_DOMAIN[] = "BTX_RC_STAGE3_AGGREGATION_V2";
constexpr char COMPOSED_DIGEST_DOMAIN[] = "BTX_RC_STAGE3_COMPOSED_DIGEST_V1";
constexpr char SECTION_DOMAIN[] = "BTX_RC_STAGE3_SECTION_V1";

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) *why = "stage3:composition:" + message;
    return false;
}

uint256 SectionDigest(const RCStage3ProofSection& section)
{
    HashWriter hash;
    hash << SECTION_DOMAIN;
    hash << static_cast<uint16_t>(section.role);
    hash << static_cast<uint32_t>(section.proof.size());
    for (const unsigned char byte : section.proof) hash << byte;
    return hash.GetHash();
}

void WritePublicContext(HashWriter& hash, const RCStage3SuccinctProof& proof)
{
    const auto& p = proof.public_inputs;
    hash << proof.magic;
    hash << proof.version;
    hash << static_cast<uint8_t>(proof.authority);
    hash << static_cast<uint8_t>(proof.statement);
    hash << p.height;
    hash << p.n_bits;
    hash << p.episode_profile;
    hash << p.coupled_profile;
    hash << p.transcript_version;
    hash << p.program_consensus_pin.version;
    hash << p.program_consensus_pin.recursive_alg_hash_root;
    hash << p.program_consensus_pin.external_sha256d_audit_root;
    hash << p.program_consensus_pin.registry_binding;
    hash << p.header_commitment;
    hash << p.params_commitment;
    hash << p.target;
    hash << p.sigma;
    hash << p.episode_digest;
    hash << p.coupled_digest;
    hash << p.final_digest;
}

} // namespace

uint256 ComputeRCStage3TranscriptCommitment(const RCStage3SuccinctProof& proof)
{
    HashWriter hash;
    hash << TRANSCRIPT_DOMAIN;
    WritePublicContext(hash, proof);

    hash << static_cast<uint32_t>(proof.commitments.size());
    for (const auto& commitment : proof.commitments) {
        hash << static_cast<uint16_t>(commitment.role);
        hash << commitment.root;
    }

    hash << static_cast<uint32_t>(proof.sections.size());
    for (const auto& section : proof.sections) {
        hash << static_cast<uint16_t>(section.role);
        hash << SectionDigest(section);
    }
    return hash.GetHash();
}

uint256 ComputeRCStage3AggregationSeed(const RCStage3SuccinctProof& proof)
{
    HashWriter hash;
    hash << AGGREGATION_DOMAIN;
    WritePublicContext(hash, proof);
    return hash.GetHash();
}

uint256 ComputeRCStage3FinalDigest(const RCStage3SuccinctProof& proof)
{
    const auto& p = proof.public_inputs;
    if (proof.statement == RCStage3StatementKind::Episode) return p.episode_digest;
    if (proof.statement == RCStage3StatementKind::Coupled) return p.coupled_digest;
    if (proof.statement != RCStage3StatementKind::Composed) return {};

    return ComputeRCStage3ComposedWorkDigest(
        proof.version, p.height, p.header_commitment, p.params_commitment,
        p.episode_profile, p.coupled_profile, p.transcript_version,
        p.episode_digest, p.coupled_digest);
}

uint256 ComputeRCStage3ComposedWorkDigest(
    uint16_t proof_version,
    int32_t height,
    const uint256& header_commitment,
    const uint256& params_commitment,
    uint32_t episode_profile,
    uint32_t coupled_profile,
    uint32_t transcript_version,
    const uint256& episode_digest,
    const uint256& coupled_digest)
{
    if (proof_version == 0 || height < 0 ||
        header_commitment.IsNull() || params_commitment.IsNull() ||
        episode_profile == 0 || coupled_profile == 0 ||
        transcript_version == 0 || episode_digest.IsNull() ||
        coupled_digest.IsNull()) {
        return {};
    }

    HashWriter hash;
    hash << COMPOSED_DIGEST_DOMAIN;
    hash << proof_version;
    hash << height;
    hash << header_commitment;
    hash << params_commitment;
    hash << episode_profile;
    hash << coupled_profile;
    hash << transcript_version;
    hash << episode_digest;
    hash << coupled_digest;
    return hash.GetHash();
}

bool VerifyRCStage3CompositionLink(const RCStage3SuccinctProof& proof, std::string* why)
{
    std::string structure_why;
    if (!ValidateRCStage3ProofStructure(proof, &structure_why)) {
        return Fail(why, structure_why);
    }

    const uint256 expected_final = ComputeRCStage3FinalDigest(proof);
    if (expected_final.IsNull()) return Fail(why, "null_expected_final_digest");
    if (proof.public_inputs.final_digest != expected_final) {
        return Fail(why, "final_digest_mismatch");
    }

    const uint256 expected_transcript = ComputeRCStage3TranscriptCommitment(proof);
    if (expected_transcript.IsNull()) return Fail(why, "null_transcript");
    if (proof.public_inputs.transcript_commitment != expected_transcript) {
        return Fail(why, "transcript_commitment_mismatch");
    }
    return true;
}

} // namespace matmul::v4::rc

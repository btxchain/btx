// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_consensus.h>

#include <consensus/params.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_consensus_tests, BasicTestingSetup)

namespace {

uint256 Filled(unsigned char byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

Consensus::Params MakeParams(bool coupled)
{
    Consensus::Params params;
    params.fMatMulPOW = true;
    params.nMatMulV4Height = 1;
    params.nMatMulRCHeight = 1;
    params.nMatMulRCProfile = 2;
    params.fMatMulRCUseToyDims = true;
    params.nMatMulV4Dimension = 256;
    params.hashMatMulRCStage3ProgramRegistryAlgRoot = Filled(0x91);
    params.hashMatMulRCStage3ProgramRegistryShaAuditRoot = Filled(0x92);
    params.hashMatMulRCStage3ProgramRegistryBinding = Filled(0x93);
    params.powLimit =
        uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    if (coupled) {
        params.nMatMulRCCoupledHeight = 1;
        params.nMatMulRCCoupledProfile = 3;
        params.fMatMulRCCoupledUseToyDims = true;
    }
    return params;
}

CBlock MakeBlock()
{
    CBlock block;
    block.nVersion = 4;
    block.hashPrevBlock = Filled(0x10);
    block.hashMerkleRoot = Filled(0x20);
    block.nTime = 1'700'000'000;
    block.nBits = 0x207fffff;
    block.nNonce64 = 99;
    block.matmul_digest = Filled(0x30);
    block.matmul_dim = 256;
    block.seed_a = Filled(0x40);
    block.seed_b = Filled(0x50);
    return block;
}

rc::RCStage3SuccinctProof MakeBoundProof(const CBlock& block,
                                         const Consensus::Params& params,
                                         int32_t height,
                                         const uint256& target)
{
    const rc::RCStage3StatementKind statement =
        rc::RequiredRCStage3Statement(params, height).value();

    rc::RCStage3SuccinctProof proof;
    proof.statement = statement;
    auto& p = proof.public_inputs;
    p.height = height;
    p.n_bits = block.nBits;
    p.episode_profile = params.nMatMulRCProfile;
    p.coupled_profile =
        statement == rc::RCStage3StatementKind::Composed
            ? params.nMatMulRCCoupledProfile
            : 0;
    p.transcript_version =
        statement == rc::RCStage3StatementKind::Composed
            ? rc::ResolveRCCoupOptions(params).transcript_version
            : rc::kRCTranscriptVersion;
    p.program_consensus_pin.recursive_alg_hash_root =
        params.hashMatMulRCStage3ProgramRegistryAlgRoot;
    p.program_consensus_pin.external_sha256d_audit_root =
        params.hashMatMulRCStage3ProgramRegistryShaAuditRoot;
    p.program_consensus_pin.registry_binding =
        params.hashMatMulRCStage3ProgramRegistryBinding;
    p.header_commitment = rc::RCStage3HeaderCommitment(block);
    p.params_commitment = rc::RCStage3ParamsCommitment(params, height, statement);
    p.target = target;
    p.sigma = matmul::v4::DeriveSigma(block);
    p.episode_digest =
        statement == rc::RCStage3StatementKind::Episode
            ? block.matmul_digest
            : Filled(0x60);
    p.coupled_digest =
        statement == rc::RCStage3StatementKind::Composed
            ? Filled(0x70)
            : uint256{};
    p.final_digest = block.matmul_digest;
    p.transcript_commitment = Filled(0x80);

    const auto roles = rc::RequiredRCStage3RelationRoles(statement);
    for (size_t i = 0; i < roles.size(); ++i) {
        proof.commitments.push_back(
            {roles[i], Filled(static_cast<unsigned char>(0x90 + i))});
        proof.sections.push_back(
            {roles[i], {static_cast<unsigned char>(i), 0xa5, 0x5a}});
    }
    return proof;
}

} // namespace

BOOST_AUTO_TEST_CASE(required_statement_makes_coupled_additive)
{
    constexpr int32_t HEIGHT{10};
    auto params = MakeParams(false);
    BOOST_REQUIRE(rc::RequiredRCStage3Statement(params, HEIGHT).has_value());
    BOOST_CHECK(*rc::RequiredRCStage3Statement(params, HEIGHT) ==
                rc::RCStage3StatementKind::Episode);

    params.nMatMulRCCoupledHeight = 1;
    params.nMatMulRCCoupledProfile = 3;
    params.fMatMulRCCoupledUseToyDims = true;
    BOOST_CHECK(*rc::RequiredRCStage3Statement(params, HEIGHT) ==
                rc::RCStage3StatementKind::Composed);

    // Coupled-only activation still selects Composed, then binding fails
    // closed because the episode leg is not active.
    params.nMatMulRCHeight = std::numeric_limits<int32_t>::max();
    BOOST_CHECK(*rc::RequiredRCStage3Statement(params, HEIGHT) ==
                rc::RCStage3StatementKind::Composed);
}

BOOST_AUTO_TEST_CASE(header_projection_avoids_final_digest_fixed_point)
{
    CBlock block = MakeBlock();
    const uint256 commitment = rc::RCStage3HeaderCommitment(block);

    block.matmul_digest = Filled(0xee);
    BOOST_CHECK(rc::RCStage3HeaderCommitment(block) == commitment);

    ++block.nNonce64;
    BOOST_CHECK(rc::RCStage3HeaderCommitment(block) != commitment);
}

BOOST_AUTO_TEST_CASE(bound_attachment_parses_then_stops_at_authority_gate)
{
    constexpr int32_t HEIGHT{10};
    const auto params = MakeParams(true);
    CBlock block = MakeBlock();
    const uint256 target = Filled(0xff);
    const auto proof = MakeBoundProof(block, params, HEIGHT, target);
    std::string why;
    BOOST_REQUIRE(rc::PackRCStage3ProofWords(proof, block.matrix_c_data, &why));

    rc::RCStage3SuccinctProof decoded;
    rc::RCStage3ProofCacheKey key;
    const auto status = rc::InspectRCStage3ConsensusAttachment(
        block, params, HEIGHT, target, &decoded, &key, &why);
    BOOST_CHECK(status == rc::RCStage3AttachmentStatus::AuthorityUnavailable);
    BOOST_CHECK(why.find("authority_unavailable") != std::string::npos);
    BOOST_CHECK(decoded == proof);
    BOOST_CHECK(key.block_hash == block.GetHash());
    BOOST_CHECK(
        key.program_registry_alg_root ==
        params.hashMatMulRCStage3ProgramRegistryAlgRoot);
    BOOST_CHECK(key.proof_payload_digest ==
                rc::RCStage3ProofPayloadDigest(block.matrix_c_data));
    BOOST_CHECK(!rc::RCStage3AttachmentIsMutation(status));
}

BOOST_AUTO_TEST_CASE(missing_malformed_and_wrong_binding_are_mutations)
{
    constexpr int32_t HEIGHT{10};
    const auto params = MakeParams(false);
    const uint256 target = Filled(0xff);
    CBlock block = MakeBlock();
    std::string why;

    auto status =
        rc::InspectRCStage3ConsensusAttachment(block, params, HEIGHT, target,
                                               nullptr, nullptr, &why);
    BOOST_CHECK(status == rc::RCStage3AttachmentStatus::Missing);
    BOOST_CHECK(rc::RCStage3AttachmentIsMutation(status));

    block.matrix_c_data = {rc::kRCStage3BlockPayloadMagic, 64, 1};
    status = rc::InspectRCStage3ConsensusAttachment(
        block, params, HEIGHT, target, nullptr, nullptr, &why);
    BOOST_CHECK(status == rc::RCStage3AttachmentStatus::Malformed);
    BOOST_CHECK(rc::RCStage3AttachmentIsMutation(status));

    auto proof = MakeBoundProof(block, params, HEIGHT, target);
    proof.public_inputs.height = HEIGHT + 1;
    BOOST_REQUIRE(rc::PackRCStage3ProofWords(proof, block.matrix_c_data, &why));
    status = rc::InspectRCStage3ConsensusAttachment(
        block, params, HEIGHT, target, nullptr, nullptr, &why);
    BOOST_CHECK(status == rc::RCStage3AttachmentStatus::BindingMismatch);
    BOOST_CHECK(why.find("height") != std::string::npos);
    BOOST_CHECK(rc::RCStage3AttachmentIsMutation(status));
}

BOOST_AUTO_TEST_CASE(binding_pins_header_params_target_and_composition)
{
    constexpr int32_t HEIGHT{10};
    const auto params = MakeParams(true);
    const CBlock block = MakeBlock();
    const uint256 target = Filled(0xff);
    const auto proof = MakeBoundProof(block, params, HEIGHT, target);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::ValidateRCStage3ConsensusBinding(
            proof, block, params, HEIGHT, target, &why),
        why);

    auto bad = proof;
    bad.public_inputs.header_commitment = Filled(0x01);
    BOOST_CHECK(!rc::ValidateRCStage3ConsensusBinding(
        bad, block, params, HEIGHT, target, &why));
    BOOST_CHECK(why.find("header_commitment") != std::string::npos);

    bad = proof;
    bad.public_inputs.params_commitment = Filled(0x02);
    BOOST_CHECK(!rc::ValidateRCStage3ConsensusBinding(
        bad, block, params, HEIGHT, target, &why));
    BOOST_CHECK(why.find("params_commitment") != std::string::npos);

    bad = proof;
    bad.public_inputs.target = Filled(0x03);
    BOOST_CHECK(!rc::ValidateRCStage3ConsensusBinding(
        bad, block, params, HEIGHT, target, &why));
    BOOST_CHECK(why.find("target") != std::string::npos);

    bad = proof;
    bad.public_inputs.program_consensus_pin.recursive_alg_hash_root =
        Filled(0x94);
    BOOST_CHECK(!rc::ValidateRCStage3ConsensusBinding(
        bad, block, params, HEIGHT, target, &why));
    BOOST_CHECK(
        why.find("program_registry_alg_root") !=
        std::string::npos);

    bad = proof;
    bad.public_inputs.program_consensus_pin.registry_binding =
        Filled(0x95);
    BOOST_CHECK(!rc::ValidateRCStage3ConsensusBinding(
        bad, block, params, HEIGHT, target, &why));
    BOOST_CHECK(
        why.find("program_registry_binding") !=
        std::string::npos);

    bad = proof;
    bad.statement = rc::RCStage3StatementKind::Coupled;
    BOOST_CHECK(!rc::ValidateRCStage3ConsensusBinding(
        bad, block, params, HEIGHT, target, &why));
}

BOOST_AUTO_TEST_CASE(producer_attachment_is_canonical_and_atomic)
{
    constexpr int32_t HEIGHT{10};
    const auto params = MakeParams(true);
    const uint256 target = Filled(0xff);
    CBlock block = MakeBlock();
    const auto proof = MakeBoundProof(block, params, HEIGHT, target);
    std::string why;

    BOOST_REQUIRE_MESSAGE(
        rc::AttachRCStage3ConsensusProof(
            block, proof, params, HEIGHT, target, &why),
        why);
    const std::vector<uint32_t> attached = block.matrix_c_data;
    const auto unpacked = rc::UnpackRCStage3ProofWords(attached, &why);
    BOOST_REQUIRE_MESSAGE(unpacked.has_value(), why);
    BOOST_CHECK(*unpacked == proof);

    auto wrong = proof;
    wrong.public_inputs.n_bits ^= 1U;
    BOOST_CHECK(!rc::AttachRCStage3ConsensusProof(
        block, wrong, params, HEIGHT, target, &why));
    BOOST_CHECK(block.matrix_c_data == attached);
}

BOOST_AUTO_TEST_CASE(valid_cache_key_is_body_aware)
{
    const auto params = MakeParams(false);
    constexpr int32_t HEIGHT{10};
    const uint256 target = Filled(0xff);
    CBlock block = MakeBlock();
    auto proof = MakeBoundProof(block, params, HEIGHT, target);
    std::string why;
    BOOST_REQUIRE(rc::PackRCStage3ProofWords(proof, block.matrix_c_data, &why));
    const rc::RCStage3ProofCacheKey first = rc::RCStage3ProofKey(block);
    BOOST_CHECK(!first.block_hash.IsNull());
    BOOST_CHECK(!first.program_registry_alg_root.IsNull());
    BOOST_CHECK(!first.proof_payload_digest.IsNull());

    // matrix_c_data is outside the header hash. A different proof body for the
    // same header must not inherit the first body's positive verdict.
    proof.sections.front().proof.push_back(0x42);
    BOOST_REQUIRE(rc::PackRCStage3ProofWords(proof, block.matrix_c_data, &why));
    const rc::RCStage3ProofCacheKey second = rc::RCStage3ProofKey(block);
    BOOST_CHECK(first.block_hash == second.block_hash);
    BOOST_CHECK(
        first.program_registry_alg_root ==
        second.program_registry_alg_root);
    BOOST_CHECK(first.proof_payload_digest != second.proof_payload_digest);

    // A canonical but different registry pin partitions the cache namespace
    // even though matrix_c_data remains outside the block header hash.
    proof.public_inputs.program_consensus_pin.recursive_alg_hash_root =
        Filled(0x94);
    BOOST_REQUIRE(rc::PackRCStage3ProofWords(
        proof, block.matrix_c_data, &why));
    const rc::RCStage3ProofCacheKey third =
        rc::RCStage3ProofKey(block);
    BOOST_CHECK(first.block_hash == third.block_hash);
    BOOST_CHECK(
        first.program_registry_alg_root !=
        third.program_registry_alg_root);
    BOOST_CHECK(
        second.proof_payload_digest !=
        third.proof_payload_digest);

    const rc::RCStage3ProofCacheKey null_key{};
    BOOST_CHECK(null_key.block_hash.IsNull());
    BOOST_CHECK(null_key.program_registry_alg_root.IsNull());
    BOOST_CHECK(null_key.proof_payload_digest.IsNull());
}

BOOST_AUTO_TEST_CASE(program_registry_pin_is_consensus_owned_and_fail_closed)
{
    constexpr int32_t HEIGHT{10};
    const uint256 target = Filled(0xff);
    const CBlock block = MakeBlock();
    const auto configured = MakeParams(true);
    const auto proof =
        MakeBoundProof(block, configured, HEIGHT, target);
    std::string why;

    auto unconfigured = configured;
    unconfigured.hashMatMulRCStage3ProgramRegistryAlgRoot.SetNull();
    BOOST_CHECK(!rc::ValidateRCStage3ConsensusBinding(
        proof, block, unconfigured, HEIGHT, target, &why));
    BOOST_CHECK(
        why.find("program_registry_unconfigured") !=
        std::string::npos);

    auto substituted = configured;
    substituted.hashMatMulRCStage3ProgramRegistryAlgRoot =
        Filled(0x94);
    BOOST_CHECK(!rc::ValidateRCStage3ConsensusBinding(
        proof, block, substituted, HEIGHT, target, &why));
    BOOST_CHECK(
        why.find("program_registry_alg_root") !=
        std::string::npos);

    auto missing_binding = configured;
    missing_binding.hashMatMulRCStage3ProgramRegistryBinding.SetNull();
    BOOST_CHECK(!rc::ValidateRCStage3ConsensusBinding(
        proof, block, missing_binding, HEIGHT, target, &why));
    BOOST_CHECK(
        why.find("program_registry_expected_pin") !=
        std::string::npos);
}

// SEAM CONTRACT (validation.cpp ContextualCheckBlock, the Stage-3 authority
// branch). The consensus seam maps VerifyRCStage3ConsensusAttachment's status
// to a BlockValidationResult exactly as follows:
//   Valid                         -> accept body (ContextualCheckBlockBodyOnly)
//   Missing / Malformed /
//   BindingMismatch /
//   MathematicalVerificationFailed-> BLOCK_MUTATED  (IsMutation == true)
//   AuthorityUnavailable /
//   NotRequired                   -> fail-closed BLOCK_CONSENSUS (not a mutation)
// This test pins that contract AND asserts the operative reality of the default
// (mainnet-shaped) build: a fully well-formed, correctly-bound proof reaches
// AuthorityUnavailable, i.e. it FAILS CLOSED and is NEVER accepted. Reaching
// Valid requires kRCStage3SuccinctAuthorityReady && the complete mathematical
// verifier; both are compile-time false (matmul_v4_rc_stage3_verify.cpp static-
// asserts that authority cannot precede the verifier), because the Stage-3
// soundness constructions are unproven. So the succinct proof is WIRED as the
// authority seam but cannot be the operative authority; ExactReplay remains the
// dispute fallback and the sole operative authority.
BOOST_AUTO_TEST_CASE(seam_status_to_consensus_result_contract_is_fail_closed)
{
    constexpr int32_t HEIGHT{10};
    const auto params = MakeParams(true);
    const uint256 target = Filled(0xff);
    CBlock block = MakeBlock();
    std::string why;

    // Authority is compile-time unavailable: the seam must NOT be able to
    // accept, and this is not a compile-time-flippable state (soundness open).
    BOOST_CHECK(!rc::kRCStage3SuccinctAuthorityReady);

    // A well-formed, correctly-bound proof: the full authority entry point
    // (VerifyRCStage3ConsensusAttachment, not just Inspect) fails closed to
    // AuthorityUnavailable -> the seam emits BLOCK_CONSENSUS, never accept.
    const auto proof = MakeBoundProof(block, params, HEIGHT, target);
    BOOST_REQUIRE(rc::PackRCStage3ProofWords(proof, block.matrix_c_data, &why));
    auto status = rc::VerifyRCStage3ConsensusAttachment(
        block, params, HEIGHT, target, &why);
    BOOST_CHECK(status == rc::RCStage3AttachmentStatus::AuthorityUnavailable);
    BOOST_CHECK(status != rc::RCStage3AttachmentStatus::Valid);
    BOOST_CHECK(!rc::RCStage3AttachmentIsMutation(status)); // -> BLOCK_CONSENSUS

    // Missing body -> mutation -> BLOCK_MUTATED (a relayer stripping the proof
    // must not poison the honest header).
    block.matrix_c_data.clear();
    status = rc::VerifyRCStage3ConsensusAttachment(
        block, params, HEIGHT, target, &why);
    BOOST_CHECK(status == rc::RCStage3AttachmentStatus::Missing);
    BOOST_CHECK(rc::RCStage3AttachmentIsMutation(status)); // -> BLOCK_MUTATED

    // Malformed body -> mutation -> BLOCK_MUTATED.
    block.matrix_c_data = {rc::kRCStage3BlockPayloadMagic, 64, 1};
    status = rc::VerifyRCStage3ConsensusAttachment(
        block, params, HEIGHT, target, &why);
    BOOST_CHECK(status == rc::RCStage3AttachmentStatus::Malformed);
    BOOST_CHECK(rc::RCStage3AttachmentIsMutation(status)); // -> BLOCK_MUTATED

    // Wrong binding (height off by one) -> mutation -> BLOCK_MUTATED.
    auto wrong = MakeBoundProof(block, params, HEIGHT, target);
    wrong.public_inputs.height = HEIGHT + 1;
    BOOST_REQUIRE(rc::PackRCStage3ProofWords(wrong, block.matrix_c_data, &why));
    status = rc::VerifyRCStage3ConsensusAttachment(
        block, params, HEIGHT, target, &why);
    BOOST_CHECK(status == rc::RCStage3AttachmentStatus::BindingMismatch);
    BOOST_CHECK(rc::RCStage3AttachmentIsMutation(status)); // -> BLOCK_MUTATED
}

BOOST_AUTO_TEST_SUITE_END()

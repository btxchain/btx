// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// PR-89 item 5 — consensus + miner integration for the Stage-3 succinct proof.
//
// SCOPE / HONESTY NOTE. These tests exercise the PRODUCER->WIRE->CONSUMER loop:
// a proof is attached to a block by the producer seam, serialized into
// matrix_c_data, then parsed and consensus-bound back out by the same code
// validation.cpp calls. They do NOT establish that any relation proof is
// mathematically sound, and they cannot reach full block acceptance, because
// kRCStage3SuccinctAuthorityReady is false and validation.cpp's Stage-3 branch
// is therefore compiled out. What "a valid proof validates" can mean today is
// exactly: every consensus binding check passes and the pipeline stops at the
// authority gate (AuthorityUnavailable) rather than at a mutation verdict. That
// distinction is asserted explicitly below.
//
// REAL DATA. The block bytes are a genuine ENC_RC block, captured via getblock
// verbosity 0 from the RC regtest chain at /home/administrator/rcepisode-chain
// (RPC 19335; conf sets regtestrccoupledheight=1000 so the required statement
// is Episode, not Composed). Regtest activates RC at height 101
// (kernel/chainparams.cpp), so height 102 is genuinely RC-ACTIVE: its header
// carries a real solved matmul_digest, real seed_a/seed_b and a real nNonce64
// produced by the real RC episode solver, and every commitment derived from it
// (RCStage3HeaderCommitment, DeriveSigma) is therefore over real structured
// data rather than a synthetic pattern.
//
// An earlier revision of this file used /home/administrator/rtprod-chain block
// 100. That was WRONG for this purpose: that chain tops out at height 100 and
// regtest RC starts at 101, so it contains ZERO RC blocks and the RC context
// would have been entirely constructed. The fixture below is a real block at a
// real RC height.

#include <matmul/matmul_v4_rc_stage3_producer.h>

#include <arith_uint256.h>
#include <consensus/params.h>
#include <consensus/validation.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_stage3.h>
#include <matmul/matmul_v4_rc_stage3_composition.h>
#include <matmul/matmul_v4_rc_stage3_consensus.h>
#include <matmul/matmul_v4_rc_stage3_episode_gemm_product.h>
#include <matmul/matmul_v4_rc_stage3_normalized_production_parent_builder.h>
#include <pow.h>
#include <primitives/block.h>
#include <serialize.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdlib>
#include <cstdint>
#include <limits>
#include <string>
#include <set>
#include <vector>

namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_producer_tests, BasicTestingSetup)

namespace {

//! Real ENC_RC block, height 102 of the RC regtest chain (hash 9aaad6b3...7677,
//! 365 bytes, digest-only ENC-DR carriage - i.e. the exact body shape the
//! Stage-3 attachment replaces).
const char* kRealRcBlock102Hex =
    "0000002091d3c0b1f4b3c49c81c32a9438212765d05ea559a7326658f9a9a246c60352"
    "cbf8bbf554af210e9eb0c117aacbbca4d0268c52ab1603936efc9109cc3034c6463e08"
    "666affff7f200000000000000000b7f9cfe3f9719c351f163b56fe4bcd154c7e906190"
    "47e17f17127c6e77a71607000137cd0e9194be5ef03c797c0b2eaf62be9aca9cea2157"
    "286921dff19ff0f2c747da8835c1811ed0d18214845c2493871ebc1ce3e638cbd7b6d0"
    "a608fa5c5bd7ed01020000000001010000000000000000000000000000000000000000"
    "000000000000000000000000ffffffff03016600ffffffff0200943577000000002252"
    "204df0e118c006dd68e46e0c8f144ff5c2c5618633a9c556dddb6c0704bd5535460000"
    "000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c6906897999"
    "62b48bebd836974e8cf901200000000000000000000000000000000000000000000000"
    "000000000000000000000000000000";

//! Real header, height 101 of the same chain (182 bytes) - also RC-active.
//! Used only as a SECOND real header so the cross-binding test rejects against
//! genuine data rather than a made-up header.
const char* kRealRcHeader101Hex =
    "000000206447c88092a5e20630b982569adcec0da38aac9aba2eec281740c4800398b5"
    "4a50a4b1b3c42f09c7bbaec7f8bfe0f957ffe1a6799aab3511882a2b3c6735b2f70c08"
    "666affff7f200000000000000000a0571f80e4522324ee6ccd6afe4a594c3e2978957d"
    "b3a1af7d6c141feae46f250001ad8ed376d38daa7b8a80916ce7a1f41813c711363d16"
    "85fea8373bad7cc27ef517292a0a8ad1c5c78bc0cce25d31724c48f380e0f488f0531c"
    "f1f969a9bcced4";

CBlock RealRcBlock102()
{
    const auto bytes = ParseHex(kRealRcBlock102Hex);
    DataStream stream{bytes};
    CBlock block;
    stream >> TX_WITH_WITNESS(block);
    return block;
}

CBlockHeader RealRcHeader101()
{
    const auto bytes = ParseHex(kRealRcHeader101Hex);
    DataStream stream{bytes};
    CBlockHeader header;
    stream >> header;
    return header;
}

uint256 Filled(unsigned char byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

struct SemanticLeafFixture {
    rc::episode_semantic_source_alg::LayerShapeV1 shape;
    rc::episode_semantic_source_alg::LayerBundleV1 bundle;
};

bool BuildSemanticLeafFixture(
    int8_t operand_a,
    SemanticLeafFixture& out,
    std::string* why)
{
    namespace source =
        rc::episode_semantic_source_alg;
    rc::RCStage3GemmExtractLayerManifest spec;
    spec.ordinal = 7;
    spec.m = 1;
    spec.n = 64;
    spec.k = 1;
    spec.b.transpose = false;
    spec.gemm_cell_count = 64;
    spec.extract_tile_begin = 0;
    spec.extract_tile_count = 2;
    if (!source::BuildLayerShapeV1(
            Filled(0x11), Filled(0x22),
            spec, out.shape, why)) {
        return false;
    }
    rc::RCStage3EpisodeGemmLayerProduct layer;
    layer.layer_ordinal = spec.ordinal;
    layer.operand_a = {operand_a};
    layer.operand_b.resize(64);
    layer.gemm_y.resize(64);
    for (uint32_t i = 0; i < 64; ++i) {
        const int8_t b =
            static_cast<int8_t>(
                static_cast<int32_t>(i % 7) - 3);
        layer.operand_b[i] = b;
        layer.gemm_y[i] =
            static_cast<int64_t>(operand_a) * b;
    }
    rc::RCStage3EpisodeExtractProduct extract;
    extract.tiles.resize(2);
    for (uint32_t tile = 0; tile < 2; ++tile) {
        for (uint32_t lane = 0;
             lane < rc::kRCMxBlockLen; ++lane) {
            extract.tiles[tile].input[lane] =
                layer.gemm_y[
                    tile * rc::kRCMxBlockLen +
                    lane];
        }
    }
    return source::ProveLayerBundleV1(
        out.shape, layer, extract,
        0, out.bundle, why);
}

//! Consensus params matching the RC chain the fixture came from: RC live well
//! below the fixture height, CI toy dims, coupled far in the future so the
//! required statement is Episode. `coupled` forces the Composed statement
//! instead, to exercise that branch of the binding check; no chain runs that
//! configuration today, and only the params_commitment (computed identically on
//! both sides) depends on it.
//!
//! The ProgramTable registry roots are UNCONFIGURED on every real network -
//! that is one of the activation blockers - and the binding check rejects a
//! null registry outright, so a test that wants to reach any LATER check has to
//! supply one here.
Consensus::Params RealChainLikeParams(bool coupled)
{
    Consensus::Params params;
    params.fMatMulPOW = true;
    params.nMatMulV4Height = 1;
    params.nMatMulRCHeight = 1;
    params.nMatMulRCProfile = 2;
    params.fMatMulRCUseToyDims = true;   // matches the CI RC chain
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

uint256 TargetFor(const CBlockHeader& header, const Consensus::Params& params)
{
    const auto target = DeriveTarget(header.nBits, params.powLimit);
    BOOST_REQUIRE(target.has_value());
    return ArithToUint256(*target);
}

//! Build a proof object whose PUBLIC INPUTS bind the given real header exactly
//! as ValidateRCStage3ConsensusBinding requires. The relation SECTIONS are
//! placeholder bytes: assembling real ones is
//! AssembleRCStage3SuccinctProofSections' job (section-assembly lane) and is
//! not what this file tests. Nothing here asserts those bytes prove anything.
rc::RCStage3SuccinctProof StatementBoundTo(const CBlockHeader& header,
                                           const Consensus::Params& params,
                                           int32_t height,
                                           const uint256& target)
{
    const auto required = rc::RequiredRCStage3Statement(params, height);
    BOOST_REQUIRE(required.has_value());
    const rc::RCStage3StatementKind statement = *required;

    rc::RCStage3SuccinctProof proof;
    proof.statement = statement;
    auto& p = proof.public_inputs;
    p.height = height;
    p.n_bits = header.nBits;
    p.episode_profile = params.nMatMulRCProfile;
    p.coupled_profile = statement == rc::RCStage3StatementKind::Composed
                            ? params.nMatMulRCCoupledProfile
                            : 0;
    p.transcript_version = statement == rc::RCStage3StatementKind::Composed
                               ? rc::ResolveRCCoupOptions(params).transcript_version
                               : rc::kRCTranscriptVersion;
    p.program_consensus_pin.recursive_alg_hash_root =
        params.hashMatMulRCStage3ProgramRegistryAlgRoot;
    p.program_consensus_pin.external_sha256d_audit_root =
        params.hashMatMulRCStage3ProgramRegistryShaAuditRoot;
    p.program_consensus_pin.registry_binding =
        params.hashMatMulRCStage3ProgramRegistryBinding;
    p.header_commitment = rc::RCStage3HeaderCommitment(header);
    p.params_commitment = rc::RCStage3ParamsCommitment(params, height, statement);
    p.target = target;
    p.sigma = matmul::v4::DeriveSigma(header);
    p.episode_digest = statement == rc::RCStage3StatementKind::Episode
                           ? header.matmul_digest
                           : Filled(0x60);
    p.coupled_digest = statement == rc::RCStage3StatementKind::Composed
                           ? Filled(0x70)
                           : uint256{};
    p.final_digest = header.matmul_digest;

    const auto roles = rc::RequiredRCStage3RelationRoles(statement);
    for (size_t i = 0; i < roles.size(); ++i) {
        proof.commitments.push_back(
            {roles[i], Filled(static_cast<unsigned char>(0xa0 + i))});
        proof.sections.push_back(
            {roles[i], {static_cast<unsigned char>(i), 0x5a, 0xa5}});
    }
    // transcript_commitment must be computed LAST, over the assembled envelope:
    // ValidateRCStage3ConsensusBinding now RECOMPUTES and compares it rather
    // than merely null-checking it, which is what transitively binds the
    // commitment roots and section bodies. A fixed placeholder here would fail
    // the binding check outright.
    p.transcript_commitment = rc::ComputeRCStage3TranscriptCommitment(proof);
    return proof;
}

//! RAII installer so a failing assertion cannot leak a proof source into the
//! next test case (the registry is process-wide).
struct ScopedProofSource {
    explicit ScopedProofSource(rc::RCStage3ProofSource source)
    {
        rc::SetRCStage3ProofSource(std::move(source));
    }
    ~ScopedProofSource() { rc::SetRCStage3ProofSource({}); }
};

} // namespace

// ---------------------------------------------------------------------------
// The real block, as it exists on disk today, carries NO Stage-3 proof.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(real_block_is_a_genuine_solved_rc_block)
{
    const CBlock block = RealRcBlock102();
    // Sanity: this is the real chain's block 100, not a fabricated one.
    BOOST_CHECK_EQUAL(
        block.GetHash().GetHex(),
        "9aaad6b37fd8a67dd60b5c7d1b5c7ccc317012bfbb7f30589e18c89a61937677");
    BOOST_CHECK_EQUAL(block.matmul_dim, 256);
    BOOST_CHECK(!block.matmul_digest.IsNull());
    BOOST_CHECK(!block.seed_a.IsNull());
    BOOST_CHECK(!block.seed_b.IsNull());
    BOOST_CHECK_EQUAL(block.vtx.size(), 1U);
    // Digest-only ENC-DR carriage: the body is empty. This is precisely the
    // state a Stage-3 activation turns into a consensus failure.
    BOOST_CHECK(block.matrix_c_data.empty());
    BOOST_CHECK(block.matrix_a_data.empty());
    BOOST_CHECK(block.matrix_b_data.empty());

    // Real PoW: the committed digest is genuinely under the block's own target.
    const auto params = RealChainLikeParams(false);
    BOOST_CHECK(UintToArith256(block.matmul_digest) <=
                UintToArith256(TargetFor(block, params)));
}

BOOST_AUTO_TEST_CASE(real_block_missing_a_required_proof_is_rejected)
{
    constexpr int32_t HEIGHT{102};
    const auto params = RealChainLikeParams(false);
    const CBlock block = RealRcBlock102();
    const uint256 target = TargetFor(block, params);

    std::string why;
    const auto status = rc::InspectRCStage3ConsensusAttachment(
        block, params, HEIGHT, target, nullptr, nullptr, &why);

    BOOST_CHECK(status == rc::RCStage3AttachmentStatus::Missing);
    // This is the verdict validation.cpp maps to BLOCK_MUTATED /
    // "missing-matmul-stage3-proof" once the authority gate closes.
    BOOST_CHECK(rc::RCStage3AttachmentIsMutation(status));
}

// ---------------------------------------------------------------------------
// PRODUCER: attach -> serialize -> parse -> bind, over the real header.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(producer_attaches_bound_proof_to_real_block)
{
    constexpr int32_t HEIGHT{102};
    const auto params = RealChainLikeParams(false);
    CBlock block = RealRcBlock102();
    const uint256 target = TargetFor(block, params);

    ScopedProofSource installed{
        [&](const CBlock& solved, const Consensus::Params& p, int32_t h,
            const uint256& t, const rc::RCStage3ProducerHints&,
            rc::RCStage3SuccinctProof& out, std::string*) {
            out = StatementBoundTo(solved, p, h, t);
            return true;
        }};
    BOOST_REQUIRE(rc::HasRCStage3ProofSource());

    std::string why;
    const auto produced = rc::AttachRCStage3ProofFromSource(
        block, params, HEIGHT, target, &why);
    BOOST_REQUIRE_MESSAGE(produced == rc::RCStage3ProduceStatus::Attached, why);
    BOOST_CHECK(!rc::RCStage3ProduceIsFatal(produced));
    BOOST_CHECK(!block.matrix_c_data.empty());
    BOOST_CHECK(rc::IsRCStage3ProofWords(block.matrix_c_data));

    // The attachment survives a full block serialize/deserialize round trip —
    // i.e. it is a real wire format, not an in-memory convention.
    DataStream stream;
    stream << TX_WITH_WITNESS(block);
    CBlock decoded;
    stream >> TX_WITH_WITNESS(decoded);
    BOOST_CHECK(decoded.matrix_c_data == block.matrix_c_data);
    BOOST_CHECK(decoded.GetHash() == block.GetHash());

    // And the consumer side accepts every consensus binding, stopping ONLY at
    // the authority gate. AuthorityUnavailable is explicitly NOT a mutation:
    // validation.cpp maps it to BLOCK_CONSENSUS
    // ("matmul-stage3-authority-unavailable"), never to BLOCK_MUTATED.
    rc::RCStage3SuccinctProof parsed;
    rc::RCStage3ProofCacheKey key;
    const auto status = rc::InspectRCStage3ConsensusAttachment(
        decoded, params, HEIGHT, target, &parsed, &key, &why);
    BOOST_CHECK(status == rc::RCStage3AttachmentStatus::AuthorityUnavailable);
    BOOST_CHECK(!rc::RCStage3AttachmentIsMutation(status));
    BOOST_CHECK(parsed == StatementBoundTo(block, params, HEIGHT, target));
    BOOST_CHECK(key.block_hash == block.GetHash());
    BOOST_CHECK(key.program_registry_alg_root ==
                params.hashMatMulRCStage3ProgramRegistryAlgRoot);
}

BOOST_AUTO_TEST_CASE(producer_attaches_composed_proof_at_coupled_height)
{
    constexpr int32_t HEIGHT{102};
    const auto params = RealChainLikeParams(true);
    CBlock block = RealRcBlock102();
    const uint256 target = TargetFor(block, params);
    BOOST_REQUIRE(*rc::RequiredRCStage3Statement(params, HEIGHT) ==
                  rc::RCStage3StatementKind::Composed);

    ScopedProofSource installed{
        [&](const CBlock& solved, const Consensus::Params& p, int32_t h,
            const uint256& t, const rc::RCStage3ProducerHints&,
            rc::RCStage3SuccinctProof& out, std::string*) {
            out = StatementBoundTo(solved, p, h, t);
            return true;
        }};

    std::string why;
    const auto produced = rc::AttachRCStage3ProofFromSource(
        block, params, HEIGHT, target, &why);
    BOOST_REQUIRE_MESSAGE(produced == rc::RCStage3ProduceStatus::Attached, why);

    const auto status = rc::InspectRCStage3ConsensusAttachment(
        block, params, HEIGHT, target, nullptr, nullptr, &why);
    BOOST_CHECK(status == rc::RCStage3AttachmentStatus::AuthorityUnavailable);
}

// ---------------------------------------------------------------------------
// TAMPER: every mutation of the attached payload must be REJECTED.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(tampered_proof_on_real_block_is_rejected)
{
    constexpr int32_t HEIGHT{102};
    const auto params = RealChainLikeParams(false);
    const uint256 target = TargetFor(RealRcBlock102(), params);

    ScopedProofSource installed{
        [&](const CBlock& solved, const Consensus::Params& p, int32_t h,
            const uint256& t, const rc::RCStage3ProducerHints&,
            rc::RCStage3SuccinctProof& out, std::string*) {
            out = StatementBoundTo(solved, p, h, t);
            return true;
        }};

    CBlock honest = RealRcBlock102();
    std::string why;
    BOOST_REQUIRE(rc::AttachRCStage3ProofFromSource(honest, params, HEIGHT,
                                                    target, &why) ==
                  rc::RCStage3ProduceStatus::Attached);
    BOOST_REQUIRE(honest.matrix_c_data.size() > 4);

    // EVERY word of the payload must now be rejected AS A MUTATION when a
    // single bit flips — envelope magic, declared byte length, proof
    // magic/version/authority/statement, every public input, every structural
    // count/role/length field, every per-role commitment root, and every
    // relation-section body byte.
    //
    // The commitment roots and section bodies are covered TRANSITIVELY:
    // ValidateRCStage3ConsensusBinding recomputes transcript_commitment via
    // ComputeRCStage3TranscriptCommitment, which hashes the statement, all
    // public inputs, every commitment root, and the hash of every section body.
    // Perturbing any of them changes the recomputed value and fails the compare.
    // An earlier revision of this file measured a 69-of-164-word UNBOUND region
    // here (transcript_commitment was only null-checked); the section-assembly
    // lane closed that, and this sweep is the check that it stays closed.
    //
    // The header is untouched by construction, which is exactly the relay-level
    // threat the mutation classification exists for.
    size_t checked{0};
    for (size_t pos = 0; pos < honest.matrix_c_data.size(); ++pos) {
        CBlock tampered = honest;
        tampered.matrix_c_data[pos] ^= 1u;
        BOOST_REQUIRE(tampered.matrix_c_data != honest.matrix_c_data);
        BOOST_CHECK(tampered.GetHash() == honest.GetHash());

        std::string tamper_why;
        const auto status = rc::InspectRCStage3ConsensusAttachment(
            tampered, params, HEIGHT, target, nullptr, nullptr, &tamper_why);
        BOOST_CHECK_MESSAGE(
            rc::RCStage3AttachmentIsMutation(status),
            "tampered word " << pos << " was not rejected as a mutation (status="
                             << static_cast<int>(status) << ")");
        ++checked;
    }
    // Totality: no word is exempt.
    BOOST_CHECK_EQUAL(checked, honest.matrix_c_data.size());
    BOOST_TEST_MESSAGE("stage3 payload words=" << honest.matrix_c_data.size()
                       << " all bound=" << checked);
}

//! Section bodies and commitment roots ARE bound by the binding layer — and the
//! exact boundary of that guarantee, which is narrower than it first looks.
//!
//! HOW they are bound: ValidateRCStage3ConsensusBinding recomputes
//! transcript_commitment with ComputeRCStage3TranscriptCommitment, which covers
//! the statement, every public input, every per-role commitment root, and the
//! hash of every section body. Change any of those without also recomputing the
//! transcript and the compare fails. An earlier revision of this file asserted
//! the OPPOSITE (transcript_commitment was then only null-checked, leaving 69 of
//! 164 payload words unauthenticated) and predicted precisely this fix; the
//! section-assembly lane landed it.
//!
//! WHAT IS STILL NOT GUARANTEED, asserted below rather than omitted: an attacker
//! who tampers with a section body AND recomputes transcript_commitment over the
//! forged envelope is ACCEPTED by this layer. That is not a defect. The binding
//! layer authenticates STRUCTURE — that the envelope is internally consistent
//! and bound to this block, height, params and target. Authenticating section
//! CONTENT — that the bytes are a proof of anything — is the mathematical
//! verifier's obligation (VerifyRCStage3MathematicalProof, gated off by
//! kRCStage3MathematicalVerifierReady == false). So "a tampered proof is
//! rejected" is true today for tampering that does not recompute the transcript,
//! and depends on the gated verifier for tampering that does.
BOOST_AUTO_TEST_CASE(section_bodies_are_bound_transitively_via_transcript)
{
    constexpr int32_t HEIGHT{102};
    const auto params = RealChainLikeParams(false);
    const uint256 target = TargetFor(RealRcBlock102(), params);

    ScopedProofSource installed{
        [&](const CBlock& solved, const Consensus::Params& p, int32_t h,
            const uint256& t, const rc::RCStage3ProducerHints&,
            rc::RCStage3SuccinctProof& out, std::string*) {
            out = StatementBoundTo(solved, p, h, t);
            return true;
        }};

    CBlock honest = RealRcBlock102();
    std::string why;
    BOOST_REQUIRE(rc::AttachRCStage3ProofFromSource(honest, params, HEIGHT,
                                                    target, &why) ==
                  rc::RCStage3ProduceStatus::Attached);

    const auto honest_statement = StatementBoundTo(honest, params, HEIGHT, target);

    // (a) Forge section bodies and commitment roots but KEEP the honest
    //     transcript_commitment — the realistic attacker, who cannot recompute
    //     it without redoing the prover's work. REJECTED as a mutation.
    {
        auto forged = honest_statement;
        for (auto& c : forged.commitments) {
            for (auto& b : c.root) b = static_cast<unsigned char>(b ^ 0xFFu);
        }
        for (auto& sec : forged.sections) {
            for (auto& b : sec.proof) b = static_cast<unsigned char>(b ^ 0xFFu);
        }
        // transcript_commitment deliberately left at the honest value.
        forged.public_inputs.transcript_commitment =
            honest_statement.public_inputs.transcript_commitment;

        CBlock swapped = RealRcBlock102();
        BOOST_REQUIRE(rc::PackRCStage3ProofWords(forged, swapped.matrix_c_data, &why));
        BOOST_REQUIRE(swapped.matrix_c_data != honest.matrix_c_data);

        const auto status = rc::InspectRCStage3ConsensusAttachment(
            swapped, params, HEIGHT, target, nullptr, nullptr, &why);
        BOOST_CHECK(rc::RCStage3AttachmentIsMutation(status));
        BOOST_CHECK(why.find("transcript_commitment") != std::string::npos);
    }

    // (b) Forge ONLY the transcript_commitment, leaving sections honest. Also
    //     rejected: the recompute no longer matches.
    {
        auto forged = honest_statement;
        for (auto& b : forged.public_inputs.transcript_commitment) {
            b = static_cast<unsigned char>(b ^ 0xFFu);
        }
        CBlock swapped = RealRcBlock102();
        BOOST_REQUIRE(rc::PackRCStage3ProofWords(forged, swapped.matrix_c_data, &why));
        const auto status = rc::InspectRCStage3ConsensusAttachment(
            swapped, params, HEIGHT, target, nullptr, nullptr, &why);
        BOOST_CHECK(rc::RCStage3AttachmentIsMutation(status));
    }

    // (c) THE REMAINING BOUNDARY. Forge the section bodies AND recompute the
    //     transcript over the forged envelope. The binding layer ACCEPTS it —
    //     it is internally consistent and correctly bound to this block. Only
    //     the (gated-off) mathematical verifier can reject this class.
    {
        auto forged = honest_statement;
        for (auto& sec : forged.sections) {
            for (auto& b : sec.proof) b = static_cast<unsigned char>(b ^ 0xFFu);
        }
        forged.public_inputs.transcript_commitment =
            rc::ComputeRCStage3TranscriptCommitment(forged);

        CBlock swapped = RealRcBlock102();
        BOOST_REQUIRE(rc::PackRCStage3ProofWords(forged, swapped.matrix_c_data, &why));
        BOOST_REQUIRE(swapped.matrix_c_data != honest.matrix_c_data);

        const auto status = rc::InspectRCStage3ConsensusAttachment(
            swapped, params, HEIGHT, target, nullptr, nullptr, &why);
        BOOST_CHECK(status == rc::RCStage3AttachmentStatus::AuthorityUnavailable);
        BOOST_CHECK(!rc::RCStage3AttachmentIsMutation(status));

        // What still distinguishes it: the proof-aware cache key. A forged body
        // can never inherit an honest body's positive verdict.
        BOOST_CHECK(rc::RCStage3ProofKey(swapped).proof_payload_digest !=
                    rc::RCStage3ProofKey(honest).proof_payload_digest);
        BOOST_CHECK(rc::RCStage3ProofKey(swapped).block_hash ==
                    rc::RCStage3ProofKey(honest).block_hash);
    }
}

BOOST_AUTO_TEST_CASE(truncated_and_extended_payloads_are_rejected)
{
    constexpr int32_t HEIGHT{102};
    const auto params = RealChainLikeParams(false);
    const uint256 target = TargetFor(RealRcBlock102(), params);

    ScopedProofSource installed{
        [&](const CBlock& solved, const Consensus::Params& p, int32_t h,
            const uint256& t, const rc::RCStage3ProducerHints&,
            rc::RCStage3SuccinctProof& out, std::string*) {
            out = StatementBoundTo(solved, p, h, t);
            return true;
        }};

    CBlock honest = RealRcBlock102();
    std::string why;
    BOOST_REQUIRE(rc::AttachRCStage3ProofFromSource(honest, params, HEIGHT,
                                                    target, &why) ==
                  rc::RCStage3ProduceStatus::Attached);

    CBlock truncated = honest;
    truncated.matrix_c_data.pop_back();
    BOOST_CHECK(rc::RCStage3AttachmentIsMutation(
        rc::InspectRCStage3ConsensusAttachment(truncated, params, HEIGHT, target,
                                               nullptr, nullptr, &why)));

    CBlock extended = honest;
    extended.matrix_c_data.push_back(0);
    BOOST_CHECK(rc::RCStage3AttachmentIsMutation(
        rc::InspectRCStage3ConsensusAttachment(extended, params, HEIGHT, target,
                                               nullptr, nullptr, &why)));
}

BOOST_AUTO_TEST_CASE(hostile_payload_length_claim_allocates_nothing)
{
    // Untrusted-parse ceiling at the CONSENSUS boundary: what a peer can put in
    // a relayed block body. The declared byte length is attacker-chosen and must
    // be refused against kRCStage3MaxProofBytes BEFORE any buffer is sized from
    // it. Same precedent as recursive.cpp's
    // MAX_VECTOR_ITEMS = kRCFri3AlgBatchMaxColumns.
    constexpr int32_t HEIGHT{102};
    const auto params = RealChainLikeParams(false);
    CBlock block = RealRcBlock102();
    const uint256 target = TargetFor(block, params);

    // Three words claiming ~4 GiB of proof. If the ceiling were checked after
    // allocating, this test would die rather than fail.
    block.matrix_c_data = {rc::kRCStage3BlockPayloadMagic, 0xFFFFFFFFu, 0u};
    std::string why;
    auto status = rc::InspectRCStage3ConsensusAttachment(
        block, params, HEIGHT, target, nullptr, nullptr, &why);
    BOOST_CHECK(status == rc::RCStage3AttachmentStatus::Malformed);
    BOOST_CHECK(rc::RCStage3AttachmentIsMutation(status));

    // Exactly one byte over the ceiling is still refused.
    block.matrix_c_data = {rc::kRCStage3BlockPayloadMagic,
                           static_cast<uint32_t>(rc::kRCStage3MaxProofBytes + 1), 0u};
    status = rc::InspectRCStage3ConsensusAttachment(block, params, HEIGHT, target,
                                                    nullptr, nullptr, &why);
    BOOST_CHECK(status == rc::RCStage3AttachmentStatus::Malformed);

    // Under the ceiling but inconsistent with the word count: refused as
    // noncanonical rather than read out of bounds.
    block.matrix_c_data = {rc::kRCStage3BlockPayloadMagic, 4096u, 0u};
    status = rc::InspectRCStage3ConsensusAttachment(block, params, HEIGHT, target,
                                                    nullptr, nullptr, &why);
    BOOST_CHECK(status == rc::RCStage3AttachmentStatus::Malformed);
}

BOOST_AUTO_TEST_CASE(proof_bound_to_a_different_real_header_is_refused)
{
    constexpr int32_t HEIGHT{102};
    const auto params = RealChainLikeParams(false);
    CBlock block = RealRcBlock102();
    const uint256 target = TargetFor(block, params);
    const CBlockHeader other = RealRcHeader101();
    BOOST_REQUIRE(other.GetHash() != block.GetHash());

    // A prover that binds the WRONG (but equally real) header.
    ScopedProofSource installed{
        [&](const CBlock&, const Consensus::Params& p, int32_t h,
            const uint256& t, const rc::RCStage3ProducerHints&,
            rc::RCStage3SuccinctProof& out, std::string*) {
            out = StatementBoundTo(other, p, h, t);
            return true;
        }};

    std::string why;
    const auto produced = rc::AttachRCStage3ProofFromSource(
        block, params, HEIGHT, target, &why);
    BOOST_CHECK(produced == rc::RCStage3ProduceStatus::BindingRejected);
    BOOST_CHECK(rc::RCStage3ProduceIsFatal(produced));
    // Atomic: a caller that ignores the status still cannot ship a foreign proof.
    BOOST_CHECK(block.matrix_c_data.empty());
    BOOST_CHECK(why.find("attach:") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(oversized_proof_is_refused_at_the_allocation_ceiling)
{
    constexpr int32_t HEIGHT{102};
    const auto params = RealChainLikeParams(false);
    CBlock block = RealRcBlock102();
    const uint256 target = TargetFor(block, params);

    // Sections past kRCStage3MaxProofBytes: serialization must refuse to emit,
    // so our own producer can never exceed the hard parse ceiling either.
    ScopedProofSource installed{
        [&](const CBlock& solved, const Consensus::Params& p, int32_t h,
            const uint256& t, const rc::RCStage3ProducerHints&,
            rc::RCStage3SuccinctProof& out, std::string*) {
            out = StatementBoundTo(solved, p, h, t);
            out.sections.front().proof.assign(rc::kRCStage3MaxProofBytes + 1, 0x7f);
            out.public_inputs.transcript_commitment =
                rc::ComputeRCStage3TranscriptCommitment(out);
            return true;
        }};

    std::string why;
    const auto produced = rc::AttachRCStage3ProofFromSource(
        block, params, HEIGHT, target, &why);
    BOOST_CHECK(produced == rc::RCStage3ProduceStatus::BindingRejected);
    BOOST_CHECK(block.matrix_c_data.empty());
}

BOOST_AUTO_TEST_CASE(attachment_size_is_measured_exactly_not_estimated)
{
    constexpr int32_t HEIGHT{102};
    const auto params = RealChainLikeParams(false);
    CBlock block = RealRcBlock102();
    const uint256 target = TargetFor(block, params);

    ScopedProofSource installed{
        [&](const CBlock& solved, const Consensus::Params& p, int32_t h,
            const uint256& t, const rc::RCStage3ProducerHints&,
            rc::RCStage3SuccinctProof& out, std::string*) {
            out = StatementBoundTo(solved, p, h, t);
            return true;
        }};

    const size_t bare_block_bytes = ::GetSerializeSize(TX_WITH_WITNESS(block));

    std::string why;
    rc::RCStage3AttachmentSizeReport report;
    BOOST_REQUIRE(rc::AttachRCStage3ProofFromSource(block, params, HEIGHT, target,
                                                    &why, &report) ==
                  rc::RCStage3ProduceStatus::Attached);

    // Every field must describe bytes that actually exist.
    BOOST_CHECK_EQUAL(report.payload_words, block.matrix_c_data.size());
    BOOST_CHECK_EQUAL(report.payload_bytes,
                      static_cast<size_t>(block.matrix_c_data[1]));
    BOOST_CHECK_EQUAL(report.payload_words, 2 + (report.payload_bytes + 3) / 4);
    BOOST_CHECK_EQUAL(report.block_serialized_total,
                      ::GetSerializeSize(TX_WITH_WITNESS(block)));
    BOOST_CHECK_EQUAL(report.block_serialized_delta,
                      report.block_serialized_total - bare_block_bytes);
    BOOST_CHECK_EQUAL(report.block_weight_total, GetBlockWeight(block));
    BOOST_CHECK_EQUAL(report.codec_cap_bytes, rc::kRCStage3MaxProofBytes);
    BOOST_CHECK_EQUAL(report.consensus_serialized_cap,
                      params.nMaxBlockSerializedSize);
    BOOST_CHECK(report.Fits());

    // The pre-prove assembler reservation is a true upper bound for every
    // accepted attachment: serialization enforces the byte cap, and the
    // reservation includes the exact maximum word envelope and CompactSize
    // framing.
    const auto reservation = rc::RCStage3PlannedReservation(params, HEIGHT);
    BOOST_REQUIRE(reservation.Usable());
    BOOST_CHECK(report.payload_bytes <= reservation.envelope_bytes);
    BOOST_CHECK(report.payload_words <= reservation.payload_words);
    BOOST_CHECK(report.block_serialized_delta <=
                reservation.block_serialized_delta);

    // WITNESS_SCALE_FACTOR == 1 on BTX: weight and serialized size coincide, so
    // every proof byte competes 1:1 with transaction bytes.
    BOOST_CHECK_EQUAL(report.block_weight_total,
                      static_cast<int64_t>(report.block_serialized_total));
    BOOST_CHECK(!report.ToString().empty());
}

BOOST_AUTO_TEST_CASE(payload_over_the_block_budget_is_refused_with_numbers)
{
    constexpr int32_t HEIGHT{102};
    // Shrink the block caps rather than grow the proof: this is about the BUDGET
    // CHECK firing and reporting. The obsolete 35,363,636-byte flat proof
    // cannot pass the codec at all and is not a valid production reservation.
    auto params = RealChainLikeParams(false);
    params.nMaxBlockSerializedSize = 512;
    params.nMaxBlockWeight = 512;

    CBlock block = RealRcBlock102();
    const uint256 target = TargetFor(block, params);

    ScopedProofSource installed{
        [&](const CBlock& solved, const Consensus::Params& p, int32_t h,
            const uint256& t, const rc::RCStage3ProducerHints&,
            rc::RCStage3SuccinctProof& out, std::string*) {
            out = StatementBoundTo(solved, p, h, t);
            return true;
        }};

    std::string why;
    rc::RCStage3AttachmentSizeReport report;
    const auto produced = rc::AttachRCStage3ProofFromSource(
        block, params, HEIGHT, target, &why, &report);

    BOOST_CHECK(produced == rc::RCStage3ProduceStatus::ExceedsSizeBudget);
    BOOST_CHECK(rc::RCStage3ProduceIsFatal(produced));
    // Atomic: an over-budget proof never reaches the block, so the miner cannot
    // produce a block its own CheckBlock would reject.
    BOOST_CHECK(block.matrix_c_data.empty());
    // The refusal carries numbers, not just a verdict.
    BOOST_CHECK(!report.Fits());
    BOOST_CHECK(!report.within_consensus_caps);
    BOOST_CHECK(report.within_codec_cap); // under 16 MiB, over the block cap
    BOOST_CHECK(report.block_serialized_total > report.consensus_serialized_cap);
    BOOST_CHECK(report.payload_bytes > 0);
    BOOST_CHECK(why.find("size_budget:") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(measure_is_pure_and_usable_without_a_prover)
{
    // MeasureRCStage3Attachment must be callable for capacity planning before
    // any prover exists — that is the point of surfacing size separately from
    // production.
    const auto params = RealChainLikeParams(false);
    const CBlock block = RealRcBlock102();
    const CBlock before = block;

    // A payload at exactly the codec ceiling.
    const size_t bytes = rc::kRCStage3MaxProofBytes;
    std::vector<uint32_t> packed(2 + (bytes + 3) / 4, 0);
    packed[0] = rc::kRCStage3BlockPayloadMagic;
    packed[1] = static_cast<uint32_t>(bytes);

    const auto report = rc::MeasureRCStage3Attachment(block, packed, params);
    BOOST_CHECK_EQUAL(report.payload_bytes, bytes);
    BOOST_CHECK(report.within_codec_cap);      // exactly at the cap is inside it
    BOOST_CHECK(report.within_consensus_caps); // 16 MiB fits under 24 MB
    BOOST_CHECK(report.block_serialized_delta >= bytes);
    BOOST_CHECK(block.matrix_c_data == before.matrix_c_data); // purity

    // One byte over the codec ceiling is outside it.
    std::vector<uint32_t> over = packed;
    over[1] = static_cast<uint32_t>(bytes + 1);
    over.push_back(0);
    const auto over_report = rc::MeasureRCStage3Attachment(block, over, params);
    BOOST_CHECK(!over_report.within_codec_cap);
    BOOST_CHECK(!over_report.Fits());
}

BOOST_AUTO_TEST_CASE(a_failing_prover_is_fatal_and_leaves_the_block_alone)
{
    constexpr int32_t HEIGHT{102};
    const auto params = RealChainLikeParams(false);
    CBlock block = RealRcBlock102();
    const uint256 target = TargetFor(block, params);

    ScopedProofSource installed{
        [](const CBlock&, const Consensus::Params&, int32_t, const uint256&,
           const rc::RCStage3ProducerHints&, rc::RCStage3SuccinctProof&,
           std::string* why) {
            if (why != nullptr) *why = "synthetic_prover_failure";
            return false;
        }};

    std::string why;
    const auto produced = rc::AttachRCStage3ProofFromSource(
        block, params, HEIGHT, target, &why);
    BOOST_CHECK(produced == rc::RCStage3ProduceStatus::ProverFailed);
    BOOST_CHECK(rc::RCStage3ProduceIsFatal(produced));
    BOOST_CHECK(block.matrix_c_data.empty());
    BOOST_CHECK(why.find("synthetic_prover_failure") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(no_registered_prover_is_fatal_not_silent)
{
    constexpr int32_t HEIGHT{102};
    const auto params = RealChainLikeParams(false);
    CBlock block = RealRcBlock102();
    const uint256 target = TargetFor(block, params);

    rc::SetRCStage3ProofSource({});
    BOOST_REQUIRE(!rc::HasRCStage3ProofSource());

    std::string why;
    const auto produced = rc::AttachRCStage3ProofFromSource(
        block, params, HEIGHT, target, &why);
    // The state the node ships in TODAY. It must be loud, not a silently-empty
    // body, because the validator's verdict for an empty body at an RC-family
    // height is BLOCK_MUTATED.
    BOOST_CHECK(produced == rc::RCStage3ProduceStatus::NoProver);
    BOOST_CHECK(rc::RCStage3ProduceIsFatal(produced));
    BOOST_CHECK(block.matrix_c_data.empty());
}

BOOST_AUTO_TEST_CASE(
    production_provider_reaches_typed_canonical_parent_builder)
{
    constexpr int32_t HEIGHT{102};
    // The normalized parent is the additive fourteen-role statement, so use
    // coupled-active params and require the provider to reach the concrete
    // solved-block -> complete relation-parent dependency.
    const auto params = RealChainLikeParams(true);
    CBlock block = RealRcBlock102();
    const CBlock before = block;
    const uint256 target = TargetFor(block, params);

    // Install a legacy source that would produce an attachable section
    // envelope. The production path must not call it: normalized root authority
    // cannot be substituted with the old REP3/OAS3 test wire.
    bool legacy_called{false};
    ScopedProofSource legacy{
        [&](const CBlock& solved, const Consensus::Params& p, int32_t h,
            const uint256& t, const rc::RCStage3ProducerHints&,
            rc::RCStage3SuccinctProof& out, std::string*) {
            legacy_called = true;
            out = StatementBoundTo(solved, p, h, t);
            return true;
        }};

    rc::InitializeRCStage3ProductionProofProvider();
    rc::InitializeRCStage3ProductionProofProvider(); // idempotent node lifetime
    BOOST_REQUIRE(rc::HasRCStage3ProductionProofProvider());

    std::vector<unsigned char> receipt_bytes{0xaa, 0xbb};
    std::string build_why;
    const auto build_status = rc::BuildRCStage3NormalizedAuthorityReceipt(
        block, params, HEIGHT, target, receipt_bytes, &build_why);
    BOOST_CHECK(
        build_status ==
        rc::RCStage3NormalizedProviderStatus::BuildFailed);
    BOOST_CHECK(receipt_bytes.empty());
    BOOST_CHECK(build_why.find("canonical_parent_product:") !=
                std::string::npos);
    BOOST_CHECK(
        build_why.find("complete_relation_parent_unavailable") !=
            std::string::npos);
    BOOST_CHECK(
        build_why.find(
            "block_to_14_role_52_endpoint_assembler_available") !=
                std::string::npos);

    std::string why;
    rc::RCStage3AttachmentSizeReport size;
    const auto produced = rc::AttachRCStage3ProofFromProductionProvider(
        block, params, HEIGHT, target, &why, &size);

    BOOST_CHECK(produced == rc::RCStage3ProduceStatus::ProverFailed);
    BOOST_CHECK(rc::RCStage3ProduceIsFatal(produced));
    BOOST_CHECK(!legacy_called);
    BOOST_CHECK(block.matrix_c_data == before.matrix_c_data);
    BOOST_CHECK_EQUAL(size.payload_bytes, 0U);
    BOOST_CHECK(why.find("canonical_parent_product:") !=
                std::string::npos);
    BOOST_CHECK(
        why.find("complete_relation_parent_unavailable") !=
            std::string::npos);
    BOOST_CHECK(
        why.find(
            "block_to_14_role_52_endpoint_assembler_available") !=
                std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    normalized_inventory_rejects_valid_cross_witness_unified_node)
{
    namespace hierarchy =
        rc::recursive_hierarchy;
    namespace source =
        rc::episode_semantic_source_alg;
    SemanticLeafFixture honest;
    SemanticLeafFixture alternate;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        BuildSemanticLeafFixture(2, honest, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        BuildSemanticLeafFixture(-3, alternate, &why),
        why);
    BOOST_REQUIRE_EQUAL(
        honest.bundle.leaves.size(), 1U);
    BOOST_REQUIRE_EQUAL(
        alternate.bundle.leaves.size(), 1U);
    const auto& honest_leaf =
        honest.bundle.leaves.front();
    const auto& alternate_leaf =
        alternate.bundle.leaves.front();
    BOOST_REQUIRE(
        honest_leaf.manifest ==
        alternate_leaf.manifest);

    const auto manifest =
        hierarchy::BuildShardOrdinalManifestV1(
            honest.shape.tile_count,
            {{
                .shard_ordinal = 0,
                .first_ordinal = 0,
                .ordinal_count =
                    honest.shape.tile_count,
                .statement_root =
                    honest_leaf.manifest
                        .manifest_commitment,
            }});
    BOOST_REQUIRE(
        hierarchy::ValidateShardOrdinalManifestV1(
            manifest));
    const auto coverage =
        hierarchy::BuildShardOrdinalCoverageV1(
            manifest, 0, 1);
    const auto honest_input =
        source::
            BuildUnifiedSameParentCtlVerificationInputV2(
                honest_leaf.manifest,
                honest_leaf
                    .unified_same_parent_ctl_join);
    const auto alternate_input =
        source::
            BuildUnifiedSameParentCtlVerificationInputV2(
                alternate_leaf.manifest,
                alternate_leaf
                    .unified_same_parent_ctl_join);
    BOOST_REQUIRE(honest_input.valid);
    BOOST_REQUIRE(alternate_input.valid);
    const auto honest_node =
        hierarchy::
            RetainVerifiedSplitRapHierarchyNodeV2(
                manifest, coverage, 1, 0,
                honest_input.expected_cs,
                *honest_input.proof,
                honest_input
                    .expected_base_column_indices,
                honest_input.public_fs_seed);
    const auto alternate_node =
        hierarchy::
            RetainVerifiedSplitRapHierarchyNodeV2(
                manifest, coverage, 1, 0,
                alternate_input.expected_cs,
                *alternate_input.proof,
                alternate_input
                    .expected_base_column_indices,
                alternate_input.public_fs_seed);
    BOOST_REQUIRE_MESSAGE(
        honest_node.valid, honest_node.note);
    BOOST_REQUIRE_MESSAGE(
        alternate_node.valid,
        alternate_node.note);
    BOOST_REQUIRE(
        honest_node.proof_bytes !=
        alternate_node.proof_bytes);

    BOOST_CHECK_MESSAGE(
        rc::normalized_production_parent_builder::
            ValidateCapturedEpisodeLeafInventoryV2(
            manifest, {honest_leaf},
            {honest_node}, &why),
        why);
    // Both inputs are natively valid for the same public shape, but the
    // normalized producer must consume the exact unified proof paired with
    // this receipt.  A separately valid node cannot replace it.
    BOOST_CHECK(
        !rc::normalized_production_parent_builder::
            ValidateCapturedEpisodeLeafInventoryV2(
            manifest, {honest_leaf},
            {alternate_node}, nullptr));
}

BOOST_AUTO_TEST_CASE(
    real_composed_work_builds_literal_14_role_52_endpoint_parent)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_PARENT_CANDIDATE") == nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_PARENT_CANDIDATE=1");
        return;
    }
    constexpr int32_t HEIGHT{102};
    const auto params = RealChainLikeParams(true);
    CBlock block = RealRcBlock102();
    const auto episode_params =
        rc::ResolveRCEpisodeParams(params, HEIGHT);
    auto episode_capture =
        std::make_shared<
            rc::RCStage3EpisodeWitnessCapture>(
                episode_params);
    const uint256 episode_digest =
        rc::MineRCEpisodeWithProofWitness(
            block, episode_params, HEIGHT,
            *episode_capture);
    const auto coupled_params =
        rc::ResolveRCCoupParams(params);
    const auto coupled_options =
        rc::ResolveRCCoupOptions(params);
    const uint256 coupled_digest =
        rc::RecomputeCoupledPuzzleReference(
            block, HEIGHT, coupled_params,
            coupled_options);
    BOOST_REQUIRE(!episode_digest.IsNull());
    BOOST_REQUIRE(!coupled_digest.IsNull());
    block.matmul_digest =
        rc::ComputeRCStage3ComposedWorkDigest(
            block, params, HEIGHT,
            episode_digest, coupled_digest);
    BOOST_REQUIRE(!block.matmul_digest.IsNull());

    const uint256 target =
        uint256{
            "ffffffffffffffffffffffffffffffff"
            "ffffffffffffffffffffffffffffffff"};
    namespace builder =
        rc::normalized_production_parent_builder;
    const builder::ProductionParentBuildInputV1 input{
        .solved_block = &block,
        .params = &params,
        .height = HEIGHT,
        .target = target,
        .episode_capture = episode_capture,
        .episode_capture_header_hash =
            block.GetHash(),
    };
    builder::ProductionRelationParentCandidateV1
        candidate;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        builder::
            BuildRelationParentCandidateForSolvedBlockV1(
                input, candidate, &why),
        why);
    BOOST_CHECK(candidate.local_parent_valid);
    BOOST_CHECK(candidate.exact_role_order);
    BOOST_CHECK(candidate.exact_endpoint_order);
    BOOST_CHECK(candidate.all_endpoint_cells_literal);
    BOOST_CHECK(candidate.winner_episode_capture_bound);
    BOOST_CHECK(candidate.episode_witness_replay_avoided);
    BOOST_CHECK_EQUAL(candidate.roles.size(), 14U);
    BOOST_CHECK_EQUAL(candidate.endpoint_count, 52U);
    BOOST_CHECK_EQUAL(candidate.witness_violations, 0U);
    BOOST_CHECK(
        candidate.episode_digest == episode_digest);
    BOOST_CHECK(
        candidate.coupled_digest == coupled_digest);
    BOOST_CHECK(
        candidate.composed_digest ==
        block.matmul_digest);
    const auto captured_layout =
        rc::RCGkrTraceLayout(episode_params);
    uint64_t expected_captured_tiles = 0;
    for (const auto& layer : captured_layout.layers) {
        BOOST_REQUIRE_EQUAL(
            layer.n % rc::kRCMxBlockLen, 0U);
        expected_captured_tiles +=
            uint64_t{layer.m} *
            (layer.n / rc::kRCMxBlockLen);
    }
    BOOST_CHECK_EQUAL(
        candidate.captured_episode_layer_count,
        captured_layout.layers.size());
    BOOST_CHECK_EQUAL(
        candidate.captured_episode_tile_count,
        expected_captured_tiles);
    BOOST_CHECK_EQUAL(
        candidate.captured_episode_leaf_manifest
            .total_ordinals,
        expected_captured_tiles);
    BOOST_REQUIRE_EQUAL(
        candidate.captured_episode_leaf_receipts.size(),
        candidate.captured_episode_leaf_nodes.size());
    BOOST_REQUIRE_EQUAL(
        candidate.captured_episode_leaf_manifest
            .entries.size(),
        candidate.captured_episode_leaf_nodes.size());
    BOOST_CHECK_GT(
        candidate.captured_episode_leaf_receipts.size(),
        1U);
    BOOST_CHECK(
        rc::recursive_hierarchy::
            ValidateShardOrdinalManifestV1(
                candidate
                    .captured_episode_leaf_manifest,
                &why));
    for (const auto& receipt :
         candidate.captured_episode_leaf_receipts) {
        BOOST_CHECK(receipt.locally_verified);
        BOOST_CHECK(!receipt.canonical_proof_bytes.empty());
        BOOST_CHECK(!receipt.receipt_commitment.IsNull());
        const auto& join =
            receipt.unified_same_parent_ctl_join;
        BOOST_CHECK(join.single_source_relation);
        BOOST_CHECK(join.all_receivers_executed);
        BOOST_CHECK(join.all_dual_alpha_terminals);
        BOOST_CHECK(join.all_terminal_cancellations);
        BOOST_CHECK(!join.proof_commitment.IsNull());
        BOOST_CHECK(!join.join_commitment.IsNull());
        BOOST_CHECK(
            receipt.proof.trace_commit ==
            join.source_trace_commitment);
        std::string join_why;
        BOOST_CHECK_MESSAGE(
            rc::episode_semantic_source_alg::
                VerifyUnifiedSameParentCtlJoinV2(
                    receipt.manifest,
                    join, &join_why),
            join_why);
    }
    for (const auto& node :
         candidate.captured_episode_leaf_nodes) {
        BOOST_CHECK(node.valid);
        BOOST_CHECK(node.proof_retained);
        BOOST_CHECK(node.native_proof_verified);
        BOOST_CHECK(node.cryptographic_child);
        BOOST_CHECK(!node.proof_bytes.empty());
    }
    BOOST_CHECK(
        candidate
            .captured_episode_leaf_inventory_verified);
    // Local source/receiver cancellation is not the missing transitive edge.
    // Until the external producer terminal is equality-constrained in the
    // normalized parent, this candidate must remain non-authoritative.
    BOOST_CHECK(
        !candidate.recursive_semantic_closure_complete);
    BOOST_CHECK(!candidate.production_authority);

    // Endpoint 2 states the same proposition in the block-derived role and
    // its heavy SHA child: seed_a is the stream value; the endpoint root is
    // the family-domain-separated manifest commitment; and the bank value is
    // the Fp3 recomposition of seed words 0..2.  Raw seed bytes must never be
    // mislabelled as the commitment root.
    std::array<uint32_t, 8> seed_words{};
    for (uint32_t word = 0;
         word < seed_words.size(); ++word) {
        const uint32_t offset = 4U * word;
        seed_words[word] =
            static_cast<uint32_t>(
                block.seed_a.begin()[offset]) |
            (static_cast<uint32_t>(
                 block.seed_a.begin()[offset + 1])
             << 8) |
            (static_cast<uint32_t>(
                 block.seed_a.begin()[offset + 2])
             << 16) |
            (static_cast<uint32_t>(
                 block.seed_a.begin()[offset + 3])
             << 24);
    }
    const auto seed_manifest =
        rc::BuildRCStage3StreamEndpointCanonicalManifest(
            rc::RCStage3StreamFamilyForEndpoint(
                rc::RCStage3RelationEndpoint::
                    EpisodeBuilderSeedChain),
            seed_words, 0, 3);
    std::array<uint32_t, 8> seed_root{};
    BOOST_REQUIRE(
        rc::RCStage3StreamEndpointCommittedRoot(
            rc::RCStage3StreamFamilyForEndpoint(
                rc::RCStage3RelationEndpoint::
                    EpisodeBuilderSeedChain),
            seed_manifest, seed_root, &why));
    const auto& seed_pin =
        candidate.roles.front().endpoints[1];
    BOOST_CHECK(
        seed_pin.endpoint ==
        rc::RCStage3RelationEndpoint::
            EpisodeBuilderSeedChain);
    for (uint32_t limb = 0; limb < 4; ++limb) {
        BOOST_CHECK_EQUAL(
            seed_pin.committed_root[limb],
            uint64_t{seed_root[2U * limb]} |
                (uint64_t{seed_root[2U * limb + 1U]}
                 << 32));
    }
    BOOST_CHECK(rc::gkr_field::Eq(
        candidate.columns[
            seed_pin.bank_value_column][0],
        rc::RCStage3StreamEndpointCtlValue(
            seed_manifest)));
    BOOST_REQUIRE_EQUAL(
        candidate
            .direct_builder_stream_children
            .size(),
        2U);
    BOOST_CHECK(
        candidate
            .builder_stream_relations_same_parent);
    BOOST_CHECK(
        !candidate
             .direct_parent_base_row_root
             .IsNull());
    BOOST_CHECK(
        candidate.direct_parent_base_column_indices
            .size() <
        candidate.cs.n_columns);
    for (const auto& child :
         candidate.direct_builder_stream_children) {
        BOOST_CHECK(
            child.complete_relation_same_parent);
        BOOST_CHECK(
            child.value_same_parent_aliased);
        BOOST_CHECK(
            child.root_same_parent_aliased);
        for (uint32_t root_column :
             child.child_root_parent_columns) {
            BOOST_REQUIRE_LT(
                root_column,
                candidate.cs.n_columns);
            // These are the hash AIR's ordinary final-word exports.  They
            // must not be metadata or a preprocessed root pin masquerading
            // as a child output.
            BOOST_CHECK(
                std::none_of(
                    candidate.cs.preprocessed.begin(),
                    candidate.cs.preprocessed.end(),
                    [root_column](const auto& fixed) {
                        return fixed.first ==
                            root_column;
                    }));
        }
    }

    // This parent is executable, but the live audit still reports missing
    // recursive semantic children.  It must never be silently promoted into
    // production authority.
    BOOST_CHECK(
        !candidate
             .recursive_semantic_closure_complete);
    BOOST_CHECK(!candidate.production_authority);
    BOOST_CHECK(!candidate.residuals.empty());

    // A forged canonical-bank cell is rejected by the actual composed
    // constraints.  This attacks the literal role->bank equality rather than
    // a host-side status flag.
    auto forged = candidate.columns;
    const uint32_t value_column =
        candidate.roles.front()
            .endpoints.front()
            .bank_value_column;
    forged[value_column][0] =
        rc::gkr_field::Add(
            forged[value_column][0],
            rc::gkr_field::Fp3::One());
    BOOST_CHECK_GT(
        rc::air_recurse::
            CountWitnessViolationsOnH(
                candidate.cs, forged),
        0U);

    // Expensive proof-level gate: prove the actual two-child parent once,
    // then coherently substitute both the SHA child output and the linked
    // role root cell.  The equality remains satisfied, but the SHA/root
    // relation does not; even a forced inexact proof is rejected by the
    // unmodified Split-RAP verifier.
    if (std::getenv(
            "BTX_RUN_STAGE3_BUILDER_DIRECT_PARENT_PROOF") !=
        nullptr) {
        namespace aq = rc::air_quotient;
        const auto proved =
            aq::AirQuotientProveRowsSplitRap(
                candidate.cs, candidate.columns,
                candidate
                    .direct_parent_base_column_indices,
                candidate
                    .direct_builder_public_fs_seed);
        BOOST_REQUIRE_MESSAGE(
            proved.ok, proved.note);
        BOOST_REQUIRE(proved.division_exact);
        BOOST_CHECK_MESSAGE(
            aq::AirQuotientVerifyRowsSplitRap(
                candidate.cs, proved.proof,
                candidate
                    .direct_parent_base_column_indices,
                candidate
                    .direct_builder_public_fs_seed,
                &why),
            why);

        auto substituted = candidate.columns;
        const auto& direct =
            candidate
                .direct_builder_stream_children
                .front();
        const uint32_t child_root =
            direct.child_root_parent_columns[0];
        const uint32_t role_root =
            direct.role_root_word_columns[0];
        const uint32_t child_value =
            direct.child_value_parent_column;
        const uint32_t role_value =
            direct.role_bank_value_column;
        for (uint32_t row = 0;
             row < candidate.cs.n_rows; ++row) {
            // Lifted child exports are zero on padding; mutate only its
            // original active rows while changing the role's broadcast root
            // everywhere.  Row zero remains a coherent alias substitution.
            if (row <
                direct.child_rows) {
                substituted[child_root][row] =
                    rc::gkr_field::Add(
                        substituted[child_root][row],
                        rc::gkr_field::Fp3::One());
                substituted[child_value][row] =
                    rc::gkr_field::Add(
                        substituted[child_value][row],
                        rc::gkr_field::Fp3::One());
            }
            substituted[role_root][row] =
                rc::gkr_field::Add(
                    substituted[role_root][row],
                    rc::gkr_field::Fp3::One());
            substituted[role_value][row] =
                rc::gkr_field::Add(
                    substituted[role_value][row],
                    rc::gkr_field::Fp3::One());
        }
        BOOST_CHECK_GT(
            rc::air_recurse::
                CountWitnessViolationsOnH(
                    candidate.cs, substituted),
            0U);
        aq::AirProveOptions force;
        force.force_commit_on_inexact = true;
        auto substituted_cs = candidate.cs;
        const uint256 substituted_r0 =
            aq::AirQuotientTwoEpochBaseRowCommitment(
                substituted_cs, substituted,
                candidate
                    .direct_parent_base_column_indices,
                &why);
        BOOST_REQUIRE_MESSAGE(
            !substituted_r0.IsNull(), why);
        BOOST_REQUIRE_EQUAL(
            substituted_cs
                .preprocessed_row_group_roots
                .size(),
            1U);
        substituted_cs
            .preprocessed_row_group_roots[0]
            .root = substituted_r0;
        const auto substituted_proof =
            aq::AirQuotientProveRowsSplitRap(
                substituted_cs, substituted,
                candidate
                    .direct_parent_base_column_indices,
                candidate
                    .direct_builder_public_fs_seed,
                force);
        BOOST_REQUIRE_MESSAGE(
            substituted_proof.ok,
            substituted_proof.note);
        BOOST_CHECK(
            !substituted_proof.division_exact);
        BOOST_CHECK(
            !aq::AirQuotientVerifyRowsSplitRap(
                candidate.cs,
                substituted_proof.proof,
                candidate
                    .direct_parent_base_column_indices,
                candidate
                    .direct_builder_public_fs_seed,
                &why));
    }
}

BOOST_AUTO_TEST_CASE(
    bounded_direct_builder_parent_proves_and_rejects_coherent_substitution)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_BUILDER_DIRECT_PARENT_CANARY") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_BUILDER_DIRECT_PARENT_CANARY=1");
        return;
    }
    namespace builder =
        rc::normalized_production_parent_builder;
    namespace aq = rc::air_quotient;
    const std::array<uint32_t, 8> seed_words{
        0x01020304U, 0x11121314U,
        0x21222324U, 0x31323334U,
        0x41424344U, 0x51525354U,
        0x61626364U, 0x71727374U};
    const std::array<uint32_t, 8> xof_words{
        0x81828384U, 0x91929394U,
        0xa1a2a3a4U, 0xb1b2b3b4U,
        0xc1c2c3c4U, 0xd1d2d3d4U,
        0xe1e2e3e4U, 0xf1f2f3f4U};
    const std::array<
        rc::RCStage3StreamEndpointManifest, 2>
        manifests{
            rc::BuildRCStage3StreamEndpointCanonicalManifest(
                rc::RCStage3StreamFamilyForEndpoint(
                    rc::RCStage3RelationEndpoint::
                        EpisodeBuilderSeedChain),
                seed_words, 0, 0),
            rc::BuildRCStage3StreamEndpointCanonicalManifest(
                rc::RCStage3StreamFamilyForEndpoint(
                    rc::RCStage3RelationEndpoint::
                        EpisodeBuilderOperandXof),
                xof_words, 0, 0),
        };
    uint256 public_seed;
    std::fill(
        public_seed.begin(), public_seed.end(),
        static_cast<unsigned char>(0x6d));
    builder::ProductionRelationParentCandidateV1
        parent;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        builder::
            BuildDirectBuilderStreamParentCanaryV1(
                manifests, public_seed,
                parent, &why),
        why);
    BOOST_REQUIRE(parent.local_parent_valid);
    BOOST_REQUIRE(
        parent.builder_stream_relations_same_parent);
    BOOST_REQUIRE_EQUAL(
        parent.direct_builder_stream_children.size(),
        2U);
    for (const auto& child :
         parent.direct_builder_stream_children) {
        BOOST_REQUIRE(
            child.complete_relation_same_parent);
        for (uint32_t root_column :
             child.child_root_parent_columns) {
            BOOST_CHECK(
                std::none_of(
                    parent.cs.preprocessed.begin(),
                    parent.cs.preprocessed.end(),
                    [root_column](const auto& fixed) {
                        return fixed.first ==
                            root_column;
                    }));
        }
    }

    const auto proved =
        aq::AirQuotientProveRowsSplitRap(
            parent.cs, parent.columns,
            parent.direct_parent_base_column_indices,
            public_seed);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRowsSplitRap(
            parent.cs, proved.proof,
            parent.direct_parent_base_column_indices,
            public_seed, &why),
        why);

    auto substituted = parent.columns;
    const auto& child =
        parent.direct_builder_stream_children.front();
    for (uint32_t row = 0;
         row < parent.cs.n_rows; ++row) {
        if (row < child.child_rows) {
            substituted[
                child.child_value_parent_column][row] =
                rc::gkr_field::Add(
                    substituted[
                        child
                            .child_value_parent_column][row],
                    rc::gkr_field::Fp3::One());
            substituted[
                child.child_root_parent_columns[0]][row] =
                rc::gkr_field::Add(
                    substituted[
                        child
                            .child_root_parent_columns[0]][row],
                    rc::gkr_field::Fp3::One());
        }
        substituted[
            child.role_bank_value_column][row] =
            rc::gkr_field::Add(
                substituted[
                    child.role_bank_value_column][row],
                rc::gkr_field::Fp3::One());
        substituted[
            child.role_root_word_columns[0]][row] =
            rc::gkr_field::Add(
                substituted[
                    child.role_root_word_columns[0]][row],
                rc::gkr_field::Fp3::One());
    }
    BOOST_REQUIRE_GT(
        rc::air_recurse::CountWitnessViolationsOnH(
            parent.cs, substituted),
        0U);
    auto substituted_cs = parent.cs;
    const uint256 substituted_r0 =
        aq::AirQuotientTwoEpochBaseRowCommitment(
            substituted_cs, substituted,
            parent.direct_parent_base_column_indices,
            &why);
    BOOST_REQUIRE_MESSAGE(
        !substituted_r0.IsNull(), why);
    BOOST_REQUIRE_EQUAL(
        substituted_cs
            .preprocessed_row_group_roots.size(),
        1U);
    substituted_cs.preprocessed_row_group_roots[0]
        .root = substituted_r0;
    aq::AirProveOptions force;
    force.force_commit_on_inexact = true;
    const auto forged =
        aq::AirQuotientProveRowsSplitRap(
            substituted_cs, substituted,
            parent.direct_parent_base_column_indices,
            public_seed, force);
    BOOST_REQUIRE_MESSAGE(forged.ok, forged.note);
    BOOST_REQUIRE(!forged.division_exact);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            parent.cs, forged.proof,
            parent.direct_parent_base_column_indices,
            public_seed, &why));
}

BOOST_AUTO_TEST_CASE(non_rc_height_requires_no_attachment)
{
    const auto params = RealChainLikeParams(false);
    CBlock block = RealRcBlock102();
    const uint256 target = TargetFor(block, params);

    ScopedProofSource installed{
        [&](const CBlock& solved, const Consensus::Params& p, int32_t h,
            const uint256& t, const rc::RCStage3ProducerHints&,
            rc::RCStage3SuccinctProof& out, std::string*) {
            out = StatementBoundTo(solved, p, h, t);
            return true;
        }};

    Consensus::Params pre_rc = params;
    pre_rc.nMatMulRCHeight = std::numeric_limits<int32_t>::max();
    pre_rc.nMatMulRCCoupledHeight = std::numeric_limits<int32_t>::max();

    std::string why;
    const auto produced = rc::AttachRCStage3ProofFromSource(
        block, pre_rc, /*height=*/102, target, &why);
    BOOST_CHECK(produced == rc::RCStage3ProduceStatus::NotRequired);
    BOOST_CHECK(!rc::RCStage3ProduceIsFatal(produced));
    // Attaching outside the RC family would make the block self-rejecting
    // ("v4-encdr-nonempty-sketch"); the body must stay empty.
    BOOST_CHECK(block.matrix_c_data.empty());
}

BOOST_AUTO_TEST_CASE(consensus_verdict_mapping_is_total_and_fails_closed)
{
    using S = rc::RCStage3AttachmentStatus;
    using A = rc::RCStage3ConsensusAction;

    // Exactly one status accepts. Everything else refuses, one way or another.
    BOOST_CHECK(rc::RCStage3ConsensusVerdictFor(S::Valid).action ==
                A::AcceptProceed);

    // A block with NO proof is REJECTED, as a body mutation with a distinct
    // reason so it can be told apart from a corrupt one.
    const auto missing = rc::RCStage3ConsensusVerdictFor(S::Missing);
    BOOST_CHECK(missing.action == A::RejectMutation);
    BOOST_CHECK_EQUAL(missing.reject_reason, "missing-matmul-stage3-proof");

    // A block with a TAMPERED proof is REJECTED, also as a body mutation: the
    // header hash is untouched, so an honest body may still arrive.
    for (const S status : {S::Malformed, S::BindingMismatch,
                           S::MathematicalVerificationFailed}) {
        const auto v = rc::RCStage3ConsensusVerdictFor(status);
        BOOST_CHECK(v.action == A::RejectMutation);
        BOOST_CHECK_EQUAL(v.reject_reason, "bad-matmul-stage3-proof");
    }

    // Fail-closed statuses never accept. NotRequired is included deliberately:
    // reaching this mapping means a proof WAS required, so NotRequired is a
    // params inconsistency and must not be mistaken for acceptance.
    for (const S status : {S::AuthorityUnavailable,
                           S::ReadyForMathematicalVerification,
                           S::NotRequired}) {
        const auto v = rc::RCStage3ConsensusVerdictFor(status);
        BOOST_CHECK(v.action == A::RejectConsensus);
        BOOST_CHECK_EQUAL(v.reject_reason, "matmul-stage3-authority-unavailable");
    }

    // Totality: no status anywhere in the enum's range accepts except Valid.
    for (int raw = 0; raw <= 16; ++raw) {
        const auto v = rc::RCStage3ConsensusVerdictFor(static_cast<S>(raw));
        if (static_cast<S>(raw) != S::Valid) {
            BOOST_CHECK_MESSAGE(v.action != A::AcceptProceed,
                                "status " << raw << " must not accept");
        }
    }
}

BOOST_AUTO_TEST_CASE(real_block_verdicts_end_to_end)
{
    // Tie the two halves together over REAL block bytes: run the attachment
    // pipeline, then map its status the way validation.cpp would.
    constexpr int32_t HEIGHT{102};
    const auto params = RealChainLikeParams(false);
    const uint256 target = TargetFor(RealRcBlock102(), params);
    std::string why;

    // (a) MISSING proof -> BLOCK_MUTATED / missing-matmul-stage3-proof.
    {
        const CBlock bare = RealRcBlock102();
        const auto status = rc::InspectRCStage3ConsensusAttachment(
            bare, params, HEIGHT, target, nullptr, nullptr, &why);
        const auto verdict = rc::RCStage3ConsensusVerdictFor(status);
        BOOST_CHECK(verdict.action == rc::RCStage3ConsensusAction::RejectMutation);
        BOOST_CHECK_EQUAL(verdict.reject_reason, "missing-matmul-stage3-proof");
    }

    ScopedProofSource installed{
        [&](const CBlock& solved, const Consensus::Params& p, int32_t h,
            const uint256& t, const rc::RCStage3ProducerHints&,
            rc::RCStage3SuccinctProof& out, std::string*) {
            out = StatementBoundTo(solved, p, h, t);
            return true;
        }};

    CBlock honest = RealRcBlock102();
    BOOST_REQUIRE(rc::AttachRCStage3ProofFromSource(honest, params, HEIGHT,
                                                    target, &why) ==
                  rc::RCStage3ProduceStatus::Attached);

    // (b) TAMPERED proof -> BLOCK_MUTATED / bad-matmul-stage3-proof.
    {
        CBlock tampered = honest;
        tampered.matrix_c_data[tampered.matrix_c_data.size() / 2] ^= 0x40u;
        const auto status = rc::InspectRCStage3ConsensusAttachment(
            tampered, params, HEIGHT, target, nullptr, nullptr, &why);
        const auto verdict = rc::RCStage3ConsensusVerdictFor(status);
        BOOST_CHECK(verdict.action == rc::RCStage3ConsensusAction::RejectMutation);
        BOOST_CHECK_EQUAL(verdict.reject_reason, "bad-matmul-stage3-proof");
    }

    // (c) HONEST proof -> NOT a mutation, and NOT accepted either, because the
    //     mathematical authority is off. This is the ceiling of what can be
    //     demonstrated today, and it is stated as such rather than dressed up
    //     as "a valid proof validates".
    {
        const auto status = rc::InspectRCStage3ConsensusAttachment(
            honest, params, HEIGHT, target, nullptr, nullptr, &why);
        BOOST_CHECK(status == rc::RCStage3AttachmentStatus::AuthorityUnavailable);
        const auto verdict = rc::RCStage3ConsensusVerdictFor(status);
        BOOST_CHECK(verdict.action ==
                    rc::RCStage3ConsensusAction::RejectConsensus);
        BOOST_CHECK(verdict.action != rc::RCStage3ConsensusAction::AcceptProceed);
    }
}

// ---------------------------------------------------------------------------
// THE GATE. Nothing above may leak onto a live path while authority is off.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(consensus_entry_point_is_fail_closed_while_authority_is_off)
{
    // Guard the premise of this whole file. If this ever fails, the assertions
    // below are testing something different from what they claim.
    BOOST_REQUIRE(!rc::kRCStage3SuccinctAuthorityReady);

    constexpr int32_t HEIGHT{102};
    const auto params = RealChainLikeParams(false);
    CBlock block = RealRcBlock102();

    // Even with a perfectly good prover installed, the GATED entry point must
    // not attach anything: validation.cpp currently rejects a non-empty body at
    // DIGEST_RECOMPUTE heights, so a producer that ran early would mine blocks
    // its own node rejects.
    ScopedProofSource installed{
        [&](const CBlock& solved, const Consensus::Params& p, int32_t h,
            const uint256& t, const rc::RCStage3ProducerHints&,
            rc::RCStage3SuccinctProof& out, std::string*) {
            out = StatementBoundTo(solved, p, h, t);
            return true;
        }};

    std::string why;
    const auto produced = rc::ProduceAndAttachRCStage3ConsensusProof(
        block, params, HEIGHT, &why);
    BOOST_CHECK(produced == rc::RCStage3ProduceStatus::AuthorityDisabled);
    BOOST_CHECK(!rc::RCStage3ProduceIsFatal(produced));
    BOOST_CHECK(block.matrix_c_data.empty());
}

BOOST_AUTO_TEST_CASE(production_finalizer_is_inert_on_the_real_block_today)
{
    constexpr int HEIGHT{102};
    const auto params = RealChainLikeParams(false);
    CBlock block = RealRcBlock102();
    const CBlock before = block;

    ScopedProofSource installed{
        [&](const CBlock& solved, const Consensus::Params& p, int32_t h,
            const uint256& t, const rc::RCStage3ProducerHints&,
            rc::RCStage3SuccinctProof& out, std::string*) {
            out = StatementBoundTo(solved, p, h, t);
            return true;
        }};

    // The miner-path seam. While the authority gate is false it must behave
    // exactly like the pre-Stage-3 finalizer: succeed, attach nothing, and
    // report that no sketch was offloaded (the real block's body is already
    // empty, so there is nothing to offload).
    std::string why;
    bool offloaded{true};
    const bool ok = FinalizeMatMulSolvedBlockForProduction(block, params, HEIGHT,
                                                           &why, &offloaded);
    BOOST_CHECK(ok);
    BOOST_CHECK(why.empty());
    BOOST_CHECK(!offloaded);
    BOOST_CHECK(block.matrix_c_data == before.matrix_c_data);
    BOOST_CHECK(block.GetHash() == before.GetHash());
}

BOOST_AUTO_TEST_SUITE_END()

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled.h>
#include <matmul/matmul_v4_rc_stage3_consensus.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_coupled_tests, BasicTestingSetup)

namespace {

constexpr std::array<rc::RCStage3RelationRole, 8> COUPLED_ROLES{
    rc::RCStage3RelationRole::CoupledBank,
    rc::RCStage3RelationRole::CoupledGemm,
    rc::RCStage3RelationRole::CoupledExchange,
    rc::RCStage3RelationRole::CoupledPermutation,
    rc::RCStage3RelationRole::CoupledMix,
    rc::RCStage3RelationRole::CoupledExtract,
    rc::RCStage3RelationRole::CoupledBarrier,
    rc::RCStage3RelationRole::CoupledDigest,
};

uint256 Filled(unsigned char value)
{
    uint256 out;
    std::fill(out.begin(), out.end(), value);
    return out;
}

rc::RCStage3SuccinctProof MakeCoupledProof()
{
    rc::RCStage3SuccinctProof proof;
    proof.statement = rc::RCStage3StatementKind::Coupled;
    auto& public_inputs = proof.public_inputs;
    public_inputs.height = 42;
    public_inputs.n_bits = 0x207fffff;
    public_inputs.coupled_profile = 4;
    public_inputs.transcript_version = rc::ENC_RC_V4;
    public_inputs.program_consensus_pin.recursive_alg_hash_root =
        Filled(0x08);
    public_inputs.program_consensus_pin.external_sha256d_audit_root =
        Filled(0x09);
    public_inputs.program_consensus_pin.registry_binding =
        Filled(0x0a);
    public_inputs.header_commitment = Filled(0x11);
    public_inputs.params_commitment = Filled(0x22);
    public_inputs.target = Filled(0x7f);
    public_inputs.sigma = Filled(0x33);
    public_inputs.coupled_digest = Filled(0x44);
    public_inputs.final_digest = Filled(0x55);
    public_inputs.transcript_commitment = Filled(0x66);

    const rc::RCStage3CoupledShape shape = rc::MakeRCStage3CoupledShape(
        rc::MakeMediumV3RCCoupParams(), rc::MakeMediumV4RCCoupOptions());
    const uint256 statement = rc::CommitRCStage3CoupledStatement(public_inputs);
    const uint256 shape_commitment = rc::CommitRCStage3CoupledShape(shape);
    uint256 input_root = public_inputs.header_commitment;

    for (size_t i = 0; i < COUPLED_ROLES.size(); ++i) {
        rc::RCStage3CoupledRelationReceipt receipt;
        receipt.role = COUPLED_ROLES[i];
        receipt.shape = shape;
        receipt.statement_commitment = statement;
        receipt.params_commitment = public_inputs.params_commitment;
        receipt.coupled_shape_commitment = shape_commitment;
        receipt.sigma = public_inputs.sigma;
        receipt.input_root = input_root;
        receipt.output_root =
            i + 1 == COUPLED_ROLES.size()
                ? public_inputs.coupled_digest
                : Filled(static_cast<unsigned char>(0x80 + i));
        receipt.trace_root = Filled(static_cast<unsigned char>(0xa0 + i));
        const auto counts =
            rc::ExpectedRCStage3CoupledRelationCounts(receipt.role, shape);
        BOOST_REQUIRE(counts.has_value());
        receipt.primary_count = counts->primary;
        receipt.secondary_count = counts->secondary;
        receipt.engine_receipt = {
            static_cast<unsigned char>(i), 0xc3, 0x5a, 0xa5};
        receipt.aggregate_root =
            rc::CommitRCStage3CoupledRelationAggregate(receipt);

        std::vector<unsigned char> section;
        BOOST_REQUIRE(rc::SerializeRCStage3CoupledRelationReceipt(receipt, section));
        proof.commitments.push_back(
            {receipt.role, rc::CommitRCStage3CoupledSection(section)});
        proof.sections.push_back({receipt.role, std::move(section)});
        input_root = receipt.output_root;
    }
    return proof;
}

size_t RoleIndex(rc::RCStage3RelationRole role)
{
    const auto it = std::find(COUPLED_ROLES.begin(), COUPLED_ROLES.end(), role);
    BOOST_REQUIRE(it != COUPLED_ROLES.end());
    return static_cast<size_t>(std::distance(COUPLED_ROLES.begin(), it));
}

rc::RCStage3CoupledRelationReceipt DecodeAt(const rc::RCStage3SuccinctProof& proof,
                                            size_t index)
{
    const auto receipt =
        rc::DeserializeRCStage3CoupledRelationReceipt(proof.sections[index].proof);
    BOOST_REQUIRE(receipt.has_value());
    return *receipt;
}

void ReplaceAt(rc::RCStage3SuccinctProof& proof, size_t index,
               rc::RCStage3CoupledRelationReceipt receipt)
{
    receipt.aggregate_root = rc::CommitRCStage3CoupledRelationAggregate(receipt);
    std::vector<unsigned char> section;
    BOOST_REQUIRE(rc::SerializeRCStage3CoupledRelationReceipt(receipt, section));
    proof.sections[index].proof = section;
    proof.commitments[index].root = rc::CommitRCStage3CoupledSection(section);
}

// Minimal shape satisfying ValidateShape (barriers in [4,8], MX-aligned power
// of two state, proof-friendly V4 permutation domain) but with lobe_width=32
// and only 1 bank page so BankDequantPagesV1 proofs fit the receipt bound and
// the suite stays fast (~1.8 MiB / ~4s per honest prove).
rc::RCStage3CoupledShape MakeBankDequantEngineTestShape()
{
    rc::RCCoupParams params;
    params.barriers = 4;
    params.lobes = 1;
    params.lobe_width = 32;
    params.bank_pages = 1;
    params.rows_per_lobe = 1;
    params.pages_per_barrier_lobe = 1;
    BOOST_REQUIRE(rc::ValidateRCCoupParams(params));
    return rc::MakeRCStage3CoupledShape(params, rc::MakeMediumV4RCCoupOptions());
}

std::vector<rc::RCStage3CoupledBankDequantPageWitness>
MakeHonestBankDequantWitness(const rc::RCStage3CoupledShape& shape)
{
    const uint32_t logical = shape.lobe_width * shape.lobe_width;
    std::vector<rc::RCStage3CoupledBankDequantPageWitness> pages(shape.bank_pages);
    for (uint32_t p = 0; p < shape.bank_pages; ++p) {
        pages[p].mantissa.resize(logical);
        pages[p].scale.resize(logical);
        for (uint32_t cell = 0; cell < logical; ++cell) {
            const int64_t mantissa =
                static_cast<int64_t>((cell + p * 7) % 11) - 5; // [-5,5]
            pages[p].mantissa[cell] = static_cast<int8_t>(mantissa);
            pages[p].scale[cell] = static_cast<uint8_t>((cell + p) % 4); // [0,3]
        }
    }
    return pages;
}

} // namespace

BOOST_AUTO_TEST_CASE(coupled_exact_relation_coverage_counts)
{
    const auto shape = rc::MakeRCStage3CoupledShape(
        rc::MakeMediumV3RCCoupParams(), rc::MakeMediumV4RCCoupOptions());
    const std::array<rc::RCStage3CoupledRelationCounts, 8> expected{{
        {64, 64},       // every bank page and every scheduled selection
        {64, 16},       // every scheduled page GEMM, grouped by barrier/lobe
        {16, 32'768},   // every fixed lobe segment; no extra exchange rounds
        {4, 32'768},    // one public affine permutation per barrier
        {52, 32'768},   // 4 * log2(8192) butterfly stages
        {1'024, 32'768},// every 32-cell Extract tile
        {4, 32'768},    // every barrier and state byte
        {1, 5},         // bank root plus four barrier roots
    }};
    for (size_t i = 0; i < COUPLED_ROLES.size(); ++i) {
        const auto actual =
            rc::ExpectedRCStage3CoupledRelationCounts(COUPLED_ROLES[i], shape);
        BOOST_REQUIRE(actual.has_value());
        BOOST_CHECK(*actual == expected[i]);
    }

    auto overflowing = shape;
    overflowing.lobes = std::numeric_limits<uint32_t>::max();
    std::string why;
    BOOST_CHECK(!rc::ExpectedRCStage3CoupledRelationCounts(
                     rc::RCStage3RelationRole::CoupledMix, overflowing, &why)
                     .has_value());
    BOOST_CHECK(why.find("state_bytes_overflow") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(coupled_receipt_codec_is_canonical_and_bounded)
{
    const auto proof = MakeCoupledProof();
    for (size_t i = 0; i < COUPLED_ROLES.size(); ++i) {
        const auto decoded =
            rc::DeserializeRCStage3CoupledRelationReceipt(proof.sections[i].proof);
        BOOST_REQUIRE(decoded.has_value());
        std::vector<unsigned char> encoded;
        BOOST_REQUIRE(rc::SerializeRCStage3CoupledRelationReceipt(*decoded, encoded));
        BOOST_CHECK(encoded == proof.sections[i].proof);

        encoded.push_back(0);
        std::string why;
        BOOST_CHECK(
            !rc::DeserializeRCStage3CoupledRelationReceipt(encoded, &why).has_value());
        BOOST_CHECK(why.find("engine_length") != std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(coupled_statement_commitment_has_no_proof_hash_cycle)
{
    const auto proof = MakeCoupledProof();
    const uint256 commitment =
        rc::CommitRCStage3CoupledStatement(proof.public_inputs);

    auto post_proof = proof.public_inputs;
    post_proof.transcript_commitment = Filled(0xee);
    BOOST_CHECK(rc::CommitRCStage3CoupledStatement(post_proof) == commitment);

    auto changed_statement = proof.public_inputs;
    changed_statement.final_digest = Filled(0xef);
    BOOST_CHECK(rc::CommitRCStage3CoupledStatement(changed_statement) != commitment);
}

BOOST_AUTO_TEST_CASE(coupled_verifier_rejects_without_proof_only_engines)
{
    const auto proof = MakeCoupledProof();
    std::string why;
    BOOST_REQUIRE(rc::ValidateRCStage3ProofStructure(proof, &why));
    BOOST_CHECK(!rc::kRCStage3CoupledRelationEnginesReady);
    BOOST_CHECK(!rc::RCStage3CoupledRelationEnginesReady(&why));
    BOOST_CHECK(why.find("proof_engines_missing") != std::string::npos);
    BOOST_CHECK(why.find("bank_seed_xof") == std::string::npos);
    BOOST_CHECK(why.find("bank_page_inclusion") == std::string::npos);
    BOOST_CHECK(why.find("exchange") == std::string::npos);
    BOOST_CHECK(why.find("permutation") == std::string::npos);
    BOOST_CHECK(why.find("mix") == std::string::npos);
    BOOST_CHECK(why.find("extract") != std::string::npos);
    BOOST_CHECK(why.find("barrier") != std::string::npos);
    BOOST_CHECK(why.find("digest") != std::string::npos);
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRelations(proof, &why));
    BOOST_CHECK(why.find("coupled:bank:recursive_decode") !=
                std::string::npos);
}

BOOST_AUTO_TEST_CASE(coupled_verifier_rejects_episode_only_and_legacy_permutation)
{
    auto episode = MakeCoupledProof();
    episode.statement = rc::RCStage3StatementKind::Episode;
    std::string why;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRelations(episode, &why));

    auto legacy = MakeCoupledProof();
    legacy.public_inputs.transcript_version = rc::ENC_RC_V3;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRelations(legacy, &why));
    BOOST_CHECK(why.find("transcript_version") != std::string::npos);

    auto legacy_receipt = DecodeAt(MakeCoupledProof(), 0);
    legacy_receipt.shape.transcript_version = rc::ENC_RC_V3;
    legacy_receipt.coupled_shape_commitment =
        rc::CommitRCStage3CoupledShape(legacy_receipt.shape);
    std::vector<unsigned char> bytes;
    BOOST_CHECK(
        !rc::SerializeRCStage3CoupledRelationReceipt(legacy_receipt, bytes, &why));
    BOOST_CHECK(why.find("permutation_not_proof_friendly") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(coupled_every_role_rejects_undercoverage)
{
    for (rc::RCStage3RelationRole role : COUPLED_ROLES) {
        auto proof = MakeCoupledProof();
        const size_t index = RoleIndex(role);
        auto receipt = DecodeAt(proof, index);
        --receipt.primary_count;
        ReplaceAt(proof, index, receipt);

        std::string why;
        BOOST_CHECK(!rc::VerifyRCStage3CoupledRelations(proof, &why));
        BOOST_CHECK_MESSAGE(
            why.find(std::string(rc::RCStage3RelationRoleName(role)) + ":coverage") !=
                std::string::npos,
            why);
    }
}

BOOST_AUTO_TEST_CASE(coupled_every_role_rejects_broken_root_chain)
{
    for (rc::RCStage3RelationRole role : COUPLED_ROLES) {
        auto proof = MakeCoupledProof();
        const size_t index = RoleIndex(role);
        auto receipt = DecodeAt(proof, index);
        receipt.input_root = Filled(0xee);
        ReplaceAt(proof, index, receipt);

        std::string why;
        BOOST_CHECK(!rc::VerifyRCStage3CoupledRelations(proof, &why));
        BOOST_CHECK_MESSAGE(
            why.find(std::string(rc::RCStage3RelationRoleName(role)) + ":input_root") !=
                std::string::npos,
            why);
    }
}

BOOST_AUTO_TEST_CASE(coupled_rejects_commitment_aggregate_and_public_mutations)
{
    std::string why;
    auto section_mutation = MakeCoupledProof();
    section_mutation.sections[3].proof.back() ^= 1;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRelations(section_mutation, &why));
    BOOST_CHECK(why.find("section_commitment") != std::string::npos);

    auto aggregate_mutation = MakeCoupledProof();
    auto receipt = DecodeAt(aggregate_mutation, 4);
    receipt.aggregate_root = Filled(0xfe);
    std::vector<unsigned char> section;
    BOOST_REQUIRE(
        rc::SerializeRCStage3CoupledRelationReceipt(receipt, section));
    aggregate_mutation.sections[4].proof = section;
    aggregate_mutation.commitments[4].root =
        rc::CommitRCStage3CoupledSection(section);
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRelations(aggregate_mutation, &why));
    BOOST_CHECK(why.find("aggregate_root") != std::string::npos);

    auto public_mutation = MakeCoupledProof();
    public_mutation.public_inputs.sigma = Filled(0xef);
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRelations(public_mutation, &why));
    BOOST_CHECK(why.find("public_binding") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(coupled_bank_dequant_engine_accepts_honest_witness)
{
    const auto shape = MakeBankDequantEngineTestShape();
    const uint256 statement_commitment = Filled(0x51);
    const uint256 shape_commitment = Filled(0x52);
    const uint256 sigma = Filled(0x53);
    const auto pages = MakeHonestBankDequantWitness(shape);

    std::vector<unsigned char> engine_receipt;
    uint256 trace_root;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankDequantEngineReceipt(
            shape, statement_commitment, shape_commitment, sigma, pages,
            engine_receipt, trace_root, &why),
        why);
    BOOST_CHECK(!trace_root.IsNull());
    BOOST_CHECK(!engine_receipt.empty());

    uint256 verified_trace_root;
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3CoupledBankDequantEngineReceipt(
            shape, statement_commitment, shape_commitment, sigma, engine_receipt,
            verified_trace_root, &why),
        why);
    BOOST_CHECK(verified_trace_root == trace_root);

    // Rebuilding from the identical witness reproduces the same trace root
    // (deterministic honest prover).
    std::vector<unsigned char> engine_receipt2;
    uint256 trace_root2;
    BOOST_REQUIRE(rc::BuildRCStage3CoupledBankDequantEngineReceipt(
        shape, statement_commitment, shape_commitment, sigma, pages,
        engine_receipt2, trace_root2, &why));
    BOOST_CHECK(trace_root2 == trace_root);

    // A different honest witness produces a different trace root.
    auto other_pages = pages;
    other_pages[0].mantissa[0] =
        static_cast<int8_t>(other_pages[0].mantissa[0] == 5 ? 4 : 5);
    std::vector<unsigned char> other_engine_receipt;
    uint256 other_trace_root;
    BOOST_REQUIRE(rc::BuildRCStage3CoupledBankDequantEngineReceipt(
        shape, statement_commitment, shape_commitment, sigma, other_pages,
        other_engine_receipt, other_trace_root, &why));
    BOOST_CHECK(other_trace_root != trace_root);
}

BOOST_AUTO_TEST_CASE(coupled_bank_dequant_engine_rejects_bad_witness_at_build_time)
{
    const auto shape = MakeBankDequantEngineTestShape();
    const uint256 statement_commitment = Filled(0x51);
    const uint256 shape_commitment = Filled(0x52);
    const uint256 sigma = Filled(0x53);
    const auto pages = MakeHonestBankDequantWitness(shape);
    std::string why;

    {
        // Wrong page count vs shape.bank_pages.
        auto too_few = pages;
        too_few.pop_back();
        std::vector<unsigned char> out;
        uint256 root;
        BOOST_CHECK(!rc::BuildRCStage3CoupledBankDequantEngineReceipt(
            shape, statement_commitment, shape_commitment, sigma, too_few, out,
            root, &why));
        BOOST_CHECK(why.find("page_count") != std::string::npos);
    }
    {
        // Wrong per-page cell count (must be lobe_width^2).
        auto bad_shape_pages = pages;
        bad_shape_pages[0].mantissa.pop_back();
        std::vector<unsigned char> out;
        uint256 root;
        BOOST_CHECK(!rc::BuildRCStage3CoupledBankDequantEngineReceipt(
            shape, statement_commitment, shape_commitment, sigma, bad_shape_pages,
            out, root, &why));
        BOOST_CHECK(why.find("page_shape") != std::string::npos);
    }
    {
        auto bad_scale_len = pages;
        bad_scale_len[0].scale.pop_back();
        std::vector<unsigned char> out;
        uint256 root;
        BOOST_CHECK(!rc::BuildRCStage3CoupledBankDequantEngineReceipt(
            shape, statement_commitment, shape_commitment, sigma, bad_scale_len,
            out, root, &why));
        BOOST_CHECK(why.find("page_shape") != std::string::npos);
    }
    {
        // Scale must be in [0,3] (two-bit factor exponent).
        auto bad_scale_range = pages;
        bad_scale_range[0].scale[0] = 4;
        std::vector<unsigned char> out;
        uint256 root;
        BOOST_CHECK(!rc::BuildRCStage3CoupledBankDequantEngineReceipt(
            shape, statement_commitment, shape_commitment, sigma,
            bad_scale_range, out, root, &why));
        BOOST_CHECK(why.find("scale_range") != std::string::npos);
    }
    {
        // Non-power-of-two logical row count is rejected up front.
        auto odd_shape = shape;
        odd_shape.lobe_width = 3; // 3*3=9, not a power of two
        std::vector<unsigned char> out;
        uint256 root;
        BOOST_CHECK(!rc::BuildRCStage3CoupledBankDequantEngineReceipt(
            odd_shape, statement_commitment, shape_commitment, sigma, pages, out,
            root, &why));
        BOOST_CHECK(why.find("logical_rows") != std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(coupled_bank_dequant_engine_rejects_tampered_receipts)
{
    const auto shape = MakeBankDequantEngineTestShape();
    const uint256 statement_commitment = Filled(0x51);
    const uint256 shape_commitment = Filled(0x52);
    const uint256 sigma = Filled(0x53);
    const auto pages = MakeHonestBankDequantWitness(shape);

    std::vector<unsigned char> engine_receipt;
    uint256 trace_root;
    std::string why;
    BOOST_REQUIRE(rc::BuildRCStage3CoupledBankDequantEngineReceipt(
        shape, statement_commitment, shape_commitment, sigma, pages,
        engine_receipt, trace_root, &why));

    // Flipping the trailing proof byte breaks either the wire codec or the
    // AirQuotient verification itself.
    {
        auto tampered = engine_receipt;
        tampered.back() ^= 0x01;
        uint256 out_root;
        BOOST_CHECK(!rc::VerifyRCStage3CoupledBankDequantEngineReceipt(
            shape, statement_commitment, shape_commitment, sigma, tampered,
            out_root, &why));
    }

    // Flipping a byte inside the first page's serialized pin.statement_commitment
    // (header(10) + page_index(4) + pin.version(2) == byte offset 16) must be
    // caught as an explicit public-binding failure.
    {
        auto tampered = engine_receipt;
        BOOST_REQUIRE(tampered.size() > 20);
        tampered[20] ^= 0x01;
        uint256 out_root;
        BOOST_CHECK(!rc::VerifyRCStage3CoupledBankDequantEngineReceipt(
            shape, statement_commitment, shape_commitment, sigma, tampered,
            out_root, &why));
        BOOST_CHECK_MESSAGE(why.find("page_binding") != std::string::npos, why);
    }

    // Corrupting the header magic/version/page-count is rejected up front.
    {
        auto tampered = engine_receipt;
        tampered[0] ^= 0x01;
        uint256 out_root;
        BOOST_CHECK(!rc::VerifyRCStage3CoupledBankDequantEngineReceipt(
            shape, statement_commitment, shape_commitment, sigma, tampered,
            out_root, &why));
        BOOST_CHECK_MESSAGE(why.find("header") != std::string::npos, why);
    }

    // No cross-statement / cross-shape / cross-sigma replay.
    {
        uint256 out_root;
        BOOST_CHECK(!rc::VerifyRCStage3CoupledBankDequantEngineReceipt(
            shape, Filled(0x61), shape_commitment, sigma, engine_receipt, out_root,
            &why));
        BOOST_CHECK(!rc::VerifyRCStage3CoupledBankDequantEngineReceipt(
            shape, statement_commitment, Filled(0x62), sigma, engine_receipt,
            out_root, &why));
        BOOST_CHECK(!rc::VerifyRCStage3CoupledBankDequantEngineReceipt(
            shape, statement_commitment, shape_commitment, Filled(0x63),
            engine_receipt, out_root, &why));
    }

    // Declaring more bank pages than the receipt proves is rejected before
    // any page proof is even checked.
    {
        auto more_pages_shape = shape;
        more_pages_shape.bank_pages = 2;
        uint256 out_root;
        BOOST_CHECK(!rc::VerifyRCStage3CoupledBankDequantEngineReceipt(
            more_pages_shape, statement_commitment, shape_commitment, sigma,
            engine_receipt, out_root, &why));
        BOOST_CHECK_MESSAGE(why.find("header") != std::string::npos, why);
    }

    // Truncated and padded engine receipts are rejected.
    {
        auto truncated = engine_receipt;
        truncated.resize(truncated.size() / 2);
        uint256 out_root;
        BOOST_CHECK(!rc::VerifyRCStage3CoupledBankDequantEngineReceipt(
            shape, statement_commitment, shape_commitment, sigma, truncated,
            out_root, &why));

        auto padded = engine_receipt;
        padded.push_back(0);
        uint256 padded_root;
        BOOST_CHECK(!rc::VerifyRCStage3CoupledBankDequantEngineReceipt(
            shape, statement_commitment, shape_commitment, sigma, padded,
            padded_root, &why));
        BOOST_CHECK_MESSAGE(why.find("trailing_bytes") != std::string::npos, why);
    }
}

BOOST_AUTO_TEST_CASE(coupled_bank_dequant_engine_wires_into_full_relation_verifier)
{
    const auto shape = MakeBankDequantEngineTestShape();
    const auto pages = MakeHonestBankDequantWitness(shape);

    rc::RCStage3SuccinctProof proof;
    proof.statement = rc::RCStage3StatementKind::Coupled;
    auto& public_inputs = proof.public_inputs;
    public_inputs.height = 42;
    public_inputs.n_bits = 0x207fffff;
    public_inputs.coupled_profile = 4;
    public_inputs.transcript_version = shape.transcript_version;
    public_inputs.program_consensus_pin.recursive_alg_hash_root = Filled(0x08);
    public_inputs.program_consensus_pin.external_sha256d_audit_root = Filled(0x09);
    public_inputs.program_consensus_pin.registry_binding = Filled(0x0a);
    public_inputs.header_commitment = Filled(0x11);
    public_inputs.params_commitment = Filled(0x22);
    public_inputs.target = Filled(0x7f);
    public_inputs.sigma = Filled(0x33);
    public_inputs.coupled_digest = Filled(0x44);
    public_inputs.final_digest = Filled(0x55);
    public_inputs.transcript_commitment = Filled(0x66);

    const uint256 statement = rc::CommitRCStage3CoupledStatement(public_inputs);
    const uint256 shape_commitment = rc::CommitRCStage3CoupledShape(shape);

    std::vector<unsigned char> bank_engine_receipt;
    uint256 bank_trace_root;
    std::string build_why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankDequantEngineReceipt(
            shape, statement, shape_commitment, public_inputs.sigma, pages,
            bank_engine_receipt, bank_trace_root, &build_why),
        build_why);

    uint256 input_root = public_inputs.header_commitment;
    for (size_t i = 0; i < COUPLED_ROLES.size(); ++i) {
        rc::RCStage3CoupledRelationReceipt receipt;
        receipt.role = COUPLED_ROLES[i];
        receipt.shape = shape;
        receipt.statement_commitment = statement;
        receipt.params_commitment = public_inputs.params_commitment;
        receipt.coupled_shape_commitment = shape_commitment;
        receipt.sigma = public_inputs.sigma;
        receipt.input_root = input_root;
        receipt.output_root =
            i + 1 == COUPLED_ROLES.size()
                ? public_inputs.coupled_digest
                : Filled(static_cast<unsigned char>(0x80 + i));
        const auto counts =
            rc::ExpectedRCStage3CoupledRelationCounts(receipt.role, shape);
        BOOST_REQUIRE(counts.has_value());
        receipt.primary_count = counts->primary;
        receipt.secondary_count = counts->secondary;

        if (receipt.role == rc::RCStage3RelationRole::CoupledBank) {
            receipt.engine = rc::RCStage3CoupledProofEngine::BankDequantPagesV1;
            receipt.engine_receipt = bank_engine_receipt;
            receipt.trace_root = bank_trace_root;
        } else {
            receipt.trace_root = Filled(static_cast<unsigned char>(0xa0 + i));
            receipt.engine_receipt = {
                static_cast<unsigned char>(i), 0xc3, 0x5a, 0xa5};
        }
        receipt.aggregate_root = rc::CommitRCStage3CoupledRelationAggregate(receipt);

        std::vector<unsigned char> section;
        std::string serialize_why;
        BOOST_REQUIRE_MESSAGE(
            rc::SerializeRCStage3CoupledRelationReceipt(receipt, section, &serialize_why),
            "role=" + std::string(rc::RCStage3RelationRoleName(receipt.role)) +
                " engine_bytes=" + std::to_string(receipt.engine_receipt.size()) +
                " why=" + serialize_why);
        proof.commitments.push_back(
            {receipt.role, rc::CommitRCStage3CoupledSection(section)});
        proof.sections.push_back({receipt.role, std::move(section)});
        input_root = receipt.output_root;
    }

    std::string why;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRelations(proof, &why));
    // CoupledBank's real engine must have verified successfully -- the very
    // next role (Gemm) is the first to fail on its ProofOnlyV1 stub, proving
    // Bank's real dispatch actually ran rather than being short-circuited.
    BOOST_CHECK_MESSAGE(
        why.find("coupled:gemm:recursive_decode") != std::string::npos, why);

    // Tampering the bank engine receipt now surfaces a bank-specific failure
    // before the verifier ever reaches Gemm's stub engine.
    auto tampered_proof = proof;
    auto tampered_bank = DecodeAt(tampered_proof, 0);
    tampered_bank.engine_receipt.back() ^= 0x01;
    ReplaceAt(tampered_proof, 0, tampered_bank);
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRelations(tampered_proof, &why));
    // Either our engine prefix or the underlying Split-RAP verify note is fine;
    // the hard requirement is that Gemm's stub path is never reached.
    BOOST_CHECK_MESSAGE(
        why.find("bank_dequant_engine") != std::string::npos ||
            why.find("dequant_air") != std::string::npos ||
            why.find("split_rap_verify") != std::string::npos,
        why);
    BOOST_CHECK(why.find("coupled:gemm") == std::string::npos);

    // Tampering the receipt's own trace_root (not the engine payload) trips
    // the trace-root binding check in VerifyProofOnlyEngine.
    auto retampered_proof = proof;
    auto bad_trace = DecodeAt(retampered_proof, 0);
    bad_trace.trace_root = Filled(0xcc);
    ReplaceAt(retampered_proof, 0, bad_trace);
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRelations(retampered_proof, &why));
    BOOST_CHECK_MESSAGE(
        why.find("bank_dequant_engine_trace_root") != std::string::npos, why);
}

rc::RCStage3CoupledShape MakeGemmDotEngineTestShape()
{
    // Same toy geometry as the gemm product suite: 4 barriers × 1 lobe × 1
    // page slot ⇒ 4 scheduled GEMMs, 1 output tile each.
    return MakeBankDequantEngineTestShape();
}

rc::RCStage3SuccinctProof MakeGemmDotEngineStatement(
    const rc::RCStage3CoupledShape& shape)
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Coupled;
    out.public_inputs.height = 700;
    out.public_inputs.n_bits = 0x207fffffU;
    out.public_inputs.coupled_profile = 2;
    out.public_inputs.transcript_version = shape.transcript_version;
    out.public_inputs.header_commitment = Filled(0x11);
    out.public_inputs.params_commitment = Filled(0x22);
    out.public_inputs.target = Filled(0xff);
    out.public_inputs.sigma = Filled(0x33);
    out.public_inputs.coupled_digest = Filled(0x44);
    out.public_inputs.final_digest = Filled(0x44);
    return out;
}

std::vector<rc::RCStage3CoupledGemmDotOpening> MakeHonestGemmDotOpenings(
    const rc::RCStage3CoupledShape& shape, size_t count, int64_t y = 32)
{
    std::vector<rc::RCStage3CoupledGemmDotOpening> out(count);
    const size_t a_len =
        size_t{shape.rows_per_lobe} * shape.lobe_width;
    const size_t b_len =
        size_t{shape.lobe_width} * shape.lobe_width;
    for (auto& opening : out) {
        opening.operand_a.assign(a_len, 1);
        opening.operand_b.assign(b_len, 1);
        opening.output_y.assign(a_len, y);
    }
    return out;
}

BOOST_AUTO_TEST_CASE(coupled_gemm_dot_engine_accepts_honest_witness)
{
    const auto shape = MakeGemmDotEngineTestShape();
    const auto statement = MakeGemmDotEngineStatement(shape);
    const uint256 statement_commitment =
        rc::CommitRCStage3CoupledStatement(statement.public_inputs);
    const uint256 shape_commitment = rc::CommitRCStage3CoupledShape(shape);
    const auto counts = rc::ExpectedRCStage3CoupledRelationCounts(
        rc::RCStage3RelationRole::CoupledGemm, shape);
    BOOST_REQUIRE(counts.has_value());
    const auto openings =
        MakeHonestGemmDotOpenings(shape, counts->primary);

    std::vector<unsigned char> engine_receipt;
    uint256 trace_root;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledGemmDotEngineReceipt(
            statement, shape, openings, engine_receipt, trace_root, &why),
        why);
    BOOST_CHECK(!trace_root.IsNull());
    BOOST_CHECK(!engine_receipt.empty());
    BOOST_CHECK_LE(engine_receipt.size(),
                   rc::kRCStage3CoupledMaxEngineReceiptBytes);

    uint256 verified_trace_root;
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3CoupledGemmDotEngineReceipt(
            shape, statement_commitment, shape_commitment,
            statement.public_inputs.sigma, engine_receipt, verified_trace_root,
            &why),
        why);
    BOOST_CHECK(verified_trace_root == trace_root);

    // Cross-statement / cross-shape / cross-sigma replay rejected.
    uint256 out_root;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledGemmDotEngineReceipt(
        shape, Filled(0x61), shape_commitment, statement.public_inputs.sigma,
        engine_receipt, out_root, &why));
    BOOST_CHECK(!rc::VerifyRCStage3CoupledGemmDotEngineReceipt(
        shape, statement_commitment, Filled(0x62), statement.public_inputs.sigma,
        engine_receipt, out_root, &why));
    BOOST_CHECK(!rc::VerifyRCStage3CoupledGemmDotEngineReceipt(
        shape, statement_commitment, shape_commitment, Filled(0x63),
        engine_receipt, out_root, &why));
}

BOOST_AUTO_TEST_CASE(coupled_gemm_dot_engine_rejects_bad_openings_and_tampering)
{
    const auto shape = MakeGemmDotEngineTestShape();
    const auto statement = MakeGemmDotEngineStatement(shape);
    const uint256 statement_commitment =
        rc::CommitRCStage3CoupledStatement(statement.public_inputs);
    const uint256 shape_commitment = rc::CommitRCStage3CoupledShape(shape);
    const auto counts = rc::ExpectedRCStage3CoupledRelationCounts(
        rc::RCStage3RelationRole::CoupledGemm, shape);
    BOOST_REQUIRE(counts.has_value());
    const auto openings =
        MakeHonestGemmDotOpenings(shape, counts->primary);
    std::string why;

    {
        // Wrong Y sum is rejected at prove time.
        auto bad_sum = MakeHonestGemmDotOpenings(shape, counts->primary, 31);
        std::vector<unsigned char> out;
        uint256 root;
        BOOST_CHECK(!rc::BuildRCStage3CoupledGemmDotEngineReceipt(
            statement, shape, bad_sum, out, root, &why));
    }
    {
        auto too_few = openings;
        too_few.pop_back();
        std::vector<unsigned char> out;
        uint256 root;
        BOOST_CHECK(!rc::BuildRCStage3CoupledGemmDotEngineReceipt(
            statement, shape, too_few, out, root, &why));
    }

    std::vector<unsigned char> engine_receipt;
    uint256 trace_root;
    BOOST_REQUIRE(rc::BuildRCStage3CoupledGemmDotEngineReceipt(
        statement, shape, openings, engine_receipt, trace_root, &why));

    {
        auto tampered = engine_receipt;
        tampered.back() ^= 0x01;
        uint256 out_root;
        BOOST_CHECK(!rc::VerifyRCStage3CoupledGemmDotEngineReceipt(
            shape, statement_commitment, shape_commitment,
            statement.public_inputs.sigma, tampered, out_root, &why));
    }
    {
        auto tampered = engine_receipt;
        tampered[0] ^= 0x01;
        uint256 out_root;
        BOOST_CHECK(!rc::VerifyRCStage3CoupledGemmDotEngineReceipt(
            shape, statement_commitment, shape_commitment,
            statement.public_inputs.sigma, tampered, out_root, &why));
        BOOST_CHECK_MESSAGE(why.find("header") != std::string::npos, why);
    }
    {
        auto padded = engine_receipt;
        padded.push_back(0);
        uint256 out_root;
        BOOST_CHECK(!rc::VerifyRCStage3CoupledGemmDotEngineReceipt(
            shape, statement_commitment, shape_commitment,
            statement.public_inputs.sigma, padded, out_root, &why));
        BOOST_CHECK_MESSAGE(why.find("trailing_bytes") != std::string::npos, why);
    }
}

BOOST_AUTO_TEST_CASE(coupled_gemm_dot_engine_wires_into_full_relation_verifier)
{
    const auto shape = MakeGemmDotEngineTestShape();
    const auto bank_pages = MakeHonestBankDequantWitness(shape);
    const auto gemm_counts = rc::ExpectedRCStage3CoupledRelationCounts(
        rc::RCStage3RelationRole::CoupledGemm, shape);
    BOOST_REQUIRE(gemm_counts.has_value());

    rc::RCStage3SuccinctProof proof;
    proof.statement = rc::RCStage3StatementKind::Coupled;
    auto& public_inputs = proof.public_inputs;
    public_inputs.height = 42;
    public_inputs.n_bits = 0x207fffff;
    public_inputs.coupled_profile = 4;
    public_inputs.transcript_version = shape.transcript_version;
    public_inputs.program_consensus_pin.recursive_alg_hash_root = Filled(0x08);
    public_inputs.program_consensus_pin.external_sha256d_audit_root = Filled(0x09);
    public_inputs.program_consensus_pin.registry_binding = Filled(0x0a);
    public_inputs.header_commitment = Filled(0x11);
    public_inputs.params_commitment = Filled(0x22);
    public_inputs.target = Filled(0x7f);
    public_inputs.sigma = Filled(0x33);
    public_inputs.coupled_digest = Filled(0x44);
    public_inputs.final_digest = Filled(0x55);
    public_inputs.transcript_commitment = Filled(0x66);

    const uint256 statement = rc::CommitRCStage3CoupledStatement(public_inputs);
    const uint256 shape_commitment = rc::CommitRCStage3CoupledShape(shape);

    std::vector<unsigned char> bank_engine_receipt;
    uint256 bank_trace_root;
    std::string build_why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankDequantEngineReceipt(
            shape, statement, shape_commitment, public_inputs.sigma, bank_pages,
            bank_engine_receipt, bank_trace_root, &build_why),
        build_why);

    rc::RCStage3SuccinctProof prove_statement = proof;
    const auto openings =
        MakeHonestGemmDotOpenings(shape, gemm_counts->primary);
    std::vector<unsigned char> gemm_engine_receipt;
    uint256 gemm_trace_root;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledGemmDotEngineReceipt(
            prove_statement, shape, openings, gemm_engine_receipt,
            gemm_trace_root, &build_why),
        build_why);

    uint256 input_root = public_inputs.header_commitment;
    for (size_t i = 0; i < COUPLED_ROLES.size(); ++i) {
        rc::RCStage3CoupledRelationReceipt receipt;
        receipt.role = COUPLED_ROLES[i];
        receipt.shape = shape;
        receipt.statement_commitment = statement;
        receipt.params_commitment = public_inputs.params_commitment;
        receipt.coupled_shape_commitment = shape_commitment;
        receipt.sigma = public_inputs.sigma;
        receipt.input_root = input_root;
        receipt.output_root =
            i + 1 == COUPLED_ROLES.size()
                ? public_inputs.coupled_digest
                : Filled(static_cast<unsigned char>(0x80 + i));
        const auto role_counts =
            rc::ExpectedRCStage3CoupledRelationCounts(receipt.role, shape);
        BOOST_REQUIRE(role_counts.has_value());
        receipt.primary_count = role_counts->primary;
        receipt.secondary_count = role_counts->secondary;

        if (receipt.role == rc::RCStage3RelationRole::CoupledBank) {
            receipt.engine = rc::RCStage3CoupledProofEngine::BankDequantPagesV1;
            receipt.engine_receipt = bank_engine_receipt;
            receipt.trace_root = bank_trace_root;
        } else if (receipt.role == rc::RCStage3RelationRole::CoupledGemm) {
            receipt.engine = rc::RCStage3CoupledProofEngine::GemmDotTilesV1;
            receipt.engine_receipt = gemm_engine_receipt;
            receipt.trace_root = gemm_trace_root;
        } else {
            receipt.trace_root = Filled(static_cast<unsigned char>(0xa0 + i));
            receipt.engine_receipt = {
                static_cast<unsigned char>(i), 0xc3, 0x5a, 0xa5};
        }
        receipt.aggregate_root = rc::CommitRCStage3CoupledRelationAggregate(receipt);

        std::vector<unsigned char> section;
        std::string serialize_why;
        BOOST_REQUIRE_MESSAGE(
            rc::SerializeRCStage3CoupledRelationReceipt(receipt, section,
                                                       &serialize_why),
            "role=" + std::string(rc::RCStage3RelationRoleName(receipt.role)) +
                " engine_bytes=" + std::to_string(receipt.engine_receipt.size()) +
                " why=" + serialize_why);
        proof.commitments.push_back(
            {receipt.role, rc::CommitRCStage3CoupledSection(section)});
        proof.sections.push_back({receipt.role, std::move(section)});
        input_root = receipt.output_root;
    }

    std::string why;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRelations(proof, &why));
    // Bank + Gemm real engines must both have verified -- Exchange is the
    // first remaining ProofOnlyV1 stub to fail.
    BOOST_CHECK_MESSAGE(
        why.find("coupled:exchange:recursive_decode") != std::string::npos, why);

    auto tampered_proof = proof;
    auto tampered_gemm = DecodeAt(tampered_proof, RoleIndex(
        rc::RCStage3RelationRole::CoupledGemm));
    tampered_gemm.engine_receipt.back() ^= 0x01;
    ReplaceAt(tampered_proof,
              RoleIndex(rc::RCStage3RelationRole::CoupledGemm), tampered_gemm);
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRelations(tampered_proof, &why));
    BOOST_CHECK_MESSAGE(
        why.find("gemm_dot_engine") != std::string::npos ||
            why.find("dot_air") != std::string::npos,
        why);
    BOOST_CHECK(why.find("coupled:exchange") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(coupled_bank_page_inclusion_engine_roundtrip_and_mutations)
{
    const auto shape = MakeBankDequantEngineTestShape();
    const auto statement = MakeGemmDotEngineStatement(shape);
    const uint256 sigma = statement.public_inputs.sigma;
    const uint256 statement_commitment =
        rc::CommitRCStage3CoupledStatement(statement.public_inputs);
    const uint256 shape_commitment = rc::CommitRCStage3CoupledShape(shape);

    std::vector<std::vector<int8_t>> pages(shape.bank_pages);
    const uint32_t logical = shape.lobe_width * shape.lobe_width;
    for (uint32_t p = 0; p < shape.bank_pages; ++p) {
        pages[p].resize(logical);
        for (uint32_t cell = 0; cell < logical; ++cell) {
            pages[p][cell] =
                static_cast<int8_t>((static_cast<int>(cell) + static_cast<int>(p) * 3) % 17 - 8);
        }
    }

    std::vector<unsigned char> receipt;
    uint256 trace_root;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankPageInclusionEngineReceipt(
            statement, shape, sigma, pages, receipt, trace_root, &why),
        why);
    BOOST_CHECK(!receipt.empty());
    BOOST_CHECK(!trace_root.IsNull());

    uint256 verified_root;
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3CoupledBankPageInclusionEngineReceipt(
            shape, statement_commitment, shape_commitment, sigma, receipt,
            verified_root, &why),
        why);
    BOOST_CHECK(verified_root == trace_root);

    BOOST_CHECK(!rc::VerifyRCStage3CoupledBankPageInclusionEngineReceipt(
        shape, Filled(0xaa), shape_commitment, sigma, receipt, verified_root, &why));
    BOOST_CHECK(!rc::VerifyRCStage3CoupledBankPageInclusionEngineReceipt(
        shape, statement_commitment, Filled(0xbb), sigma, receipt, verified_root, &why));
    BOOST_CHECK(!rc::VerifyRCStage3CoupledBankPageInclusionEngineReceipt(
        shape, statement_commitment, shape_commitment, Filled(0xcc), receipt,
        verified_root, &why));
    auto bad = receipt;
    bad.back() ^= 0x01;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledBankPageInclusionEngineReceipt(
        shape, statement_commitment, shape_commitment, sigma, bad, verified_root, &why));

    auto wrong_pages = pages;
    wrong_pages[0][0] ^= 1;
    std::vector<unsigned char> wrong_receipt;
    uint256 wrong_root;
    BOOST_REQUIRE(rc::BuildRCStage3CoupledBankPageInclusionEngineReceipt(
        statement, shape, sigma, wrong_pages, wrong_receipt, wrong_root, &why));
    BOOST_CHECK(wrong_root != trace_root);
}

BOOST_AUTO_TEST_CASE(coupled_bank_seed_xof_engine_opt_in_roundtrip)
{
    // Full FlatBoundary packaging for lobe_width=32 is multi-minute; keep the
    // default suite fast. Set BTX_RUN_STAGE3_BANK_SEED_XOF_ENGINE=1 (and
    // MemoryMax≥40G) to exercise the real BankSeedXofV1 prove/verify path.
    // Prototype evidence for Gap clearance remains
    // matmul_v4_rc_stage3_coupled_bank_product_tests.
    if (std::getenv("BTX_RUN_STAGE3_BANK_SEED_XOF_ENGINE") == nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_BANK_SEED_XOF_ENGINE=1 to run BankSeedXofV1 "
            "engine roundtrip");
        return;
    }

    CBlockHeader header;
    header.nVersion = 7;
    header.hashPrevBlock = Filled(0x10);
    header.hashMerkleRoot = Filled(0x20);
    header.nTime = 123456;
    header.nBits = 0x207fffffU;
    header.nNonce = 99;
    header.nNonce64 = 123;
    header.seed_a = Filled(0x30);
    header.seed_b = Filled(0x40);
    header.matmul_digest = Filled(0x50);

    const auto shape = MakeBankDequantEngineTestShape();
    rc::RCStage3SuccinctProof statement;
    statement.statement = rc::RCStage3StatementKind::Coupled;
    statement.public_inputs.height = 700;
    statement.public_inputs.n_bits = header.nBits;
    statement.public_inputs.coupled_profile = 4;
    statement.public_inputs.transcript_version = shape.transcript_version;
    statement.public_inputs.header_commitment = rc::RCStage3HeaderCommitment(header);
    statement.public_inputs.params_commitment = Filled(0x22);
    statement.public_inputs.target = Filled(0xff);
    statement.public_inputs.sigma = Filled(0x33);
    statement.public_inputs.coupled_digest = Filled(0x44);
    statement.public_inputs.final_digest = Filled(0x44);

    std::vector<unsigned char> receipt;
    uint256 trace_root;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankSeedXofEngineReceipt(
            statement, header, shape, receipt, trace_root, &why),
        why);
    BOOST_CHECK(!receipt.empty());
    BOOST_CHECK(receipt.size() <= rc::kRCStage3CoupledMaxEngineReceiptBytes);

    uint256 verified;
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3CoupledBankSeedXofEngineReceipt(
            statement, shape, receipt, verified, &why),
        why);
    BOOST_CHECK(verified == trace_root);
    BOOST_TEST_MESSAGE("BankSeedXofV1 engine_bytes=" << receipt.size());
}

namespace {

rc::RCStage3CoupledShape MakeMixExchangeEngineTestShape()
{
    rc::RCStage3CoupledShape out;
    out.barriers = 4;
    out.lobes = 1;
    out.lobe_width = 32;
    out.bank_pages = 1;
    out.rows_per_lobe = 1;
    out.pages_per_barrier_lobe = 1;
    out.transcript_version = rc::ENC_RC_V4;
    out.full_bank_schedule = true;
    out.material_exchange = true;
    out.exchange_rows = 32;
    out.exchange_rounds = 0;
    return out;
}

rc::RCStage3SuccinctProof MakeMixExchangeEngineStatement(
    const rc::RCStage3CoupledShape& shape)
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Coupled;
    out.public_inputs.height = 811;
    out.public_inputs.n_bits = 0x207fffffU;
    out.public_inputs.coupled_profile = 4;
    out.public_inputs.transcript_version = shape.transcript_version;
    out.public_inputs.header_commitment = Filled(0x11);
    out.public_inputs.params_commitment = Filled(0x22);
    out.public_inputs.target = Filled(0xff);
    out.public_inputs.sigma = Filled(0x33);
    out.public_inputs.coupled_digest = Filled(0x44);
    out.public_inputs.final_digest = Filled(0x44);
    return out;
}

std::vector<int64_t> SaltedValues(uint32_t count, uint64_t salt)
{
    std::vector<int64_t> out(count);
    for (uint32_t i = 0; i < count; ++i) {
        const uint64_t bits =
            (salt << 48) ^ (uint64_t{i} * UINT64_C(0x9e3779b97f4a7c15));
        out[i] = static_cast<int64_t>(bits);
    }
    return out;
}

rc::RCStage3CoupledExchangePermutationOpening MakeExchangePermOpening(
    const rc::RCStage3CoupledShape& shape)
{
    rc::RCStage3CoupledExchangePermutationOpening out;
    const uint32_t lobe_cells = shape.rows_per_lobe * shape.lobe_width;
    const uint32_t state_cells = shape.lobes * lobe_cells;
    for (uint32_t barrier = 0; barrier < shape.barriers; ++barrier) {
        for (uint32_t lobe = 0; lobe < shape.lobes; ++lobe) {
            out.fixed_exchange_inputs.push_back(
                SaltedValues(lobe_cells, 10 + barrier * 3 + lobe));
        }
        for (uint32_t round = 0; round < shape.exchange_rounds; ++round) {
            out.material_exchange_inputs.push_back(
                SaltedValues(state_cells, 40 + barrier * 7 + round));
        }
        out.permutation_inputs.push_back(SaltedValues(state_cells, 80 + barrier));
    }
    return out;
}

std::vector<std::vector<int64_t>> MakeMixInputs(const rc::RCStage3CoupledShape& shape)
{
    const uint32_t state_cells = shape.lobes * shape.rows_per_lobe * shape.lobe_width;
    std::vector<std::vector<int64_t>> out(shape.barriers, std::vector<int64_t>(state_cells));
    for (uint32_t barrier = 0; barrier < shape.barriers; ++barrier) {
        for (uint32_t i = 0; i < state_cells; ++i) {
            out[barrier][i] = int64_t{barrier} * 100 + int64_t{i} - 16;
        }
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(coupled_exchange_permutation_engines_roundtrip)
{
    const auto shape = MakeMixExchangeEngineTestShape();
    const auto statement = MakeMixExchangeEngineStatement(shape);
    const auto opening = MakeExchangePermOpening(shape);
    std::string why;

    std::vector<unsigned char> exchange_receipt;
    uint256 exchange_root;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledExchangeEngineReceipt(
            statement, shape, opening, exchange_receipt, exchange_root, &why),
        why);
    uint256 exchange_verified;
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3CoupledExchangeEngineReceipt(
            statement, shape, exchange_receipt, exchange_verified, &why),
        why);
    BOOST_CHECK(exchange_verified == exchange_root);
    auto bad_ex = exchange_receipt;
    bad_ex.back() ^= 0x01;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledExchangeEngineReceipt(
        statement, shape, bad_ex, exchange_verified, &why));

    std::vector<unsigned char> perm_receipt;
    uint256 perm_root;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledPermutationEngineReceipt(
            statement, shape, opening, perm_receipt, perm_root, &why),
        why);
    uint256 perm_verified;
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3CoupledPermutationEngineReceipt(
            statement, shape, perm_receipt, perm_verified, &why),
        why);
    BOOST_CHECK(perm_verified == perm_root);
    auto bad_perm = perm_receipt;
    bad_perm.back() ^= 0x01;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledPermutationEngineReceipt(
        statement, shape, bad_perm, perm_verified, &why));

    BOOST_TEST_MESSAGE("ExchangeStagesV1 bytes=" << exchange_receipt.size());
    BOOST_TEST_MESSAGE("PermutationStagesV1 bytes=" << perm_receipt.size());
}

BOOST_AUTO_TEST_CASE(coupled_mix_engine_opt_in_roundtrip)
{
    // MixArithmeticV1 prove is ~14min / ~1.2GiB on the toy 4×32 shape
    // (same cost as mix_product_tests::full_seed_and_arithmetic_proofs_*).
    if (std::getenv("BTX_RUN_STAGE3_MIX_ENGINE") == nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_MIX_ENGINE=1 to run MixArithmeticV1 "
            "engine roundtrip under MemoryMax≥40G");
        return;
    }
    const auto shape = MakeMixExchangeEngineTestShape();
    const auto statement = MakeMixExchangeEngineStatement(shape);
    const auto mix_inputs = MakeMixInputs(shape);
    std::string why;
    std::vector<unsigned char> mix_receipt;
    uint256 mix_root;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledMixEngineReceipt(
            statement, shape, mix_inputs, mix_receipt, mix_root, &why),
        why);
    uint256 mix_verified;
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3CoupledMixEngineReceipt(
            statement, shape, mix_receipt, mix_verified, &why),
        why);
    BOOST_CHECK(mix_verified == mix_root);
    auto bad_mix = mix_receipt;
    bad_mix.back() ^= 0x01;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledMixEngineReceipt(
        statement, shape, bad_mix, mix_verified, &why));
    BOOST_TEST_MESSAGE("MixArithmeticV1 bytes=" << mix_receipt.size());
}

BOOST_AUTO_TEST_SUITE_END()

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_p2_consumer_bridge.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_recursive_parent.h>

#include <hash.h>

#include <algorithm>

namespace matmul::v4::rc::stage3_multirow_v11_recursive_parent {
namespace {

uint256 H(uint32_t tag)
{
    HashWriter hash;
    hash << uint64_t{0x31545345'54525056ULL};
    hash << tag;
    return hash.GetHash();
}

aq::AirConstraintSystem<gf::Fp3> ZeroAir()
{
    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = 256;
    cs.n_columns = 2;
    cs.constraints.push_back({
        "zero_relation",
        aq::AirKind::kEverywhere,
        1,
        [](const auto&, const auto&) {
            return gf::Fp3::Zero();
        }});
    return cs;
}

std::vector<std::vector<gf::Fp3>> ZeroTrace(
    const aq::AirConstraintSystem<gf::Fp3>& cs)
{
    return std::vector<std::vector<gf::Fp3>>(
        cs.n_columns,
        std::vector<gf::Fp3>(
            cs.n_rows, gf::Fp3::Zero()));
}

tp::StatementV1 StatementFromProof(
    const backend::ProofV1& proof)
{
    const auto& envelope = proof.envelope;
    const auto& split = envelope.split;
    const auto& batch = split.batch;
    tp::StatementV1 out;
    for (uint32_t word = 0;
         word < envelope.public_fs_seed.size(); ++word) {
        for (uint32_t byte = 0; byte < 4; ++byte) {
            out.public_fs_seed.data()[4 * word + byte] =
                static_cast<unsigned char>(
                    envelope.public_fs_seed[word] >>
                    (8 * byte));
        }
    }
    out.pow_grind_nonce = batch.pow_grind_nonce;
    out.trace_rows = split.trace_rows;
    out.trace_columns = envelope.trace_columns;
    out.quotient_len = envelope.quotient_len;
    out.n_coeffs = batch.n_coeffs;
    out.blowup = batch.blowup;
    out.base_column_indices = split.base_column_indices;
    BOOST_REQUIRE_EQUAL(batch.groups.size(), out.groups.size());
    for (uint32_t group = 0; group < out.groups.size(); ++group) {
        out.groups[group] = {
            batch.groups[group].role,
            batch.groups[group].first_column,
            batch.groups[group].column_count,
            batch.groups[group].row_commit.n_leaves,
            batch.groups[group].row_commit.root,
        };
    }
    out.column_len = batch.column_len;
    out.evals_z1 = batch.evals_z1;
    out.evals_z2 = batch.evals_z2;
    for (const auto& fold : batch.fold_layers) {
        out.folds.push_back(
            {fold.n_leaves, fold.root});
    }
    out.final_value = batch.final_value;
    return out;
}

struct Material {
    ChildInputV1 child;
    tp::ReceiptV1 transcript;
};

Material MaterialFromProof(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<uint32_t>& base_indices,
    const backend::ProofV1& proof,
    uint32_t role,
    uint32_t tag)
{
    Material out;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        backend::VerifyV1(
            proof, &out.transcript, &why),
        why);
    std::vector<uint32_t> words;
    BOOST_REQUIRE_MESSAGE(
        abi::EncodeCanonicalV1(
            proof.envelope, words, nullptr, &why),
        why);
    const auto decoded =
        abi::DecodeCanonicalV1(words, &why);
    BOOST_REQUIRE_MESSAGE(decoded.has_value(), why);
    const auto statement = StatementFromProof(proof);
    const auto replay =
        tp::BuildProductV1(statement);
    BOOST_REQUIRE_MESSAGE(replay.valid, replay.note);
    const auto consumer =
        stage3_multirow_p2_consumer_bridge::BuildProductV1(
            replay);
    BOOST_REQUIRE_MESSAGE(consumer.valid, consumer.note);
    std::vector<abi::ParentPublicCellV1> parent_public;
    uint32_t parent_column = 1000;
    for (const auto& source : decoded->sources) {
        if (source.ownership ==
            abi::OwnershipClassV1::PublicStatement) {
            parent_public.push_back({
                source.key, parent_column++, source.value});
        }
    }
    auto parent_join = pj::BuildProductV1(
        *decoded, parent_public, replay, consumer);
    BOOST_REQUIRE_MESSAGE(
        parent_join.valid, parent_join.note);
    auto shard = mf::BuildShardV1(
        *decoded, out.transcript, 0, 1);
    BOOST_REQUIRE_MESSAGE(shard.valid, shard.note);
    out.child.statement.role = role;
    out.child.statement.program_root = H(100 + tag);
    out.child.statement.application_statement_root =
        H(200 + tag);
    out.child.statement.public_fs_seed =
        statement.public_fs_seed;
    out.child.cs = cs;
    out.child.base_column_indices = base_indices;
    out.child.proof = proof;
    out.child.parent_join = std::move(parent_join);
    out.child.merkle_fold_shards.push_back(
        std::move(shard));
    return out;
}

struct Fixture {
    std::array<ChildInputV1, kRecursiveParentArityV1> children;
    ProductV1 product;
};

Fixture BuildFixture()
{
    Fixture out;
    const auto cs = ZeroAir();
    const uint256 seed = H(1);
    const auto proved = backend::ProveAirQuotientV1(
        cs, ZeroTrace(cs), {0}, seed);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.proximity.ok);
    auto first = MaterialFromProof(
        cs, {0}, proved.proximity.proof, 1, 1);
    auto second = MaterialFromProof(
        cs, {0}, proved.proximity.proof, 2, 2);
    out.children[0] = std::move(first.child);
    out.children[1] = std::move(second.child);
    out.product = BuildProductV1(out.children);
    return out;
}

const Fixture& Honest()
{
    static const Fixture fixture = BuildFixture();
    return fixture;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_recursive_parent_tests)

BOOST_AUTO_TEST_CASE(
    exact_arity_two_constant_width_parent_proves_and_roundtrips)
{
    const auto& fixture = Honest();
    const auto& product = fixture.product;
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    BOOST_CHECK_EQUAL(
        product.layout.n_columns, 74U);
    BOOST_CHECK_EQUAL(
        product.acceptance_cs.n_rows,
        kRecursiveParentTraceRowsV1);
    BOOST_CHECK_EQUAL(
        product.width_slope_per_child_proof_column, 0U);
    BOOST_CHECK_EQUAL(product.native_children_verified, 2U);
    BOOST_CHECK_EQUAL(
        product.published_parent_joins_consumed, 2U);
    BOOST_CHECK_EQUAL(
        product.published_merkle_fold_products_consumed, 2U);
    BOOST_CHECK(product.exact_arity_and_order);
    BOOST_CHECK(product.role_program_statement_seed_bound);
    BOOST_CHECK(product.proof_abi_roots_recomputed);
    BOOST_CHECK(product.child_proof_payloads_native_verified);
    BOOST_CHECK(product.parent_join_roots_recomputed);
    BOOST_CHECK(product.merkle_fold_roots_recomputed);
    BOOST_CHECK(product.acceptance_rows_root_pinned);
    BOOST_CHECK(product.constant_width_acceptance);
    BOOST_CHECK(product.parent_own_v11_proof_executed);
    BOOST_CHECK(product.parent_own_v11_proof_verified);
    BOOST_CHECK(product.level_two_native_reentry_supported);
    BOOST_CHECK(!product.child_verifier_executed_in_parent_air);
    BOOST_CHECK(!product.canonical_recursive_verifier_executable);
    BOOST_CHECK(!product.recursive_authority_ready);
    BOOST_TEST_MESSAGE(
        "v11 recursive-parent foundation: rows="
        << product.acceptance_cs.n_rows
        << " columns=" << product.layout.n_columns
        << " width_slope="
        << product.width_slope_per_child_proof_column
        << " parent_proof_bytes="
        << product.parent_proof_bytes
        << " receipt_bytes=" << product.encoded_bytes
        << " parent_prove_us="
        << product.parent_prove_micros
        << " parent_verify_us="
        << product.parent_verify_micros
        << " residual_mask=0x" << std::hex
        << product.residual_mask << std::dec);
    BOOST_CHECK_NE(product.residual_mask, 0U);
    BOOST_CHECK(
        product.residual_mask &
        kResidualSameParentDecoderJoin);
    BOOST_CHECK(
        product.residual_mask &
        kResidualDeepQuotientChip);
    BOOST_CHECK(
        product.residual_mask &
        kResidualCanonicalConstraintVm);
    BOOST_CHECK(
        product.residual_mask &
        kResidualRecursiveV11Verifier);
    BOOST_CHECK(
        product.residual_mask &
        kResidualFullShardMaterialization);

    std::string why;
    BOOST_REQUIRE_MESSAGE(
        VerifyReceiptV1(
            fixture.children, product.receipt, &why),
        why);
    std::vector<unsigned char> wire;
    const size_t bytes =
        SerializeReceiptV1(product.receipt, wire);
    BOOST_REQUIRE_EQUAL(bytes, wire.size());
    BOOST_CHECK_LE(bytes, kMaxReceiptBytesV1);
    const auto decoded =
        DeserializeReceiptV1(wire, &why);
    BOOST_REQUIRE_MESSAGE(decoded.has_value(), why);
    BOOST_CHECK_EQUAL(
        decoded->receipt_root.GetHex(),
        product.receipt.receipt_root.GetHex());

    const auto readiness = CurrentReadinessV1();
    BOOST_CHECK(
        readiness.real_child_v11_native_verification_executable);
    BOOST_CHECK(
        readiness.constant_width_root_pinned_acceptance_executable);
    BOOST_CHECK(readiness.parent_own_v11_proof_executable);
    BOOST_CHECK(readiness.level_two_native_reentry_executable);
    BOOST_CHECK(
        !readiness.same_parent_decoder_deep_vm_executable);
    BOOST_CHECK(!readiness.recursive_authority_ready);
}

BOOST_AUTO_TEST_CASE(
    child_swap_role_program_seed_root_and_payload_attacks_reject)
{
    const auto& fixture = Honest();
    std::string why;

    auto swapped = fixture.children;
    std::swap(swapped[0], swapped[1]);
    BOOST_CHECK(!VerifyReceiptV1(
        swapped, fixture.product.receipt, &why));

    auto role = fixture.children;
    role[0].statement.role ^= 1U;
    BOOST_CHECK(!VerifyReceiptV1(
        role, fixture.product.receipt, &why));

    auto program = fixture.children;
    program[0].statement.program_root = H(900);
    BOOST_CHECK(!VerifyReceiptV1(
        program, fixture.product.receipt, &why));

    auto seed = fixture.children;
    seed[0].statement.public_fs_seed = H(901);
    BOOST_CHECK(!VerifyReceiptV1(
        seed, fixture.product.receipt, &why));

    auto root = fixture.children;
    root[0].proof.envelope.split.batch.groups[0]
        .row_commit.root[0] ^= 1U;
    BOOST_CHECK(!VerifyReceiptV1(
        root, fixture.product.receipt, &why));

    auto payload = fixture.children;
    payload[0].proof.envelope.split.batch.queries[0]
        .group_rows[0].values[0].c0 ^= 1U;
    BOOST_CHECK(!VerifyReceiptV1(
        payload, fixture.product.receipt, &why));
}

BOOST_AUTO_TEST_CASE(
    omitted_duplicate_parent_proof_and_codec_payload_attacks_reject)
{
    const auto& fixture = Honest();
    std::string why;

    std::vector<unsigned char> wire;
    BOOST_REQUIRE(
        SerializeReceiptV1(
            fixture.product.receipt, wire) != 0);
    auto omitted = wire;
    omitted.pop_back();
    BOOST_CHECK(!DeserializeReceiptV1(
        omitted, &why).has_value());

    auto duplicated = fixture.product.receipt;
    duplicated.children[1] = duplicated.children[0];
    duplicated.children[1].ordinal = 1;
    duplicated.children[1].child_statement_root =
        ComputeChildStatementRootV1(
            duplicated.children[1]);
    duplicated.parent_application_statement_root = H(902);
    duplicated.receipt_root =
        ComputeParentReceiptRootV1(duplicated);
    BOOST_CHECK(!VerifyReceiptV1(
        fixture.children, duplicated, &why));

    auto parent_proof = fixture.product.receipt;
    parent_proof.parent_proof.envelope.split.batch.queries[0]
        .group_rows[0].values[0].c1 ^= 1U;
    parent_proof.parent_proof_root = H(903);
    parent_proof.receipt_root =
        ComputeParentReceiptRootV1(parent_proof);
    BOOST_CHECK(!VerifyReceiptV1(
        fixture.children, parent_proof, &why));

    auto codec_payload = wire;
    BOOST_REQUIRE_GT(codec_payload.size(), 128U);
    codec_payload[codec_payload.size() - 40] ^= 1U;
    BOOST_CHECK(!DeserializeReceiptV1(
        codec_payload, &why).has_value());

    auto trailing = wire;
    trailing.push_back(0);
    BOOST_CHECK(!DeserializeReceiptV1(
        trailing, &why).has_value());
}

BOOST_AUTO_TEST_CASE(
    level_one_parent_own_v11_proof_reenters_as_level_two_child)
{
    const auto& fixture = Honest();
    const auto& level_one = fixture.product;
    auto material = MaterialFromProof(
        level_one.parent_proof_cs,
        level_one.parent_base_column_indices,
        level_one.receipt.parent_proof,
        13, 13);
    std::array<ChildInputV1, kRecursiveParentArityV1>
        level_two_children{
            std::move(material.child),
            fixture.children[0],
        };
    const auto level_two =
        BuildProductV1(level_two_children);
    BOOST_REQUIRE_MESSAGE(level_two.valid, level_two.note);
    BOOST_CHECK(level_two.parent_own_v11_proof_verified);
    BOOST_CHECK_EQUAL(
        level_two.layout.n_columns,
        level_one.layout.n_columns);
    BOOST_CHECK_EQUAL(
        level_two.width_slope_per_child_proof_column, 0U);
    std::string why;
    BOOST_CHECK_MESSAGE(
        VerifyReceiptV1(
            level_two_children, level_two.receipt, &why),
        why);
    BOOST_CHECK(!level_two.recursive_authority_ready);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v11_recursive_parent

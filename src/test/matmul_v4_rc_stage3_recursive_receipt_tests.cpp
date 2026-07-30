// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_recursive_receipt.h>

#include <algorithm>
#include <cstdlib>

namespace aq = matmul::v4::rc::air_quotient;
namespace fp =
    matmul::v4::rc::recursive_fixedpoint;
namespace gf = matmul::v4::rc::gkr_field;
namespace rr =
    matmul::v4::rc::recursive_receipt;
namespace rc = matmul::v4::rc;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_recursive_receipt_tests)

namespace {

uint256 Seed(unsigned char byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

struct SyntheticAttachedShard {
    fp::FoldBusComposition composition;
    fp::BytecodeInterpreterAttachment interpreter;
};

SyntheticAttachedShard BuildSyntheticAttachedShardWithTerminals(
    const std::vector<uint32_t>& query_indices,
    const std::vector<gf::Fp3>& local_q)
{
    SyntheticAttachedShard out;
    if (query_indices.empty() ||
        query_indices.size() != local_q.size()) {
        return out;
    }
    uint32_t rows = 8;
    while (rows < query_indices.size()) rows <<= 1;
    const fp::BytecodeBusLayout bus(0);
    out.composition.combined.n_rows = rows;
    out.composition.combined.n_columns = bus.End();
    out.composition.combined.preprocessed_pin_ood = true;
    out.composition.columns.assign(
        bus.End(),
        std::vector<gf::Fp3>(
            rows, gf::Fp3::Zero()));

    // Canonical quotient rows, in inherited child-query order.
    out.composition.hash.program.public_inputs.query_index =
        query_indices;
    for (uint32_t query = 0;
         query < query_indices.size(); ++query) {
        out.composition.columns[
            bus.RowKind(8)][query] =
            gf::Fp3::One();
        out.composition.columns[
            bus.Value(3)][query] =
            local_q[query];
    }
    out.composition.combined.preprocessed.emplace_back(
        bus.RowKind(8),
        out.composition.columns[bus.RowKind(8)]);

    out.interpreter.layout = bus;
    out.interpreter.program_table.programs.resize(2);
    out.interpreter.program_commitment = Seed(0x41);
    out.interpreter.prechallenge_commitment = Seed(0x42);
    out.interpreter.quotient_rows =
        static_cast<uint32_t>(query_indices.size());
    out.interpreter.quotient_opening_equality = true;
    out.interpreter.valid = true;
    out.composition.valid = true;
    return out;
}

SyntheticAttachedShard BuildSyntheticAttachedShard()
{
    return BuildSyntheticAttachedShardWithTerminals(
        {3U, 11U},
        {gf::Fp3{17, 19, 23},
         gf::Fp3{29, 31, 37}});
}

struct AuthenticatedParent {
    aq::AirConstraintSystem<gf::Fp3> constraint_system;
    fp::AlgAirProof proof;
    uint256 fs_seed{};
    fp::FoldBusComposition composition;
    uint32_t current_width{1};
    std::vector<gf::Fp3> quotient;
};

AuthenticatedParent BuildAuthenticatedParent()
{
    AuthenticatedParent out;
    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = 2;
    cs.n_columns = out.current_width;
    aq::AirConstraint<gf::Fp3> boolean;
    boolean.name =
        "stage3.receipt.test.authenticated_parent";
    boolean.kind = aq::AirKind::kEverywhere;
    boolean.alg_degree = 2;
    boolean.eval =
        [](const std::vector<gf::Fp3>& cur,
           const std::vector<gf::Fp3>&) {
            return gf::Mul(
                cur[0],
                gf::Sub(cur[0], gf::Fp3::One()));
        };
    cs.constraints.push_back(std::move(boolean));
    std::vector<std::vector<gf::Fp3>> columns{
        {gf::Fp3::Zero(), gf::Fp3::One()}};
    out.fs_seed = Seed(0x67);
    const auto proved =
        aq::AirQuotientProve<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            cs, columns, out.fs_seed, {});
    BOOST_REQUIRE_MESSAGE(
        proved.ok && proved.division_exact,
        proved.note);
    out.constraint_system = cs;
    out.proof = proved.proof;
    out.composition =
        fp::BuildFoldBusComposition(
            out.constraint_system, out.proof,
            out.fs_seed);
    BOOST_REQUIRE_MESSAGE(
        out.composition.valid,
        out.composition.note);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        fp::ExtractAuthenticatedParentQuotientOpenings(
            out.composition, out.current_width,
            out.quotient, &why),
        why);
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    l1_receipt_binds_public_q_terminals_and_round_trips)
{
    auto fixture = BuildSyntheticAttachedShard();
    const rr::ShardTerminalBindingV1 binding =
        rr::BindShardLocalQuotientTerminalsV1(
            fixture.composition,
            fixture.interpreter,
            /*shard_index=*/0);
    BOOST_REQUIRE_MESSAGE(binding.valid, binding.note);
    BOOST_CHECK(binding.canonical_quotient_rows);
    BOOST_CHECK(binding.expected_q_preprocessed);
    BOOST_CHECK(binding.query_indices_preprocessed);
    BOOST_CHECK(binding.q_terminal_equality_constrained);
    BOOST_CHECK_EQUAL(binding.queries, 2U);
    BOOST_CHECK_EQUAL(
        fixture.composition.combined.n_columns,
        binding.original_columns + 2);

    const rr::ShardReceiptProveResultV1 proved =
        rr::ProveShardReceiptV1(
            fixture.composition, binding);
    BOOST_REQUIRE_MESSAGE(proved.valid, proved.note);
    BOOST_CHECK(proved.terminal_binding_valid);
    BOOST_CHECK(proved.proof_retained);
    BOOST_CHECK(proved.proved);
    BOOST_CHECK(proved.verified);
    BOOST_CHECK(proved.canonical_codec_round_trip);
    BOOST_CHECK(proved.wire_fits);
    BOOST_CHECK(proved.forgery_rejected);
    BOOST_CHECK_LE(
        proved.encoded_bytes,
        uint64_t{rc::kRCStage3MaxProofBytes});

    std::string why;
    BOOST_CHECK_MESSAGE(
        rr::VerifyShardReceiptV1(
            fixture.composition.combined,
            binding, proved.receipt, &why),
        why);
    const rr::ShardReceiptOwnershipAuditV1 audit =
        rr::AssessShardReceiptOwnershipV1(
            fixture.composition.combined,
            binding, proved.receipt);
    BOOST_REQUIRE_MESSAGE(audit.valid, audit.note);
    BOOST_CHECK(audit.canonical_receipt);
    BOOST_CHECK(audit.native_child_proof_verified);
    BOOST_CHECK(audit.local_q_public_statement_bound);
    BOOST_CHECK(audit.program_and_query_identity_bound);
    BOOST_CHECK(audit.receipt_root_recomputed);
    BOOST_CHECK(audit.wire_fits);
    BOOST_CHECK(!audit.recursively_consumed_by_parent);
    BOOST_REQUIRE_EQUAL(audit.residuals.size(), 1U);

    std::vector<unsigned char> bytes;
    BOOST_REQUIRE_MESSAGE(
        rr::SerializeShardReceiptV1(
            proved.receipt, bytes, &why),
        why);
    const auto decoded =
        rr::DeserializeShardReceiptV1(bytes, &why);
    BOOST_REQUIRE_MESSAGE(decoded.has_value(), why);
    BOOST_CHECK(
        decoded->receipt_root ==
        proved.receipt.receipt_root);
    BOOST_CHECK(
        decoded->proof_bytes ==
        proved.receipt.proof_bytes);

    // Canonical parser and statement binding reject all independently.
    auto trailing = bytes;
    trailing.push_back(0);
    BOOST_CHECK(
        !rr::DeserializeShardReceiptV1(
            trailing, nullptr).has_value());

    auto q_tamper = proved.receipt;
    q_tamper.local_q_per_query[0] =
        gf::Add(
            q_tamper.local_q_per_query[0],
            gf::Fp3::One());
    q_tamper.receipt_root =
        rr::ComputeShardReceiptRootV1(q_tamper);
    BOOST_CHECK(!rr::VerifyShardReceiptV1(
        fixture.composition.combined,
        binding, q_tamper, nullptr));

    auto query_tamper = proved.receipt;
    std::swap(
        query_tamper.query_indices[0],
        query_tamper.query_indices[1]);
    query_tamper.receipt_root =
        rr::ComputeShardReceiptRootV1(query_tamper);
    BOOST_CHECK(!rr::VerifyShardReceiptV1(
        fixture.composition.combined,
        binding, query_tamper, nullptr));

    auto shard_tamper = proved.receipt;
    ++shard_tamper.shard_index;
    shard_tamper.receipt_root =
        rr::ComputeShardReceiptRootV1(shard_tamper);
    BOOST_CHECK(!rr::VerifyShardReceiptV1(
        fixture.composition.combined,
        binding, shard_tamper, nullptr));

    auto seed_tamper = proved.receipt;
    seed_tamper.fs_seed.data()[0] ^= 1;
    seed_tamper.receipt_root =
        rr::ComputeShardReceiptRootV1(seed_tamper);
    BOOST_CHECK(!rr::VerifyShardReceiptV1(
        fixture.composition.combined,
        binding, seed_tamper, nullptr));

    auto proof_tamper = proved.receipt;
    proof_tamper.proof_bytes[
        proof_tamper.proof_bytes.size() / 2] ^= 1;
    proof_tamper.receipt_root =
        rr::ComputeShardReceiptRootV1(proof_tamper);
    BOOST_CHECK(!rr::VerifyShardReceiptV1(
        fixture.composition.combined,
        binding, proof_tamper, nullptr));

    BOOST_TEST_MESSAGE(proved.note);
    static_assert(rr::kShardReceiptExecutableV1);
    static_assert(
        !rr::kShardReceiptRecursiveOwnershipReadyV1);
}

BOOST_AUTO_TEST_CASE(
    q_sum_mirror_pins_operands_and_receipts_reject_substitution)
{
    constexpr uint32_t kQueries = 4;
    std::vector<std::vector<gf::Fp3>> shards(
        2, std::vector<gf::Fp3>(
               kQueries, gf::Fp3::Zero()));
    std::vector<gf::Fp3> parent(
        kQueries, gf::Fp3::Zero());
    for (uint32_t query = 0; query < kQueries; ++query) {
        shards[0][query] =
            gf::Fp3::FromFp(100 + query);
        shards[1][query] =
            gf::Fp3::FromFp(200 + query);
        parent[query] =
            gf::Add(
                shards[0][query],
                shards[1][query]);
    }
    const auto honest =
        fp::AirMirrorNarrowBytecodeShardLocalQuotientsV1(
            parent, shards, true);
    BOOST_REQUIRE_MESSAGE(honest.valid, honest.note);
    BOOST_CHECK(honest.operands_preprocessed);
    BOOST_CHECK(honest.compensated_forgery_rejected);

    // A separately reconstructed statement may legitimately describe
    // different operands that preserve the sum. The mirror's internal
    // compensated-forgery check above proves those values cannot be used
    // under the ORIGINAL verifier-owned preprocessed columns.
    const gf::Fp3 delta{7, 11, 13};
    shards[0][0] = gf::Add(shards[0][0], delta);
    shards[1][0] = gf::Sub(shards[1][0], delta);
    const auto compensated =
        fp::AirMirrorNarrowBytecodeShardLocalQuotientsV1(
            parent, shards, true);
    BOOST_REQUIRE_MESSAGE(
        compensated.valid, compensated.note);
    BOOST_CHECK(compensated.operands_preprocessed);
    BOOST_CHECK(compensated.compensated_forgery_rejected);

    // A proof-owned receipt does not permit the same substitution without
    // changing its public statement and re-proving the L1 shard.
    auto fixture = BuildSyntheticAttachedShard();
    const auto binding =
        rr::BindShardLocalQuotientTerminalsV1(
            fixture.composition,
            fixture.interpreter, 0);
    BOOST_REQUIRE_MESSAGE(binding.valid, binding.note);
    const auto proved =
        rr::ProveShardReceiptV1(
            fixture.composition, binding);
    BOOST_REQUIRE_MESSAGE(proved.valid, proved.note);
    auto compensated_receipt = proved.receipt;
    compensated_receipt.local_q_per_query[0] =
        gf::Add(
            compensated_receipt.local_q_per_query[0],
            delta);
    compensated_receipt.receipt_root =
        rr::ComputeShardReceiptRootV1(
            compensated_receipt);
    BOOST_CHECK(!rr::VerifyShardReceiptV1(
        fixture.composition.combined,
        binding, compensated_receipt, nullptr));

    BOOST_TEST_MESSAGE(
        "q_join_operands_preprocessed=1;"
        "same_statement_compensated_reject=1;"
        "proof_owned_receipt_substitution_reject=1;"
        "l2_recursive_consumption_open=1");
    static_assert(
        !fp::kNarrowBytecodeShardQuotientJoinReady);
    static_assert(
        !rr::kShardReceiptRecursiveOwnershipReadyV1);
}

BOOST_AUTO_TEST_CASE(
    ordered_receipts_feed_real_l2_fri_consumer_fail_closed)
{
    auto first = BuildSyntheticAttachedShard();
    auto second = BuildSyntheticAttachedShard();
    // Real sliced bytecode shards commit different program/value material.
    // Their bytecode prechallenges are independently bound, not equal.
    second.interpreter.prechallenge_commitment =
        Seed(0x43);
    const auto first_binding =
        rr::BindShardLocalQuotientTerminalsV1(
            first.composition, first.interpreter,
            /*shard_index=*/4);
    const auto second_binding =
        rr::BindShardLocalQuotientTerminalsV1(
            second.composition, second.interpreter,
            /*shard_index=*/9);
    BOOST_REQUIRE_MESSAGE(
        first_binding.valid, first_binding.note);
    BOOST_REQUIRE_MESSAGE(
        second_binding.valid, second_binding.note);

    const auto first_proved =
        rr::ProveShardReceiptV1(
            first.composition, first_binding);
    const auto second_proved =
        rr::ProveShardReceiptV1(
            second.composition, second_binding);
    BOOST_REQUIRE_MESSAGE(
        first_proved.valid, first_proved.note);
    BOOST_REQUIRE_MESSAGE(
        second_proved.valid, second_proved.note);
    BOOST_REQUIRE(
        first_proved.receipt.receipt_root !=
        second_proved.receipt.receipt_root);
    BOOST_REQUIRE(
        first_proved.receipt
            .bytecode_prechallenge_commitment !=
        second_proved.receipt
            .bytecode_prechallenge_commitment);

    const std::vector<aq::AirConstraintSystem<gf::Fp3>>
        child_css{
            first.composition.combined,
            second.composition.combined};
    const std::vector<rr::ShardTerminalBindingV1>
        bindings{first_binding, second_binding};
    const std::vector<rr::ShardReceiptV1> receipts{
        first_proved.receipt, second_proved.receipt};
    const uint256 set_root =
        rr::ComputeOrderedShardReceiptSetRootV1(
            receipts);
    BOOST_REQUIRE(!set_root.IsNull());

    const auto consumed =
        rr::ConsumeShardReceiptsL2V1(
            child_css, bindings, receipts,
            /*prove=*/false);
    // Shape-only construction is useful evidence, but is not cryptographic
    // recursive consumption until the parent proof is produced and verified.
    BOOST_CHECK(!consumed.valid);
    BOOST_CHECK(consumed.receipts_verified);
    BOOST_CHECK(consumed.canonical_shard_order);
    BOOST_CHECK(consumed.unique_receipt_roots);
    BOOST_CHECK(consumed.common_query_schedule);
    BOOST_CHECK(consumed.child_prechallenges_bound);
    BOOST_CHECK(consumed.child_proofs_decoded);
    BOOST_CHECK(
        !consumed.child_proofs_cryptographically_consumed);
    BOOST_CHECK(
        consumed.local_q_cells_child_air_bound);
    BOOST_CHECK(consumed.reordered_receipts_rejected);
    BOOST_CHECK(
        consumed.ordered_receipt_set_root == set_root);
    BOOST_CHECK(
        consumed.ordered_receipt_root_parent_air_bound);
    BOOST_CHECK(consumed.ordered_root_pin.valid);
    BOOST_CHECK(
        consumed.ordered_root_pin.equality_constrained);
    BOOST_CHECK(consumed.ordered_root_pin.proved);
    BOOST_CHECK(consumed.ordered_root_pin.verified);
    BOOST_CHECK(
        consumed.ordered_root_pin.forgery_rejected);
    BOOST_CHECK(
        !consumed
             .full_parent_q_join_recursively_consumed);
    BOOST_REQUIRE_EQUAL(
        consumed.residuals.size(), 1U);
    BOOST_CHECK(consumed.l2.fold_bus_built);
    BOOST_CHECK(consumed.l2.fri_shape_representable);
    BOOST_CHECK(consumed.l2.forgery_rejected);
    BOOST_CHECK(!consumed.l2.proved);

    // Canonical order is load-bearing. Reversing otherwise-valid receipts
    // refuses before the multi-child constructor is reached.
    auto reversed_receipts = receipts;
    auto reversed_bindings = bindings;
    auto reversed_css = child_css;
    std::reverse(
        reversed_receipts.begin(),
        reversed_receipts.end());
    std::reverse(
        reversed_bindings.begin(),
        reversed_bindings.end());
    std::reverse(
        reversed_css.begin(), reversed_css.end());
    BOOST_CHECK(
        rr::ComputeOrderedShardReceiptSetRootV1(
            reversed_receipts).IsNull());
    BOOST_CHECK(
        !rr::ConsumeShardReceiptsL2V1(
             reversed_css, reversed_bindings,
             reversed_receipts,
             /*prove=*/false).valid);

    // A cache entry cannot substitute a different terminal and recompute
    // only its envelope root: native receipt verification refuses it.
    auto tampered_receipts = receipts;
    tampered_receipts[1].local_q_per_query[0] =
        gf::Add(
            tampered_receipts[1]
                .local_q_per_query[0],
            gf::Fp3::One());
    tampered_receipts[1].receipt_root =
        rr::ComputeShardReceiptRootV1(
            tampered_receipts[1]);
    BOOST_CHECK(
        !rr::ConsumeShardReceiptsL2V1(
             child_css, bindings, tampered_receipts,
             /*prove=*/false).valid);
    BOOST_TEST_MESSAGE(consumed.note);
    static_assert(
        rr::kShardReceiptL2ConsumeExecutableV1);
    static_assert(
        !rr::kShardReceiptRecursiveOwnershipReadyV1);
}

BOOST_AUTO_TEST_CASE(
    receipt_owned_q_sum_uses_authenticated_parent_opening)
{
    const AuthenticatedParent parent =
        BuildAuthenticatedParent();
    const auto& query_indices =
        parent.composition.hash.program
            .public_inputs.query_index;
    BOOST_REQUIRE_EQUAL(
        parent.quotient.size(),
        query_indices.size());

    std::vector<gf::Fp3> first_q(
        parent.quotient.size(), gf::Fp3::One());
    std::vector<gf::Fp3> second_q(
        parent.quotient.size(), gf::Fp3::Zero());
    bool second_nonzero = false;
    for (size_t query = 0;
         query < parent.quotient.size(); ++query) {
        second_q[query] =
            gf::Sub(
                parent.quotient[query],
                first_q[query]);
        second_nonzero =
            second_nonzero ||
            !gf::IsZero(second_q[query]);
    }
    if (!second_nonzero) {
        const gf::Fp3 two =
            gf::Fp3::FromFp(gf::FromU64(2));
        std::fill(first_q.begin(), first_q.end(), two);
        for (size_t query = 0;
             query < parent.quotient.size(); ++query) {
            second_q[query] =
                gf::Sub(parent.quotient[query], two);
        }
    }

    auto first =
        BuildSyntheticAttachedShardWithTerminals(
            query_indices, first_q);
    auto second =
        BuildSyntheticAttachedShardWithTerminals(
            query_indices, second_q);
    second.interpreter.program_commitment = Seed(0x51);
    second.interpreter.prechallenge_commitment =
        Seed(0x52);
    const auto first_binding =
        rr::BindShardLocalQuotientTerminalsV1(
            first.composition, first.interpreter,
            /*shard_index=*/1);
    const auto second_binding =
        rr::BindShardLocalQuotientTerminalsV1(
            second.composition, second.interpreter,
            /*shard_index=*/2);
    BOOST_REQUIRE_MESSAGE(
        first_binding.valid, first_binding.note);
    BOOST_REQUIRE_MESSAGE(
        second_binding.valid, second_binding.note);
    const auto first_proved =
        rr::ProveShardReceiptV1(
            first.composition, first_binding);
    const auto second_proved =
        rr::ProveShardReceiptV1(
            second.composition, second_binding);
    BOOST_REQUIRE_MESSAGE(
        first_proved.valid, first_proved.note);
    BOOST_REQUIRE_MESSAGE(
        second_proved.valid, second_proved.note);

    const std::vector<
        aq::AirConstraintSystem<gf::Fp3>> child_css{
        first.composition.combined,
        second.composition.combined};
    const std::vector<rr::ShardTerminalBindingV1>
        bindings{first_binding, second_binding};
    const std::vector<rr::ShardReceiptV1> receipts{
        first_proved.receipt, second_proved.receipt};
    constexpr uint32_t kProgramsTotal = 4;
    const auto joined =
        rr::JoinShardReceiptLocalQuotientsV1(
            parent.composition, parent.current_width,
            kProgramsTotal, child_css, bindings,
            receipts);
    // This bounded path retains and verifies the local join proof, but its
    // normalized parent is deliberately shape-only (prove=false). It must not
    // claim recursive cryptographic consumption.
    BOOST_CHECK(!joined.valid);
    BOOST_CHECK(joined.receipts_verified);
    BOOST_CHECK(joined.canonical_shard_order);
    BOOST_CHECK(joined.common_query_schedule);
    BOOST_CHECK(
        joined.authenticated_parent_q_extracted);
    BOOST_CHECK(joined.program_partition_full);
    BOOST_CHECK(joined.parent_q_absolute);
    BOOST_CHECK(joined.air_join_proved);
    BOOST_CHECK(joined.air_join_verified);
    BOOST_CHECK(joined.air_join_forgery_rejected);
    BOOST_CHECK(
        !joined.recursively_consumed_by_parent);
    BOOST_CHECK(!joined.parent_consume.valid);
    BOOST_CHECK(
        joined.parent_consume.join_air_proof_retained);
    BOOST_CHECK(
        joined.parent_consume.companion_child_built);
    BOOST_CHECK(
        !joined.parent_consume.cryptographically_consumed);
    BOOST_CHECK(
        joined.parent_consume.forgery_rejected);
    BOOST_REQUIRE_EQUAL(joined.residuals.size(), 1U);

    // Coverage is semantic data, not a caller-controlled readiness flag.
    BOOST_CHECK(
        !rr::JoinShardReceiptLocalQuotientsV1(
             parent.composition, parent.current_width,
             kProgramsTotal + 1, child_css, bindings,
             receipts).valid);

    // Changing an authenticated parent quotient cell makes the equality
    // fail, even if a caller leaves the aggregate `valid` bit stale.
    auto forged_parent = parent.composition;
    const fp::HashOpeningLayout hash_layout =
        fp::HashOpeningLayoutAt(
            forged_parent.hash.column_base);
    bool parent_cell_mutated = false;
    for (uint32_t row = 0;
         row < forged_parent.hash.program.active_rows &&
         !parent_cell_mutated; ++row) {
        const auto& meta =
            forged_parent.hash.program.rows[row];
        if (!meta.current_row_sponge) continue;
        for (uint32_t lane = 0;
             lane < matmul::v4::rc::alg_hash::kAlgHashRate;
             ++lane) {
            const uint32_t position =
                meta.current_word_offset + lane;
            if (position / 3U !=
                parent.current_width) {
                continue;
            }
            forged_parent.columns[
                hash_layout.absorbed_pin_base +
                lane][row] =
                gf::Add(
                    forged_parent.columns[
                        hash_layout.absorbed_pin_base +
                        lane][row],
                    gf::Fp3::One());
            parent_cell_mutated = true;
            break;
        }
    }
    BOOST_REQUIRE(parent_cell_mutated);
    BOOST_CHECK(
        !rr::JoinShardReceiptLocalQuotientsV1(
             forged_parent, parent.current_width,
             kProgramsTotal, child_css, bindings,
             receipts).valid);

    auto tampered_receipts = receipts;
    tampered_receipts[0].local_q_per_query[0] =
        gf::Add(
            tampered_receipts[0]
                .local_q_per_query[0],
            gf::Fp3::One());
    tampered_receipts[0].receipt_root =
        rr::ComputeShardReceiptRootV1(
            tampered_receipts[0]);
    BOOST_CHECK(
        !rr::JoinShardReceiptLocalQuotientsV1(
             parent.composition, parent.current_width,
             kProgramsTotal, child_css, bindings,
             tampered_receipts).valid);

    BOOST_TEST_MESSAGE(joined.note);
}

BOOST_AUTO_TEST_CASE(
    ordered_receipt_set_root_parent_air_pin_forgery_rejects)
{
    auto first = BuildSyntheticAttachedShard();
    auto second = BuildSyntheticAttachedShard();
    second.interpreter.prechallenge_commitment =
        Seed(0x44);
    const auto first_binding =
        rr::BindShardLocalQuotientTerminalsV1(
            first.composition, first.interpreter, 2);
    const auto second_binding =
        rr::BindShardLocalQuotientTerminalsV1(
            second.composition, second.interpreter, 5);
    BOOST_REQUIRE(first_binding.valid);
    BOOST_REQUIRE(second_binding.valid);
    const auto first_proved =
        rr::ProveShardReceiptV1(
            first.composition, first_binding);
    const auto second_proved =
        rr::ProveShardReceiptV1(
            second.composition, second_binding);
    BOOST_REQUIRE(first_proved.valid);
    BOOST_REQUIRE(second_proved.valid);
    const std::vector<rr::ShardReceiptV1> receipts{
        first_proved.receipt, second_proved.receipt};
    const uint256 root =
        rr::ComputeOrderedShardReceiptSetRootV1(receipts);
    BOOST_REQUIRE(!root.IsNull());

    const auto pin =
        rr::PinOrderedReceiptSetRootParentAirV1(root);
    BOOST_REQUIRE_MESSAGE(pin.valid, pin.note);
    BOOST_CHECK(pin.public_cells_installed);
    BOOST_CHECK(pin.equality_constrained);
    BOOST_CHECK(pin.proved);
    BOOST_CHECK(pin.verified);
    BOOST_CHECK(pin.forgery_rejected);
    BOOST_CHECK_EQUAL(pin.n_rows, 8U);
    BOOST_CHECK_EQUAL(pin.n_columns, 2U);
    BOOST_CHECK(
        !rr::PinOrderedReceiptSetRootParentAirV1({})
             .valid);
    BOOST_TEST_MESSAGE(pin.note);
    static_assert(
        !rr::kShardReceiptRecursiveOwnershipReadyV1);
}

BOOST_AUTO_TEST_CASE(
    receipt_owned_q_join_normalized_parent_child_consume)
{
    const AuthenticatedParent parent =
        BuildAuthenticatedParent();
    std::vector<gf::Fp3> first_q(
        parent.quotient.size(), gf::Fp3::One());
    std::vector<gf::Fp3> second_q(
        parent.quotient.size(), gf::Fp3::Zero());
    for (size_t query = 0;
         query < parent.quotient.size(); ++query) {
        second_q[query] =
            gf::Sub(
                parent.quotient[query],
                first_q[query]);
    }
    const auto consumed =
        rr::ConsumeReceiptOwnedQuotientJoinAsNormalizedParentChildV1(
            parent.quotient,
            {first_q, second_q},
            /*absolute_parent_bound=*/true,
            /*prove=*/false);
    BOOST_CHECK(!consumed.valid);
    BOOST_CHECK(consumed.join_air_proof_retained);
    BOOST_CHECK(consumed.join_operands_preprocessed);
    BOOST_CHECK(consumed.compensated_forgery_rejected);
    BOOST_CHECK(consumed.companion_child_built);
    BOOST_CHECK(consumed.parent_fold_bus_built);
    BOOST_CHECK(!consumed.cryptographically_consumed);
    BOOST_CHECK(consumed.forgery_rejected);
    BOOST_CHECK(consumed.parent.fri_shape_representable);
    BOOST_CHECK(!consumed.parent.proved);

    // Bound mismatch must refuse retain before parent consume.
    auto bad_bound = parent.quotient;
    bad_bound[0] = gf::Add(bad_bound[0], gf::Fp3::One());
    BOOST_CHECK(
        !rr::ConsumeReceiptOwnedQuotientJoinAsNormalizedParentChildV1(
             bad_bound, {first_q, second_q}, true, false)
             .valid);
    BOOST_TEST_MESSAGE(consumed.note);
    static_assert(
        !rr::kShardReceiptRecursiveOwnershipReadyV1);
}

BOOST_AUTO_TEST_CASE(
    unified_source_receipts_manifest_and_q_join_share_one_l2_parent)
{
    const AuthenticatedParent source =
        BuildAuthenticatedParent();
    const auto& query_indices =
        source.composition.hash.program.public_inputs
            .query_index;
    BOOST_REQUIRE_EQUAL(
        source.quotient.size(), query_indices.size());

    std::vector<gf::Fp3> first_q(
        source.quotient.size(), gf::Fp3::One());
    std::vector<gf::Fp3> second_q(
        source.quotient.size(), gf::Fp3::Zero());
    for (size_t query = 0;
         query < source.quotient.size(); ++query) {
        second_q[query] =
            gf::Sub(source.quotient[query],
                    first_q[query]);
    }

    auto first =
        BuildSyntheticAttachedShardWithTerminals(
            query_indices, first_q);
    auto second =
        BuildSyntheticAttachedShardWithTerminals(
            query_indices, second_q);
    second.interpreter.program_commitment = Seed(0x71);
    second.interpreter.prechallenge_commitment =
        Seed(0x72);
    const auto first_binding =
        rr::BindShardLocalQuotientTerminalsV1(
            first.composition, first.interpreter,
            /*shard_index=*/0);
    const auto second_binding =
        rr::BindShardLocalQuotientTerminalsV1(
            second.composition, second.interpreter,
            /*shard_index=*/1);
    BOOST_REQUIRE_MESSAGE(
        first_binding.valid, first_binding.note);
    BOOST_REQUIRE_MESSAGE(
        second_binding.valid, second_binding.note);
    const auto first_proved =
        rr::ProveShardReceiptV1(
            first.composition, first_binding);
    const auto second_proved =
        rr::ProveShardReceiptV1(
            second.composition, second_binding);
    BOOST_REQUIRE_MESSAGE(
        first_proved.valid, first_proved.note);
    BOOST_REQUIRE_MESSAGE(
        second_proved.valid, second_proved.note);

    const std::vector<
        aq::AirConstraintSystem<gf::Fp3>> child_css{
        first.composition.combined,
        second.composition.combined};
    const std::vector<rr::ShardTerminalBindingV1>
        bindings{first_binding, second_binding};
    const std::vector<rr::ShardReceiptV1> receipts{
        first_proved.receipt, second_proved.receipt};
    const auto manifest =
        matmul::v4::rc::recursive_hierarchy::
            BuildShardOrdinalManifestV2(
                /*total_ordinals=*/4,
                {{0, {0, 2},
                  first_binding.statement_commitment},
                 {1, {1, 3},
                  second_binding.statement_commitment}});
    BOOST_REQUIRE_MESSAGE(
        matmul::v4::rc::recursive_hierarchy::
            ValidateShardOrdinalManifestV2(
                manifest, nullptr),
        "exact-set manifest must be canonical");

    const auto shape =
        rr::ConsumeUnifiedShardReceiptL2ParentV1(
            source.constraint_system,
            source.proof,
            source.fs_seed,
            source.current_width,
            manifest,
            child_css,
            bindings,
            receipts,
            /*prove=*/false);
    BOOST_CHECK(!shape.valid);
    BOOST_CHECK(shape.source_child_verified);
    BOOST_CHECK(shape.receipts_verified);
    BOOST_CHECK(shape.exact_set_manifest_verified);
    BOOST_CHECK(shape.manifest_statement_roots_match);
    BOOST_CHECK(shape.common_query_schedule);
    BOOST_CHECK(shape.q_join_operands_preprocessed);
    BOOST_CHECK(shape.compensated_q_forgery_rejected);
    BOOST_CHECK(
        shape.ownership_context_bound_to_q_join_seed);
    BOOST_CHECK(shape.q_join_child_tamper_rejected);
    BOOST_CHECK(!shape.production_complete);
    BOOST_CHECK(
        !shape.active_p2_transcript_owned_in_same_parent);
    BOOST_CHECK(
        !shape.verifier_reconstructed_constraint_systems);
    BOOST_REQUIRE_EQUAL(shape.residuals.size(), 2U);
    BOOST_TEST_MESSAGE(shape.note);

    // The exact-set root is not an envelope decoration: omission, overlap,
    // statement substitution and receipt reorder all refuse before a parent
    // proof can be accepted.
    auto omitted = manifest;
    omitted.entries[0].program_ordinals.pop_back();
    omitted.commitment =
        matmul::v4::rc::recursive_hierarchy::
            CommitShardOrdinalManifestV2(omitted);
    BOOST_CHECK(
        !rr::ConsumeUnifiedShardReceiptL2ParentV1(
             source.constraint_system, source.proof,
             source.fs_seed, source.current_width,
             omitted, child_css, bindings, receipts,
             /*prove=*/false)
             .valid);

    auto substituted = manifest;
    substituted.entries[1].statement_root =
        first_binding.statement_commitment;
    substituted.commitment =
        matmul::v4::rc::recursive_hierarchy::
            CommitShardOrdinalManifestV2(substituted);
    BOOST_CHECK(
        !rr::ConsumeUnifiedShardReceiptL2ParentV1(
             source.constraint_system, source.proof,
             source.fs_seed, source.current_width,
             substituted, child_css, bindings, receipts,
             /*prove=*/false)
             .valid);

    auto reordered = receipts;
    std::reverse(reordered.begin(), reordered.end());
    BOOST_CHECK(
        !rr::ConsumeUnifiedShardReceiptL2ParentV1(
             source.constraint_system, source.proof,
             source.fs_seed, source.current_width,
             manifest, child_css, bindings, reordered,
             /*prove=*/false)
             .valid);

    auto forged_source = source.proof;
    BOOST_REQUIRE(!forged_source.batch.queries.empty());
    BOOST_REQUIRE(
        !forged_source.batch.queries[0]
             .row.values.empty());
    forged_source.batch.queries[0].row.values[0] =
        gf::Add(
            forged_source.batch.queries[0]
                .row.values[0],
            gf::Fp3::One());
    BOOST_CHECK(
        !rr::ConsumeUnifiedShardReceiptL2ParentV1(
             source.constraint_system, forged_source,
             source.fs_seed, source.current_width,
             manifest, child_css, bindings, receipts,
             /*prove=*/false)
             .valid);

    if (std::getenv(
            "BTX_RUN_G2_UNIFIED_RECEIPT_L2") != nullptr) {
        const auto proved =
            rr::ConsumeUnifiedShardReceiptL2ParentV1(
                source.constraint_system,
                source.proof,
                source.fs_seed,
                source.current_width,
                manifest,
                child_css,
                bindings,
                receipts,
                /*prove=*/true);
        BOOST_REQUIRE_MESSAGE(proved.valid, proved.note);
        BOOST_CHECK(
            proved
                .one_parent_consumes_source_receipts_and_q_join);
        BOOST_CHECK(proved.parent_proof_retained);
        BOOST_CHECK(proved.parent_proof_reentry_verified);
        BOOST_CHECK(proved.parent_proof_tamper_rejected);
        BOOST_CHECK(proved.canonical_whole_parent_codec);
        BOOST_CHECK(proved.within_relay_budget);
        BOOST_CHECK(proved.within_wire_budget);
        BOOST_CHECK_LE(
            proved.parent_proof_bytes,
            uint64_t{rc::kRCStage3MaxProofBytes});
        BOOST_CHECK(!proved.production_complete);
        BOOST_TEST_MESSAGE(proved.note);
    }
}

BOOST_AUTO_TEST_SUITE_END()

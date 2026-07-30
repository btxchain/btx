// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_recursive_receipt_v2.h>

#include <algorithm>

namespace aq = matmul::v4::rc::air_quotient;
namespace cb =
    matmul::v4::rc::constraint_bytecode;
namespace fp =
    matmul::v4::rc::recursive_fixedpoint;
namespace gf = matmul::v4::rc::gkr_field;
namespace rr2 =
    matmul::v4::rc::recursive_receipt_v2;
namespace rc = matmul::v4::rc;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_recursive_receipt_v2_tests)

namespace {

uint256 Seed(unsigned char byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

cb::ProgramTable BooleanProgramTable()
{
    cb::Program program;
    program.role =
        rc::RCStage3RelationRole::
            EpisodeDeterministicBuilder;
    program.constraint_ordinal = 0;
    program.kind = aq::AirKind::kEverywhere;
    program.declared_degree = 2;
    program.current_width = 1;
    program.next_width = 1;
    program.instructions = {
        {cb::Opcode::Current, 0, 0, gf::Fp3::Zero()},
        {cb::Opcode::Constant, 0, 0, gf::Fp3::One()},
        {cb::Opcode::Sub, 0, 1, gf::Fp3::Zero()},
        {cb::Opcode::Mul, 0, 2, gf::Fp3::Zero()},
    };
    cb::ProgramTable table;
    table.role = program.role;
    table.current_width = 1;
    table.next_width = 1;
    table.programs.push_back(program);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(table, &why), why);
    return table;
}

struct SourceFixture {
    aq::AirConstraintSystem<gf::Fp3> cs;
    fp::AlgAirProof proof;
    uint256 seed{};
    fp::FoldBusComposition attached;
    fp::BytecodeInterpreterAttachment interpreter;
};

SourceFixture BuildSourceFixture(unsigned char seed_byte)
{
    SourceFixture out;
    out.cs.n_rows = 2;
    out.cs.n_columns = 1;
    aq::AirConstraint<gf::Fp3> boolean;
    boolean.name =
        "stage3.receipt_v2.test.boolean";
    boolean.kind = aq::AirKind::kEverywhere;
    boolean.alg_degree = 2;
    boolean.eval =
        [](const std::vector<gf::Fp3>& cur,
           const std::vector<gf::Fp3>&) {
            return gf::Mul(
                cur[0],
                gf::Sub(cur[0], gf::Fp3::One()));
        };
    out.cs.constraints.push_back(std::move(boolean));
    const std::vector<std::vector<gf::Fp3>> columns{
        {gf::Fp3::Zero(), gf::Fp3::One()}};
    out.seed = Seed(seed_byte);
    const auto proved =
        aq::AirQuotientProve<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            out.cs, columns, out.seed, {});
    BOOST_REQUIRE_MESSAGE(
        proved.ok && proved.division_exact,
        proved.note);
    out.proof = proved.proof;
    std::string verify_why;
    BOOST_REQUIRE_MESSAGE(
        (aq::AirQuotientVerify<
            gf::Fp3, aq::AirFriBackendAlg<gf::Fp3>>(
            out.cs, out.proof, out.seed,
            &verify_why)),
        verify_why);

    out.attached =
        fp::BuildFoldBusComposition(
            out.cs, out.proof, out.seed);
    BOOST_REQUIRE_MESSAGE(
        out.attached.valid, out.attached.note);
    out.interpreter =
        fp::AttachConstraintBytecodeInterpreter(
            out.attached, BooleanProgramTable());
    BOOST_REQUIRE_MESSAGE(
        out.interpreter.valid, out.interpreter.note);
    BOOST_REQUIRE(
        out.interpreter.quotient_opening_equality);
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    source_parent_q_and_all_identities_are_proof_owned)
{
    SourceFixture source = BuildSourceFixture(0x71);
    const uint32_t columns_before =
        source.attached.combined.n_columns;
    const rr2::ShardSourceTerminalBindingV2 binding =
        rr2::BindShardSourceTerminalsV2(
            source.attached, source.interpreter,
            /*shard_index=*/0,
            source.cs, source.proof, source.seed,
            /*source_current_width=*/1);
    BOOST_REQUIRE_MESSAGE(binding.valid, binding.note);
    BOOST_CHECK(binding.source_child_native_verified);
    BOOST_CHECK(binding.source_opening_direct_aliases);
    BOOST_CHECK(
        binding.source_q_reconstruction_constrained);
    BOOST_CHECK(binding.identities_u32_preprocessed);
    BOOST_CHECK(binding.local_q_v1_constrained);
    BOOST_REQUIRE_EQUAL(
        binding.source_opening_exports.size(),
        binding.local.queries * 3U);
    BOOST_CHECK_EQUAL(
        source.attached.combined.n_columns,
        binding.layout.End());
    BOOST_CHECK_EQUAL(
        binding.layout.base,
        columns_before + 2U);
    BOOST_CHECK_EQUAL(
        binding.layout.End() - binding.layout.base,
        62U);

    const rr2::ShardReceiptProveResultV2 proved =
        rr2::ProveShardReceiptV2(
            source.attached, binding);
    BOOST_REQUIRE_MESSAGE(proved.valid, proved.note);
    BOOST_CHECK(proved.binding_valid);
    BOOST_CHECK(proved.proved);
    BOOST_CHECK(proved.verified);
    BOOST_CHECK(proved.canonical_codec_round_trip);
    BOOST_CHECK(proved.proof_tamper_rejected);
    BOOST_CHECK(proved.source_opening_forgery_rejected);
    BOOST_CHECK(proved.wire_fits);
    BOOST_CHECK(!proved.recursively_consumed_by_parent);
    BOOST_CHECK_LE(
        proved.encoded_bytes,
        uint64_t{rc::kRCStage3MaxProofBytes});

    std::string why;
    BOOST_CHECK_MESSAGE(
        rr2::VerifyShardReceiptV2(
            source.cs, source.proof, source.seed,
            source.attached.combined, binding,
            proved.receipt, &why),
        why);

    // Attack 1: mutate the ACTUAL FoldBus hash-opening source cell.  The
    // verifier-owned lane export is unchanged, so the direct same-row AIR
    // equality breaks.  This is a proof failure, not a host-side vector
    // comparison.
    auto opening_forgery = source.attached;
    const auto& source_cell =
        binding.source_opening_exports.front();
    const fp::HashOpeningLayout hash_layout =
        fp::HashOpeningLayoutAt(
            binding.source_hash_column_base);
    opening_forgery.columns[
        hash_layout.absorbed_pin_base +
        source_cell.lane][source_cell.row] =
        gf::Add(
            opening_forgery.columns[
                hash_layout.absorbed_pin_base +
                source_cell.lane][source_cell.row],
            gf::Fp3::One());
    const auto forged_opening_proof =
        rr2::ProveShardReceiptV2(
            opening_forgery, binding);
    BOOST_CHECK(!forged_opening_proof.valid);
    BOOST_CHECK(!forged_opening_proof.proved);

    // Attack 2: another genuinely valid source proof cannot be substituted
    // while retaining exactly the same shard-local q receipt.  The source
    // proof, FS seed and reconstructed prechallenge have independent
    // identities in the statement and on every query row.
    const SourceFixture alternate =
        BuildSourceFixture(0x72);
    BOOST_CHECK(!rr2::VerifyShardReceiptV2(
        alternate.cs, alternate.proof, alternate.seed,
        source.attached.combined, binding,
        proved.receipt, nullptr));
    BOOST_REQUIRE_EQUAL(
        proved.receipt.local_q_per_query.size(),
        binding.local.local_q_per_query.size());
    for (size_t query = 0;
         query < proved.receipt.local_q_per_query.size();
         ++query) {
        BOOST_CHECK(gf::Eq(
            proved.receipt.local_q_per_query[query],
            binding.local.local_q_per_query[query]));
    }

    // Attack 3: Goldilocks 0 and p are equal as field elements, but p is not
    // a canonical public encoding.  Even if both the trace and verifier-owned
    // preprocessed copy are edited, V2 rejects before proving.
    auto alias_columns = source.attached;
    uint32_t quotient_row =
        alias_columns.combined.n_rows;
    const uint32_t bytecode_width =
        fp::BytecodeBusLayout(0).End();
    const fp::BytecodeBusLayout bytecode(
        binding.local.original_columns -
        bytecode_width);
    for (uint32_t row = 0;
         row < alias_columns.combined.n_rows; ++row) {
        if (!gf::IsZero(
                alias_columns.columns[
                    bytecode.RowKind(8)][row])) {
            quotient_row = row;
            break;
        }
    }
    BOOST_REQUIRE_LT(
        quotient_row, alias_columns.combined.n_rows);
    alias_columns.columns[
        binding.layout.shard_index][quotient_row] =
        gf::Fp3{gf::kP, 0, 0};
    for (auto& [column, values] :
         alias_columns.combined.preprocessed) {
        if (column == binding.layout.shard_index) {
            values[quotient_row] =
                gf::Fp3{gf::kP, 0, 0};
        }
    }
    const auto alias_proof =
        rr2::ProveShardReceiptV2(
            alias_columns, binding);
    BOOST_CHECK(!alias_proof.valid);
    BOOST_CHECK(!alias_proof.binding_valid);

    auto alias_receipt = proved.receipt;
    alias_receipt.local_q_per_query[0].c0 = gf::kP;
    std::vector<unsigned char> alias_bytes;
    BOOST_CHECK(!rr2::SerializeShardReceiptV2(
        alias_receipt, alias_bytes, nullptr));

    // Attack 4: canonical proof bytes remain load-bearing after the attacker
    // recomputes the envelope root.
    auto proof_tamper = proved.receipt;
    proof_tamper.proof_bytes[
        proof_tamper.proof_bytes.size() / 2] ^= 1;
    proof_tamper.receipt_root =
        rr2::ComputeShardReceiptRootV2(proof_tamper);
    BOOST_CHECK(!rr2::VerifyShardReceiptV2(
        source.cs, source.proof, source.seed,
        source.attached.combined, binding,
        proof_tamper, nullptr));

    std::vector<unsigned char> encoded;
    BOOST_REQUIRE(rr2::SerializeShardReceiptV2(
        proved.receipt, encoded, &why));
    auto trailing = encoded;
    trailing.push_back(0);
    BOOST_CHECK(
        !rr2::DeserializeShardReceiptV2(
            trailing, nullptr).has_value());

    BOOST_TEST_MESSAGE(proved.note);
    BOOST_TEST_MESSAGE(
        "RECEIPT_V2_SOURCE_EXPORT"
        " source_direct=1 local_v1=1"
        " source_substitution_reject=1"
        " goldilocks_alias_reject=1"
        " proof_tamper_reject=1"
        " rows=" << proved.receipt.n_rows
        << " cols=" << proved.receipt.n_columns
        << " constraints=" << proved.receipt.n_constraints
        << " bytes=" << proved.encoded_bytes
        << " prove_us=" << proved.prove_micros
        << " verify_us=" << proved.verify_micros
        << " recursive_consumption=0");
    static_assert(rr2::kShardReceiptExecutableV2);
    static_assert(
        !rr2::kShardReceiptRecursiveOwnershipReadyV2);
}

BOOST_AUTO_TEST_SUITE_END()

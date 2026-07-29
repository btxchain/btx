// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>
#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_multirow_v11_merkle_fold.h>
#include <matmul/matmul_v4_rc_stage3_v13_merkle_fold_parent.h>

#include <algorithm>
#include <chrono>
#include <functional>
#include <set>
#include <string_view>
#include <tuple>

namespace matmul::v4::rc::stage3_multirow_v11_merkle_fold {
namespace {

using Digest = alg_hash::Digest;
namespace cb = constraint_bytecode;

struct Tree {
    std::vector<std::vector<Digest>> levels;
    Digest root{};

    [[nodiscard]] std::vector<Digest> Path(uint32_t index) const
    {
        std::vector<Digest> out;
        for (uint32_t level = 0; level + 1 < levels.size(); ++level) {
            out.push_back(levels[level][index ^ 1U]);
            index >>= 1;
        }
        return out;
    }
};

template <typename Leaf>
Tree BuildTree(uint32_t leaves, Leaf leaf)
{
    BOOST_REQUIRE(leaves >= 2);
    BOOST_REQUIRE((leaves & (leaves - 1)) == 0);
    Tree out;
    out.levels.emplace_back(leaves);
    for (uint32_t index = 0; index < leaves; ++index) {
        out.levels[0][index] = leaf(index);
    }
    uint32_t width = leaves;
    while (width > 1) {
        out.levels.emplace_back(width / 2);
        for (uint32_t index = 0; index < width / 2; ++index) {
            out.levels.back()[index] = alg_hash::Compress(
                out.levels[out.levels.size() - 2][2 * index],
                out.levels[out.levels.size() - 2][2 * index + 1]);
        }
        width >>= 1;
    }
    out.root = out.levels.back()[0];
    return out;
}

struct Fixture {
    abi::EnvelopeV1 envelope;
    backend::ProofV1 proof;
    abi::DecodedV1 decoded;
    tp::ReceiptV1 transcript;
    std::vector<uint32_t> words;
};

Fixture BuildFixture()
{
    constexpr uint32_t trace_rows = 256;
    constexpr uint32_t n_coeffs = 256;
    constexpr uint32_t blowup = kRCFriBlowup;
    constexpr uint32_t n_lde = n_coeffs * blowup;
    const Fp3 zero = Fp3::Zero();

    const Tree row_tree = BuildTree(
        n_lde,
        [&](uint32_t index) {
            return alg_hash::LeafHashRow({zero}, index);
        });
    std::vector<Tree> fold_trees;
    for (uint32_t width = n_lde;; width >>= 1) {
        fold_trees.push_back(BuildTree(
            width,
            [&](uint32_t index) {
                return alg_hash::LeafHash(zero, index);
            }));
        if (width == blowup) break;
    }

    Fixture fixture;
    auto& split = fixture.envelope.split;
    auto& batch = split.batch;
    for (uint32_t word = 0; word < fixture.envelope.public_fs_seed.size();
         ++word) {
        fixture.envelope.public_fs_seed[word] =
            0x11223300U + word;
    }
    fixture.envelope.trace_columns = 2;
    fixture.envelope.quotient_len = trace_rows;
    split.version = 1;
    split.trace_rows = trace_rows;
    split.base_column_indices = {0};
    batch.version = kRCFri3AlgMultiRowBatchProofVersion;
    batch.pow_grind_nonce = 0;
    batch.blowup = blowup;
    batch.n_coeffs = n_coeffs;
    batch.groups = {
        {Fri3AlgMultiRowGroupRole::MainTrace, 0, 1,
         {row_tree.root, n_lde}},
        {Fri3AlgMultiRowGroupRole::AuxiliaryTrace, 1, 1,
         {row_tree.root, n_lde}},
        {Fri3AlgMultiRowGroupRole::Quotient, 2, 1,
         {row_tree.root, n_lde}}};
    batch.column_len = {trace_rows, trace_rows, trace_rows};
    batch.evals_z1.assign(3, zero);
    batch.evals_z2.assign(3, zero);
    for (uint32_t fold = 0; fold < fold_trees.size(); ++fold) {
        batch.fold_layers.push_back({
            fold_trees[fold].root, n_lde >> fold});
    }
    batch.final_value = zero;

    tp::StatementV1 statement;
    for (uint32_t word = 0; word < 8; ++word) {
        for (uint32_t byte = 0; byte < 4; ++byte) {
            statement.public_fs_seed.data()[4 * word + byte] =
                static_cast<unsigned char>(
                    fixture.envelope.public_fs_seed[word] >> (8 * byte));
        }
    }
    statement.trace_rows = trace_rows;
    statement.trace_columns = 2;
    statement.quotient_len = trace_rows;
    statement.n_coeffs = n_coeffs;
    statement.blowup = blowup;
    statement.base_column_indices = {0};
    statement.groups = {{
        {Fri3AlgMultiRowGroupRole::MainTrace, 0, 1,
         n_lde, row_tree.root},
        {Fri3AlgMultiRowGroupRole::AuxiliaryTrace, 1, 1,
         n_lde, row_tree.root},
        {Fri3AlgMultiRowGroupRole::Quotient, 2, 1,
         n_lde, row_tree.root}}};
    statement.column_len = batch.column_len;
    statement.evals_z1 = batch.evals_z1;
    statement.evals_z2 = batch.evals_z2;
    for (uint32_t fold = 0; fold < fold_trees.size(); ++fold) {
        statement.folds.push_back(
            {n_lde >> fold, fold_trees[fold].root});
    }
    statement.final_value = zero;
    fixture.transcript = tp::DeriveV1(statement);
    BOOST_REQUIRE_MESSAGE(
        fixture.transcript.valid, fixture.transcript.note);
    split.air_constraint_lambda = fixture.transcript.air_lambda;
    batch.lambda = fixture.transcript.batching_coefficients[0];
    batch.z1 = fixture.transcript.z1;
    batch.z2 = fixture.transcript.z2;
    batch.w1 = fixture.transcript.w1;
    batch.w2 = fixture.transcript.w2;
    batch.fold_challenges = fixture.transcript.fold_challenges;

    batch.queries.resize(kProductionQueriesV1);
    split.next_trace_group_rows.resize(kProductionQueriesV1);
    for (uint32_t q = 0; q < kProductionQueriesV1; ++q) {
        auto& query = batch.queries[q];
        query.index = fixture.transcript.queries[q].index;
        query.group_rows.resize(3);
        for (uint32_t group = 0; group < 3; ++group) {
            query.group_rows[group].values = {zero};
            query.group_rows[group].siblings =
                row_tree.Path(query.index);
        }
        uint32_t index = query.index;
        query.steps.resize(batch.fold_challenges.size());
        for (uint32_t fold = 0;
             fold < batch.fold_challenges.size(); ++fold) {
            const uint32_t width = n_lde >> fold;
            const uint32_t half = width / 2;
            auto& step = query.steps[fold];
            step.even_index = index % half;
            step.odd_index = step.even_index + half;
            step.even = zero;
            step.odd = zero;
            step.even_siblings =
                fold_trees[fold].Path(step.even_index);
            step.odd_siblings =
                fold_trees[fold].Path(step.odd_index);
            index %= half;
        }
        const uint32_t next_index =
            (query.index + n_lde / trace_rows) % n_lde;
        split.next_trace_group_rows[q].resize(2);
        for (uint32_t group = 0; group < 2; ++group) {
            split.next_trace_group_rows[q][group].values = {zero};
            split.next_trace_group_rows[q][group].siblings =
                row_tree.Path(next_index);
        }
    }

    std::string why;
    BOOST_REQUIRE_MESSAGE(
        abi::EncodeCanonicalV1(
            fixture.envelope, fixture.words, nullptr, &why),
        why);
    auto decoded = abi::DecodeCanonicalV1(fixture.words, &why);
    BOOST_REQUIRE_MESSAGE(decoded.has_value(), why);
    fixture.decoded = std::move(*decoded);
    fixture.proof.envelope = fixture.envelope;
    return fixture;
}

const Fixture& Honest()
{
    static const Fixture fixture = BuildFixture();
    return fixture;
}

std::optional<abi::DecodedV1> Recode(const abi::EnvelopeV1& envelope)
{
    std::vector<uint32_t> words;
    std::string why;
    if (!abi::EncodeCanonicalV1(envelope, words, nullptr, &why)) {
        return std::nullopt;
    }
    return abi::DecodeCanonicalV1(words, &why);
}

uint256 FixedRoot(uint8_t value)
{
    uint256 out;
    std::fill(out.begin(), out.end(), value);
    return out;
}

struct TapeFixtureV1 {
    stage3_multirow_v13_proof_tape_air::PublicShapeV1 shape;
    stage3_multirow_v13_proof_tape_air::PublicBindingV1 binding;
    std::vector<uint32_t> words;
    abi::DecodedV1 decoded;
    stage3_multirow_v13_proof_tape_air::ProductV1 product;
};

TapeFixtureV1 BuildTapeFixtureV1(const Fixture& fixture)
{
    namespace tape =
        stage3_multirow_v13_proof_tape_air;
    TapeFixtureV1 out;
    const auto& split = fixture.envelope.split;
    out.shape.trace_rows = split.trace_rows;
    out.shape.trace_columns =
        fixture.envelope.trace_columns;
    out.shape.quotient_len =
        fixture.envelope.quotient_len;
    out.shape.n_coeffs =
        split.batch.n_coeffs;
    out.shape.base_column_indices =
        split.base_column_indices;
    out.binding.program_root = FixedRoot(0x11);
    out.binding.statement_root = FixedRoot(0x22);
    out.binding.proof_wire_root = FixedRoot(0x44);
    for (uint32_t word = 0;
         word < 8; ++word) {
        for (uint32_t byte = 0;
             byte < 4; ++byte) {
            out.binding.public_fs_seed
                .data()[4 * word + byte] =
                static_cast<unsigned char>(
                    fixture.envelope
                        .public_fs_seed[word] >>
                    (8 * byte));
        }
    }

    const auto schedule =
        tape::BuildScheduleV1(
            out.shape, out.binding);
    BOOST_REQUIRE_MESSAGE(
        schedule.valid, schedule.note);
    out.words.resize(
        tape::kHeaderRecordsV1 +
        size_t{schedule.source_records} * 2);
    for (uint32_t header = 0;
         header < tape::kHeaderRecordsV1;
         ++header) {
        out.words[header] =
            schedule.records[
                tape::kPublicPrefixRecordsV1 +
                header].expected_value;
    }
    for (uint32_t address = 0;
         address < schedule.source_records;
         ++address) {
        const auto& record =
            schedule.records[
                tape::kPublicPrefixRecordsV1 +
                tape::kHeaderRecordsV1 +
                address];
        const size_t offset =
            tape::kHeaderRecordsV1 +
            size_t{address} * 2;
        out.words[offset] =
            record.expected_address;
        if (record.fixed_value) {
            out.words[offset + 1] =
                record.expected_value;
            continue;
        }
        const auto fixture_address =
            abi::FindSourceAddressV1(
                fixture.decoded.sources,
                record.key);
        BOOST_REQUIRE_MESSAGE(
            fixture_address.has_value(),
            "SAFE-V13 source missing from canonical fixture");
        out.words[offset + 1] =
            fixture.decoded
                .sources[*fixture_address]
                .value;
    }
    std::string why;
    const auto decoded =
        abi::DecodeCanonicalSafeV13(
            out.words, &why);
    BOOST_REQUIRE_MESSAGE(
        decoded.has_value(), why);
    out.decoded = *decoded;
    out.binding.tape_root =
        tape::ComputeTapeRootV1(
            out.shape, out.binding,
            out.words, &why);
    BOOST_REQUIRE_MESSAGE(
        out.binding.tape_root !=
            alg_hash::Digest{},
        why);
    out.product =
        tape::BuildProductV1(
            out.shape, out.binding,
            out.words);
    BOOST_REQUIRE_MESSAGE(
        out.product.valid,
        out.product.note);
    return out;
}

struct TypedSourceCanaryV1 {
    aq::AirConstraintSystem<Fp3> cs;
    std::vector<std::vector<Fp3>>
        columns;
};

TypedSourceCanaryV1 BuildTypedSourceCanaryV1(
    uint32_t low,
    uint32_t high,
    Fp3 target)
{
    TypedSourceCanaryV1 out;
    out.cs.n_rows = 2;
    out.cs.n_columns = 4;
    out.columns.assign(
        out.cs.n_columns,
        std::vector<Fp3>(
            out.cs.n_rows,
            Fp3::Zero()));
    for (uint32_t row = 0;
         row < out.cs.n_rows;
         ++row) {
        out.columns[0][row] =
            gf::FromU64_3(low);
        out.columns[1][row] =
            gf::FromU64_3(high);
        out.columns[2][row] =
            target;
        out.columns[3][row] =
            Fp3::One();
    }
    const auto add =
        [&out](
            const char* name,
            aq::AirKind kind,
            uint32_t degree,
            std::function<Fp3(
                const std::vector<Fp3>&,
                const std::vector<Fp3>&)>
                eval) {
            aq::AirConstraint<Fp3>
                constraint;
            constraint.name = name;
            constraint.kind = kind;
            constraint.alg_degree =
                degree;
            constraint.eval =
                std::move(eval);
            out.cs.constraints.push_back(
                std::move(constraint));
        };
    for (uint32_t column = 0;
         column < 3; ++column) {
        add(
            "stage3.v13_merkle_fold.canary_carry",
            aq::AirKind::kTransition,
            1,
            [column](
                const auto& current,
                const auto& next) {
                return gf::Sub(
                    next[column],
                    current[column]);
            });
    }
    add(
        "stage3.v13_merkle_fold.canary_recompose",
        aq::AirKind::kEverywhere,
        1,
        [](const auto& current,
           const auto&) {
            const Fp3 expected =
                gf::Add(
                    current[0],
                    gf::Mul(
                        gf::FromU64_3(
                            uint64_t{1}
                            << 32),
                        current[1]));
            return gf::Sub(
                current[2], expected);
        });
    add(
        "stage3.v13_merkle_fold.canary_accept",
        aq::AirKind::kFirstRow,
        1,
        [](const auto& current,
           const auto&) {
            return gf::Sub(
                current[3],
                Fp3::One());
        });
    return out;
}

TypedSourceCanaryV1
BuildCanonicalAcceptanceCanaryV1(
    const aq::AirConstraint<Fp3>& source,
    bool substitute_constant)
{
    BOOST_REQUIRE(
        std::string_view(source.name) ==
            "stage3.v13_merkle_fold.hash_acceptance" ||
        std::string_view(source.name) ==
            "stage3.v13_merkle_fold.fold_acceptance");
    BOOST_REQUIRE(
        source.canonical_program_table_wire !=
            nullptr);
    cb::ProgramTable source_table;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        cb::DeserializeProgramTable(
            *source.canonical_program_table_wire,
            source_table, &why),
        why);
    BOOST_REQUIRE_LT(
        source.canonical_program_ordinal,
        source_table.programs.size());
    cb::Program program =
        source_table.programs[
            source.canonical_program_ordinal];
    BOOST_REQUIRE(
        program.kind ==
            aq::AirKind::kFirstRow);
    BOOST_REQUIRE_EQUAL(
        program.declared_degree, 1U);
    bool saw_column = false;
    bool saw_one = false;
    for (auto& instruction :
         program.instructions) {
        if (instruction.opcode ==
                cb::Opcode::Current ||
            instruction.opcode ==
                cb::Opcode::Next) {
            instruction.lhs = 0;
            saw_column = true;
        }
        if (instruction.opcode ==
                cb::Opcode::Constant &&
            gf::Eq(
                instruction.constant,
                Fp3::One())) {
            saw_one = true;
            if (substitute_constant) {
                instruction.constant =
                    Fp3::Zero();
            }
        }
    }
    BOOST_REQUIRE(saw_column);
    BOOST_REQUIRE(saw_one);
    program.constraint_ordinal = 0;
    program.current_width = 1;
    program.next_width = 1;
    program.challenge_width = 0;
    cb::ProgramTable table;
    table.version =
        cb::kConstraintBytecodeVersion;
    table.role = source_table.role;
    table.current_width = 1;
    table.next_width = 1;
    table.challenge_width = 0;
    table.programs.push_back(
        std::move(program));
    TypedSourceCanaryV1 out;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            table, 2, out.cs, &why),
        why);
    out.columns = {{
        Fp3::One(), Fp3::One()}};
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_merkle_fold_tests)

BOOST_AUTO_TEST_CASE(
    all_q192_current_next_and_fold_paths_close)
{
    const auto& fixture = Honest();
    std::string backend_why;
    tp::ReceiptV1 backend_transcript;
    BOOST_REQUIRE_MESSAGE(
        backend::VerifyV1(
            fixture.proof, &backend_transcript, &backend_why),
        backend_why);
    BOOST_REQUIRE(backend_transcript.valid);
    BOOST_CHECK_EQUAL(
        backend_transcript.queries[0].index,
        fixture.transcript.queries[0].index);
    const auto audit = AuditAllV1(
        fixture.proof, fixture.transcript);
    BOOST_REQUIRE_MESSAGE(audit.valid, audit.note);
    BOOST_CHECK_EQUAL(audit.queries_checked, 192U);
    BOOST_CHECK_EQUAL(audit.current_paths_checked, 576U);
    BOOST_CHECK_EQUAL(audit.next_paths_checked, 384U);
    BOOST_CHECK_EQUAL(audit.fold_paths_checked, 3072U);
    BOOST_CHECK_EQUAL(audit.fold_equations_checked, 1536U);
    BOOST_CHECK(audit.current_group_paths_verified);
    BOOST_CHECK(audit.next_group_paths_verified);
    BOOST_CHECK(audit.fold_paths_verified);
    BOOST_CHECK(audit.fold_equations_verified);
    BOOST_CHECK(audit.terminal_value_verified);
    BOOST_CHECK(audit.exact_source_addresses);
    BOOST_CHECK(audit.full_q192_coverage);
    BOOST_CHECK(audit.duplicate_queries_preserved);
    BOOST_CHECK(audit.literal_parent_consumer_refs);
    BOOST_CHECK_GT(audit.duplicate_query_count, 0U);
    BOOST_CHECK_EQUAL(audit.parent_consumer_cells, 5952U);
    BOOST_CHECK_GT(audit.poseidon_permutations, 40000U);
    BOOST_TEST_MESSAGE(
        "V11 full native Merkle/fold audit permutations="
        << audit.poseidon_permutations
        << " source_cells=" << audit.source_cells_consumed);
}

BOOST_AUTO_TEST_CASE(
    sibling_path_root_current_next_and_index_mutations_reject)
{
    const auto& fixture = Honest();
    {
        auto forged = fixture.envelope;
        forged.split.batch.queries[0]
            .group_rows[0].siblings[0][0] =
            gf::Add(
                forged.split.batch.queries[0]
                    .group_rows[0].siblings[0][0],
                gf::FromU64(1));
        const auto decoded = Recode(forged);
        BOOST_REQUIRE(decoded.has_value());
        BOOST_CHECK(!AuditAllV1(*decoded, fixture.transcript).valid);
    }
    {
        auto forged = fixture.envelope;
        std::swap(
            forged.split.batch.queries[0]
                .group_rows[0].siblings[0],
            forged.split.batch.queries[0]
                .group_rows[0].siblings[1]);
        const auto decoded = Recode(forged);
        BOOST_REQUIRE(decoded.has_value());
        BOOST_CHECK(!AuditAllV1(*decoded, fixture.transcript).valid);
    }
    {
        auto forged = fixture.envelope;
        forged.split.batch.groups[0].row_commit.root[0] =
            gf::Add(
                forged.split.batch.groups[0].row_commit.root[0],
                gf::FromU64(1));
        const auto decoded = Recode(forged);
        BOOST_REQUIRE(decoded.has_value());
        BOOST_CHECK(!AuditAllV1(*decoded, fixture.transcript).valid);
    }
    {
        auto forged = fixture.envelope;
        forged.split.next_trace_group_rows[0][0].siblings =
            forged.split.batch.queries[0].group_rows[0].siblings;
        const auto decoded = Recode(forged);
        BOOST_REQUIRE(decoded.has_value());
        BOOST_CHECK(!AuditAllV1(*decoded, fixture.transcript).valid);
    }
    {
        auto forged = fixture.envelope;
        forged.split.batch.queries[0].index ^=
            forged.split.batch.blowup;
        const auto decoded = Recode(forged);
        BOOST_CHECK(
            !decoded.has_value() ||
            !AuditAllV1(*decoded, fixture.transcript).valid);
    }
}

BOOST_AUTO_TEST_CASE(
    fold_side_beta_final_and_goldilocks_alias_mutations_reject)
{
    const auto& fixture = Honest();
    {
        auto forged = fixture.envelope;
        ++forged.split.batch.queries[0].steps[0].even_index;
        const auto decoded = Recode(forged);
        BOOST_CHECK(
            !decoded.has_value() ||
            !AuditAllV1(*decoded, fixture.transcript).valid);
    }
    {
        auto forged = fixture.envelope;
        forged.split.batch.fold_challenges[0] = gf::Add(
            forged.split.batch.fold_challenges[0],
            Fp3::One());
        const auto decoded = Recode(forged);
        BOOST_REQUIRE(decoded.has_value());
        BOOST_CHECK(!AuditAllV1(*decoded, fixture.transcript).valid);
    }
    {
        auto forged = fixture.envelope;
        forged.split.batch.final_value = Fp3::One();
        const auto decoded = Recode(forged);
        BOOST_REQUIRE(decoded.has_value());
        BOOST_CHECK(!AuditAllV1(*decoded, fixture.transcript).valid);
    }
    {
        auto words = fixture.words;
        const auto address = abi::FindSourceAddressV1(
            fixture.decoded.sources,
            {abi::FieldKindV1::QueryStepEven, 0, 0, 0, 0, 0});
        BOOST_REQUIRE(address.has_value());
        words[abi::kFieldAbiHeaderWordsV1 + 2 * *address + 1] =
            static_cast<uint32_t>(gf::kP);
        words[abi::kFieldAbiHeaderWordsV1 + 2 * (*address + 1) + 1] =
            static_cast<uint32_t>(gf::kP >> 32);
        std::string why;
        BOOST_CHECK(!abi::DecodeCanonicalV1(words, &why).has_value());
        BOOST_CHECK(
            why.find("noncanonical") != std::string::npos ||
            why.find("decode") != std::string::npos);
    }
}

BOOST_AUTO_TEST_CASE(
    one_query_shard_is_constant_width_and_quadratic)
{
    const auto& fixture = Honest();
    const auto shard = BuildShardV1(
        fixture.proof, fixture.transcript, 0, 1);
    BOOST_REQUIRE_MESSAGE(shard.valid, shard.note);
    BOOST_CHECK_EQUAL(shard.hash_layout.n_columns, 500U);
    BOOST_CHECK_EQUAL(shard.fold_layout.n_columns, 16U);
    BOOST_CHECK_EQUAL(shard.hash_real_rows, 217U);
    BOOST_CHECK_EQUAL(shard.hash_trace_rows, 256U);
    BOOST_CHECK_EQUAL(shard.fold_real_rows, 8U);
    BOOST_CHECK_EQUAL(shard.fold_trace_rows, 8U);
    BOOST_CHECK_EQUAL(shard.hash_violations, 0U);
    BOOST_CHECK_EQUAL(shard.fold_violations, 0U);
    BOOST_CHECK_LE(shard.hash_max_degree, 2U);
    BOOST_CHECK_LE(shard.fold_max_degree, 2U);
    BOOST_CHECK(shard.proof_owned_pins_ood_bound);
    BOOST_CHECK(!shard.proof_owned_pins_root_pinned);
    BOOST_CHECK(shard.constant_width_schedule);
    BOOST_CHECK(shard.duplicate_queries_preserved);
    BOOST_CHECK(shard.literal_parent_consumer_refs);
    BOOST_CHECK_EQUAL(shard.parent_consumer_refs.size(), 31U);
    BOOST_CHECK(!shard.same_parent_decoder_aliases);
    BOOST_CHECK(!shard.deep_quotient_constrained);
    BOOST_CHECK(!shard.canonical_vm_constrained);
    BOOST_CHECK(!shard.recursive_authority_ready);

    auto forged_hash = shard.hash_columns;
    forged_hash[shard.hash_layout.poseidon.perm.InputCol(0)][0] =
        gf::Add(
            forged_hash[
                shard.hash_layout.poseidon.perm.InputCol(0)][0],
            Fp3::One());
    BOOST_CHECK_GT(
        RecountViolationsV1(shard.hash_cs, forged_hash), 0U);
    auto forged_fold = shard.fold_columns;
    forged_fold[shard.fold_layout.folded][0] =
        gf::Add(forged_fold[shard.fold_layout.folded][0], Fp3::One());
    BOOST_CHECK_GT(
        RecountViolationsV1(shard.fold_cs, forged_fold), 0U);
    auto forged_side = shard.fold_columns;
    forged_side[shard.fold_layout.side][0] = gf::Sub(
        Fp3::One(), forged_side[shard.fold_layout.side][0]);
    BOOST_CHECK_GT(
        RecountViolationsV1(shard.fold_cs, forged_side), 0U);
}

BOOST_AUTO_TEST_CASE(
    v13_parent_exports_every_hash_and_fold_source_as_ordinary)
{
    namespace parent =
        stage3_v13_merkle_fold_parent;
    namespace composer =
        stage3_air_parent_composer;
    const auto& fixture = Honest();
    const auto tape = BuildTapeFixtureV1(
        fixture);
    const auto shard = BuildShardV1(
        tape.decoded,
        fixture.transcript, 0, 1);
    BOOST_REQUIRE_MESSAGE(shard.valid, shard.note);

    const auto hash =
        parent::BuildOrdinaryHashProductV1(
            tape.decoded, shard);
    BOOST_REQUIRE_MESSAGE(hash.valid, hash.note);
    BOOST_CHECK(hash.plan.every_input_lane_resolved);
    BOOST_CHECK(hash.plan.every_prior_precedes_consumer);
    BOOST_CHECK(hash.plan.every_source_address_canonical);
    BOOST_CHECK(hash.plan.lane_ownership_unique);
    BOOST_CHECK(
        hash.plan.output_inventory_complete);
    BOOST_CHECK_EQUAL(
        hash.plan.output_aliases,
        hash.plan.expected_output_aliases);
    BOOST_CHECK(hash.proof_pins_ordinary);
    BOOST_CHECK(hash.selectors_and_constants_only_preprocessed);
    BOOST_CHECK(hash.all_abi_words_exported);
    BOOST_CHECK(hash.all_prior_edges_constrained);
    BOOST_CHECK(hash.all_output_roots_constrained);
    BOOST_CHECK(hash.typed_inputs_canonical_bytecode);
    BOOST_CHECK(
        hash.all_relation_constraints_canonical_bytecode);
    BOOST_CHECK_EQUAL(
        hash.canonical_typed_input_constraints,
        hash.plan.inputs.size());
    BOOST_CHECK_EQUAL(
        hash.canonical_relation_constraints,
        hash.cs.constraints.size() -
            shard.hash_cs.constraints.size());
    BOOST_CHECK_EQUAL(hash.violations, 0U);
    BOOST_CHECK(!hash.source_carriers.empty());

    std::set<std::tuple<
        uint32_t, uint32_t, uint32_t,
        uint32_t>>
        canonical_fold_leaf_edges;
    for (const auto& expression :
         hash.plan.inputs) {
        if (expression.kind !=
                parent::
                    HashLaneExpressionKindV1::
                        SelectPriorOrSiblingLeft ||
            expression.lane != 0) {
            continue;
        }
        const auto& consumer =
            shard.hash_tasks[
                expression.task_row];
        if ((consumer.group != 5 &&
             consumer.group != 6) ||
            consumer.level != 0) {
            continue;
        }
        BOOST_REQUIRE_LT(
            expression.prior_task_row,
            shard.hash_tasks.size());
        const auto& leaf =
            shard.hash_tasks[
                expression.prior_task_row];
        BOOST_CHECK(
            leaf.kind ==
            HashTaskKindV1::FoldLeaf);
        BOOST_CHECK_EQUAL(
            leaf.query, consumer.query);
        BOOST_CHECK_EQUAL(
            leaf.fold, consumer.fold);
        BOOST_CHECK_EQUAL(
            leaf.group,
            consumer.group - 5);
        canonical_fold_leaf_edges.emplace(
            consumer.query,
            consumer.fold,
            leaf.group,
            consumer.group);
    }
    BOOST_CHECK_EQUAL(
        canonical_fold_leaf_edges.size(),
        size_t{
            2 *
            fixture.envelope.split.batch
                .fold_challenges.size()});

    uint64_t q192_task_rows =
        hash.plan.task_rows;
    uint64_t q192_input_lanes =
        hash.plan.expected_input_lanes;
    uint64_t q192_output_aliases =
        hash.plan.output_aliases;
    for (uint32_t query = 1;
         query <
             kProductionQueriesV1;
         ++query) {
        const auto query_shard =
            BuildShardV1(
                tape.decoded,
                fixture.transcript,
                query, 1);
        BOOST_REQUIRE_MESSAGE(
            query_shard.valid,
            query_shard.note);
        const auto query_plan =
            parent::BuildTypedHashPlanV1(
                tape.decoded,
                query_shard);
        BOOST_REQUIRE_MESSAGE(
            query_plan.valid,
            query_plan.note);
        BOOST_CHECK(
            query_plan
                .output_inventory_complete);
        q192_task_rows +=
            query_plan.task_rows;
        q192_input_lanes +=
            query_plan
                .expected_input_lanes;
        q192_output_aliases +=
            query_plan.output_aliases;
    }
    BOOST_CHECK_EQUAL(
        q192_input_lanes,
        q192_task_rows *
            alg_hash::kAlgHashT);
    BOOST_CHECK_EQUAL(
        q192_output_aliases,
        uint64_t{
            kProductionQueriesV1} *
            hash.plan
                .expected_output_aliases);
    BOOST_TEST_MESSAGE(
        "V13 exact Q192 Merkle inventory:"
        " task_rows="
        << q192_task_rows
        << " input_lanes="
        << q192_input_lanes
        << " root_aliases="
        << q192_output_aliases);

    // The old 0/1-vs-5/6 namespace mismatch left no physical leaf edge.
    // Mutating an even leaf into the odd namespace (the test values are
    // deliberately equal) must still fail before a proof can be built.
    auto missing_canonical_edge = shard;
    const auto even_leaf =
        std::find_if(
            missing_canonical_edge
                .hash_tasks.begin(),
            missing_canonical_edge
                .hash_tasks.end(),
            [](const auto& task) {
                return task.kind ==
                        HashTaskKindV1::
                            FoldLeaf &&
                    task.group == 0;
            });
    BOOST_REQUIRE(
        even_leaf !=
        missing_canonical_edge
            .hash_tasks.end());
    even_leaf->group = 1;
    const auto detached_plan =
        parent::BuildTypedHashPlanV1(
            tape.decoded,
            missing_canonical_edge);
    BOOST_CHECK(!detached_plan.valid);
    BOOST_CHECK(
        detached_plan.note.find(
            "fold_leaf_source_schema") !=
        std::string::npos);

    const auto fold =
        parent::BuildOrdinaryFoldProductV1(
            tape.decoded, shard);
    BOOST_REQUIRE_MESSAGE(fold.valid, fold.note);
    BOOST_CHECK(fold.plan.every_source_address_canonical);
    BOOST_CHECK(fold.plan.exact_query_fold_schedule);
    BOOST_CHECK(fold.proof_pins_ordinary);
    BOOST_CHECK(fold.schedule_only_preprocessed);
    BOOST_CHECK(fold.all_abi_words_exported);
    BOOST_CHECK(fold.index_bits_constrained);
    BOOST_CHECK(fold.domain_point_exponentiation_constrained);
    BOOST_CHECK(fold.fold_chain_constrained);
    BOOST_CHECK(
        fold.all_relation_constraints_canonical_bytecode);
    BOOST_CHECK_EQUAL(
        fold.canonical_relation_constraints,
        fold.cs.constraints.size() -
            shard.fold_cs.constraints.size());
    BOOST_CHECK_EQUAL(fold.violations, 0U);
    BOOST_CHECK(!fold.source_carriers.empty());

    aq::AirConstraintSystem<Fp3> parent_cs;
    std::vector<std::vector<Fp3>>
        parent_columns;
    composer::ChildAttachmentV1
        tape_attachment;
    composer::ChildAttachmentV1
        hash_attachment;
    composer::ChildAttachmentV1
        fold_attachment;
    const uint32_t parent_rows =
        std::max({
            tape.product.cs.n_rows,
            hash.cs.n_rows,
            fold.cs.n_rows});
    std::string why;
    const auto append =
        [&](const auto& child,
            uint32_t ordinal,
            composer::ChildAttachmentV1&
                attachment) {
            return child.cs.n_rows ==
                    parent_rows
                ? composer::AppendChildV1(
                      parent_cs,
                      parent_columns,
                      child.cs,
                      child.columns,
                      ordinal,
                      attachment,
                      &why)
                : composer::AppendChildLiftedV1(
                      parent_cs,
                      parent_columns,
                      child.cs,
                      child.columns,
                      parent_rows,
                      ordinal,
                      attachment,
                      &why);
        };
    BOOST_REQUIRE_MESSAGE(
        append(tape.product, 0,
               tape_attachment),
        why);
    BOOST_REQUIRE_MESSAGE(
        append(hash, 1,
               hash_attachment),
        why);
    BOOST_REQUIRE_MESSAGE(
        append(fold, 2,
               fold_attachment),
        why);
    parent::ParentAliasAttachmentV1
        aliases;
    BOOST_REQUIRE_MESSAGE(
        parent::AppendProofTapeAliasesV1(
            parent_cs,
            parent_columns,
            tape.product,
            tape_attachment,
            hash,
            hash_attachment,
            fold,
            fold_attachment,
            aliases,
            &why),
        why);
    BOOST_CHECK(aliases.valid);
    BOOST_CHECK_EQUAL(
        aliases.source_aliases,
        hash.source_carriers.size() +
            fold.source_carriers.size());
    BOOST_CHECK(aliases.tape_cells_literal);
    BOOST_CHECK(
        aliases.child_carriers_ordinary);
    BOOST_CHECK(
        aliases.cross_row_transport_constrained);
    BOOST_CHECK(
        aliases.global_r0_pending);
    BOOST_CHECK_EQUAL(
        aliases.violations, 0U);

    // Metadata is part of physical provenance even when values coincide.
    // Repoint an even source carrier at the equal-valued odd source address
    // while retaining its exact semantic key.  The same-parent tape join
    // must reject the cross-group transplant.
    auto transplanted_hash = hash;
    auto even_carrier =
        std::find_if(
            transplanted_hash
                .source_carriers.begin(),
            transplanted_hash
                .source_carriers.end(),
            [](const auto& carrier) {
                return carrier.source_key.kind ==
                        abi::FieldKindV1::
                            QueryStepEven &&
                    carrier.source_key.limb == 0;
            });
    BOOST_REQUIRE(
        even_carrier !=
        transplanted_hash
            .source_carriers.end());
    auto odd_key =
        even_carrier->source_key;
    odd_key.kind =
        abi::FieldKindV1::QueryStepOdd;
    const auto odd_address =
        abi::FindSourceAddressV1(
            tape.decoded.sources,
            odd_key);
    BOOST_REQUIRE(
        odd_address.has_value());
    BOOST_REQUIRE_EQUAL(
        tape.decoded.sources[
            even_carrier->source_address]
            .value,
        tape.decoded.sources[
            *odd_address].value);
    even_carrier->source_address =
        *odd_address;
    auto attacked_cs = parent_cs;
    auto attacked_columns =
        parent_columns;
    parent::ParentAliasAttachmentV1
        attacked_aliases;
    BOOST_CHECK(
        !parent::AppendProofTapeAliasesV1(
            attacked_cs,
            attacked_columns,
            tape.product,
            tape_attachment,
            transplanted_hash,
            hash_attachment,
            fold,
            fold_attachment,
            attacked_aliases,
            &why));

    const parent::SourceCarrierV1*
        canary_low = nullptr;
    const parent::SourceCarrierV1*
        canary_high = nullptr;
    for (const auto& candidate :
         hash.source_carriers) {
        if (candidate.source_key.limb !=
            0) {
            continue;
        }
        auto high_key =
            candidate.source_key;
        high_key.limb = 1;
        const auto high =
            std::find_if(
                hash.source_carriers.begin(),
                hash.source_carriers.end(),
                [&high_key](
                    const auto& carrier) {
                    return carrier.source_key ==
                        high_key;
                });
        if (high ==
            hash.source_carriers.end()) {
            continue;
        }
        const uint32_t low_value =
            tape.decoded.sources[
                candidate.source_address]
                .value;
        const uint32_t high_value =
            tape.decoded.sources[
                high->source_address]
                .value;
        if (low_value != high_value) {
            canary_low = &candidate;
            canary_high = &*high;
            break;
        }
    }
    BOOST_REQUIRE(canary_low != nullptr);
    BOOST_REQUIRE(canary_high != nullptr);
    const uint32_t low_value =
        tape.decoded.sources[
            canary_low->source_address]
            .value;
    const uint32_t high_value =
        tape.decoded.sources[
            canary_high->source_address]
            .value;
    const Fp3 recomposed =
        gf::Add(
            gf::FromU64_3(low_value),
            gf::Mul(
                gf::FromU64_3(
                    uint64_t{1} << 32),
                gf::FromU64_3(
                    high_value)));
    const Fp3 swapped_recomposition =
        gf::Add(
            gf::FromU64_3(high_value),
            gf::Mul(
                gf::FromU64_3(
                    uint64_t{1} << 32),
                gf::FromU64_3(
                    low_value)));
    BOOST_REQUIRE(
        !gf::Eq(
            recomposed,
            swapped_recomposition));
    using CanaryBackend =
        aq::AirFriBackendAlg<Fp3>;
    const uint256 canary_seed =
        uint256::ONE;
    auto honest_canary =
        BuildTypedSourceCanaryV1(
            low_value,
            high_value,
            recomposed);
    const auto honest_canary_proof =
        aq::AirQuotientProve<
            Fp3, CanaryBackend>(
            honest_canary.cs,
            honest_canary.columns,
            canary_seed);
    BOOST_REQUIRE_MESSAGE(
        honest_canary_proof.ok,
        honest_canary_proof.note);
    BOOST_REQUIRE(
        honest_canary_proof
            .division_exact);
    BOOST_REQUIRE_MESSAGE(
        (aq::AirQuotientVerify<
            Fp3, CanaryBackend>(
            honest_canary.cs,
            honest_canary_proof.proof,
            canary_seed,
            &why)),
        why);

    aq::AirProveOptions force;
    force.force_commit_on_inexact =
        true;
    auto mismatch_canary =
        BuildTypedSourceCanaryV1(
            low_value,
            high_value,
            gf::Add(
                recomposed,
                Fp3::One()));
    const auto mismatch_proof =
        aq::AirQuotientProve<
            Fp3, CanaryBackend>(
            mismatch_canary.cs,
            mismatch_canary.columns,
            canary_seed,
            force);
    BOOST_REQUIRE_MESSAGE(
        mismatch_proof.ok,
        mismatch_proof.note);
    BOOST_REQUIRE(
        !mismatch_proof.division_exact);
    BOOST_CHECK(
        (!aq::AirQuotientVerify<
            Fp3, CanaryBackend>(
            mismatch_canary.cs,
            mismatch_proof.proof,
            canary_seed,
            &why)));

    auto swapped_canary =
        BuildTypedSourceCanaryV1(
            high_value,
            low_value,
            recomposed);
    const auto swapped_proof =
        aq::AirQuotientProve<
            Fp3, CanaryBackend>(
            swapped_canary.cs,
            swapped_canary.columns,
            canary_seed,
            force);
    BOOST_REQUIRE_MESSAGE(
        swapped_proof.ok,
        swapped_proof.note);
    BOOST_REQUIRE(
        !swapped_proof.division_exact);
    BOOST_CHECK(
        (!aq::AirQuotientVerify<
            Fp3, CanaryBackend>(
            swapped_canary.cs,
            swapped_proof.proof,
            canary_seed,
            &why)));

}

BOOST_AUTO_TEST_CASE(
    representative_shard_proofs_verify_and_substitution_rejects)
{
    const auto& fixture = Honest();
    const auto shard = BuildShardV1(
        fixture.proof, fixture.transcript, 0, 1);
    BOOST_REQUIRE_MESSAGE(shard.valid, shard.note);
    const uint256 seed = uint256::ONE;
    std::string why;

    const auto hash_prove_start = std::chrono::steady_clock::now();
    const auto hash_proved = aq::AirQuotientProveRows(
        shard.hash_cs, shard.hash_columns, seed);
    const auto hash_prove_end = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(hash_proved.ok, hash_proved.note);
    BOOST_REQUIRE(hash_proved.division_exact);
    const auto hash_verify_start = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRows(
            shard.hash_cs, hash_proved.proof, seed, &why),
        why);
    const auto hash_verify_end = std::chrono::steady_clock::now();

    AirQuotientProofAlg canonical;
    canonical.batch = hash_proved.proof.batch;
    canonical.next_openings = hash_proved.proof.next_openings;
    canonical.trace_commit = hash_proved.proof.trace_commit;
    std::vector<unsigned char> bytes;
    BOOST_REQUIRE_MESSAGE(
        SerializeAirQuotientProofAlg(canonical, bytes, &why), why);
    BOOST_TEST_MESSAGE(
        "V11_MERKLE_SHARD proof_bytes=" << bytes.size()
        << " prove_ms="
        << std::chrono::duration_cast<std::chrono::milliseconds>(
               hash_prove_end - hash_prove_start).count()
        << " verify_us="
        << std::chrono::duration_cast<std::chrono::microseconds>(
               hash_verify_end - hash_verify_start).count()
        << " rows=" << shard.hash_trace_rows
        << " cols=" << shard.hash_layout.n_columns
        << " constraints=" << shard.hash_constraints);

    // Proof-level child substitution: the same proof must not verify after
    // changing one root-pinned operation-table input.
    auto substituted_cs = shard.hash_cs;
    BOOST_REQUIRE(!substituted_cs.preprocessed.empty());
    substituted_cs.preprocessed[0].second[0] = gf::Add(
        substituted_cs.preprocessed[0].second[0], Fp3::One());
    BOOST_CHECK(!aq::AirQuotientVerifyRows(
        substituted_cs, hash_proved.proof, seed, &why));

    auto tampered = hash_proved.proof;
    BOOST_REQUIRE(!tampered.batch.queries.empty());
    BOOST_REQUIRE(
        !tampered.batch.queries[0].row.values.empty());
    tampered.batch.queries[0].row.values[0] = gf::Add(
        tampered.batch.queries[0].row.values[0], Fp3::One());
    BOOST_CHECK(!aq::AirQuotientVerifyRows(
        shard.hash_cs, tampered, seed, &why));

    const auto fold_proved = aq::AirQuotientProveRows(
        shard.fold_cs, shard.fold_columns, seed);
    BOOST_REQUIRE_MESSAGE(fold_proved.ok, fold_proved.note);
    BOOST_REQUIRE(fold_proved.division_exact);
    BOOST_CHECK(aq::AirQuotientVerifyRows(
        shard.fold_cs, fold_proved.proof, seed, &why));
}

BOOST_AUTO_TEST_CASE(
    canonical_v13_merkle_fold_tables_prove_and_substitution_reject)
{
    namespace parent =
        stage3_v13_merkle_fold_parent;
    namespace tape =
        stage3_multirow_v13_proof_tape_air;
    tape::PublicShapeV1 shape;
    shape.trace_rows = 256;
    shape.trace_columns = 2;
    shape.quotient_len = 256;
    shape.n_coeffs = 256;
    shape.base_column_indices = {0};
    tape::PublicBindingV1 binding;
    binding.program_root = FixedRoot(0x61);
    binding.statement_root = FixedRoot(0x62);
    binding.public_fs_seed = FixedRoot(0x63);
    binding.proof_wire_root = FixedRoot(0x64);
    binding.tape_root = {1, 2, 3, 4};
    parent::PublicConstraintSystemsV1 systems;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        parent::BuildPublicConstraintSystemsV1(
            shape, binding,
            {.ordinal = 0,
             .first_query = 0,
             .query_count = 1},
            systems, &why),
        why);
    BOOST_REQUIRE(
        systems.hash_relations_canonical_bytecode);
    BOOST_REQUIRE(
        systems.fold_relations_canonical_bytecode);

    const auto acceptance =
        [](const auto& cs,
           const char* name)
            -> const aq::AirConstraint<Fp3>& {
            const auto found =
                std::find_if(
                    cs.constraints.begin(),
                    cs.constraints.end(),
                    [name](const auto& constraint) {
                        return constraint.name == name;
                    });
            BOOST_REQUIRE(
                found != cs.constraints.end());
            return *found;
        };
    const std::array<const aq::AirConstraint<Fp3>*, 2>
        sources{{
            &acceptance(
                systems.hash_cs,
                "stage3.v13_merkle_fold.hash_acceptance"),
            &acceptance(
                systems.fold_cs,
                "stage3.v13_merkle_fold.fold_acceptance"),
        }};
    using Backend =
        aq::AirFriBackendAlg<Fp3>;
    const uint256 seed = uint256::ONE;
    for (const auto* source : sources) {
        const auto honest =
            BuildCanonicalAcceptanceCanaryV1(
                *source, false);
        const auto proved =
            aq::AirQuotientProve<
                Fp3, Backend>(
                honest.cs,
                honest.columns, seed);
        BOOST_REQUIRE_MESSAGE(
            proved.ok, proved.note);
        BOOST_REQUIRE(
            proved.division_exact);
        BOOST_REQUIRE_MESSAGE(
            (aq::AirQuotientVerify<
                Fp3, Backend>(
                honest.cs, proved.proof,
                seed, &why)),
            why);

        const auto substituted =
            BuildCanonicalAcceptanceCanaryV1(
                *source, true);
        BOOST_CHECK(
            (!aq::AirQuotientVerify<
                Fp3, Backend>(
                substituted.cs,
                proved.proof,
                seed, &why)));

        auto tampered = proved.proof;
        BOOST_REQUIRE(
            !tampered.batch.queries.empty());
        BOOST_REQUIRE(
            !tampered.batch.queries[0]
                 .row.values.empty());
        tampered.batch.queries[0]
            .row.values[0] =
            gf::Add(
                tampered.batch.queries[0]
                    .row.values[0],
                Fp3::One());
        BOOST_CHECK(
            (!aq::AirQuotientVerify<
                Fp3, Backend>(
                honest.cs, tampered,
                seed, &why)));
    }
}

BOOST_AUTO_TEST_CASE(readiness_is_explicitly_fail_closed)
{
    constexpr auto readiness = CurrentReadinessV1();
    static_assert(readiness.canonical_abi_consumption_executable);
    static_assert(readiness.all_current_next_paths_executable);
    static_assert(readiness.all_fold_paths_executable);
    static_assert(readiness.fp3_fold_equations_executable);
    static_assert(readiness.bounded_poseidon_operation_table_executable);
    static_assert(!readiness.same_parent_decoder_aliases_executable);
    static_assert(!readiness.deep_quotient_executable);
    static_assert(!readiness.canonical_vm_executable);
    static_assert(!readiness.recursive_authority_ready);
    BOOST_CHECK(!readiness.recursive_authority_ready);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v11_merkle_fold

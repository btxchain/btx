// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_relation_local_sharding.h>
#include <matmul/matmul_v4_rc_stage3_episode_extract_product.h>
#include <matmul/matmul_v4_rc_stage3_coupled_exchange_permutation_product.h>
#include <matmul/matmul_v4_rc_stage3_episode_wiring_product.h>
#include <matmul/matmul_v4_rc_stage3_extract_stream_ctl.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_tile_tree_hash_ctl.h>
#include <matmul/matmul_v4_rc_gkr_air.h>
#include <span.h>
#include <uint256.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

namespace rc = matmul::v4::rc;
namespace cb = rc::constraint_bytecode;
namespace gf = matmul::v4::rc::gkr_field;
namespace rl =
    matmul::v4::rc::stage3_relation_local_sharding;
using gf::Fp3;

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_stage3_role_bytecode_tests)

namespace {

Fp3 U(uint64_t value)
{
    return gf::FromU64_3(value);
}

uint256 SeedFromByte(uint8_t value)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(value);
    return uint256{
        Span<const unsigned char>{bytes.data(), bytes.size()}};
}

Fp3 BitSum(
    const std::vector<Fp3>& row,
    uint32_t first,
    uint32_t count)
{
    Fp3 sum = Fp3::Zero();
    uint64_t weight = 1;
    for (uint32_t bit = 0; bit < count; ++bit) {
        sum = gf::Add(
            sum,
            gf::Mul(
                row[first + bit], U(weight)));
        weight <<= 1;
    }
    return sum;
}

Fp3 ExtractReference(
    uint32_t ordinal,
    const std::vector<Fp3>& row)
{
    constexpr uint32_t BOOLEAN_COUNT =
        rc::kRCStage3EpisodeExtractMixColumns -
        rc::kRCStage3ExtractMixBranch;
    constexpr uint32_t GOLDEN = 0x9E3779B9U;
    if (ordinal < BOOLEAN_COUNT) {
        const Fp3 value =
            row[rc::kRCStage3ExtractMixBranch + ordinal];
        return gf::Mul(
            value, gf::Sub(value, Fp3::One()));
    }
    ordinal -= BOOLEAN_COUNT;
    if (ordinal == 0) {
        const Fp3 branch =
            row[rc::kRCStage3ExtractMixBranch];
        const Fp3 boolean = gf::Mul(
            branch, gf::Sub(branch, Fp3::One()));
        return gf::Mul(boolean, boolean);
    }
    if (ordinal >= 1 && ordinal <= 3) {
        const uint32_t target[] = {
            rc::kRCStage3ExtractMixU,
            rc::kRCStage3ExtractMixQ,
            rc::kRCStage3ExtractMixV};
        const uint32_t first[] = {
            rc::kRCStage3ExtractMixUBits,
            rc::kRCStage3ExtractMixQBits,
            rc::kRCStage3ExtractMixVBits};
        return gf::Sub(
            row[target[ordinal - 1]],
            BitSum(
                row, first[ordinal - 1],
                rc::kRCStage3EpisodeExtractMixBits));
    }
    if (ordinal == 4) {
        return gf::Sub(
            U(GOLDEN),
            gf::Add(
                row[rc::kRCStage3ExtractMixQ],
                BitSum(
                    row,
                    rc::kRCStage3ExtractMixQDifferenceBits,
                    rc::kRCStage3EpisodeExtractMixBits)));
    }
    if (ordinal == 5) {
        return gf::Sub(
            gf::Mul(
                row[rc::kRCStage3ExtractMixU],
                U(GOLDEN)),
            gf::Add(
                gf::Mul(
                    row[rc::kRCStage3ExtractMixQ],
                    U(UINT64_C(1) << 32)),
                row[rc::kRCStage3ExtractMixV]));
    }
    if (ordinal == 6) {
        return gf::Sub(
            row[rc::kRCStage3ExtractMixH],
            BitSum(
                row,
                rc::kRCStage3ExtractMixVBits + 28,
                4));
    }
    BOOST_REQUIRE_EQUAL(ordinal, 7U);
    const Fp3 lo = BitSum(
        row, rc::kRCStage3ExtractMixYLoBits,
        rc::kRCStage3EpisodeExtractMixBits);
    Fp3 xored = Fp3::Zero();
    uint64_t weight = 1;
    for (uint32_t bit = 0;
         bit < rc::kRCStage3EpisodeExtractMixBits;
         ++bit) {
        const Fp3 a =
            row[rc::kRCStage3ExtractMixYLoBits + bit];
        const Fp3 b =
            row[rc::kRCStage3ExtractMixYHiBits + bit];
        const Fp3 x = gf::Sub(
            gf::Add(a, b),
            gf::Mul(U(2), gf::Mul(a, b)));
        xored = gf::Add(
            xored, gf::Mul(x, U(weight)));
        weight <<= 1;
    }
    const Fp3 branch =
        row[rc::kRCStage3ExtractMixBranch];
    return gf::Sub(
        row[rc::kRCStage3ExtractMixU],
        gf::Add(
            gf::Mul(branch, lo),
            gf::Mul(
                gf::Sub(Fp3::One(), branch),
                xored)));
}

void CheckAdapterMatchesPrograms(
    const cb::ProgramTable& table,
    const std::vector<Fp3>& current)
{
    BOOST_REQUIRE(cb::ValidateProgramTable(table));
    rc::air_quotient::AirConstraintSystem<Fp3> cs;
    BOOST_REQUIRE(
        cb::BuildAirConstraintSystemFromProgramTable(
            table, 2, cs));
    const std::vector<Fp3> next(
        table.next_width, Fp3::Zero());
    BOOST_REQUIRE_EQUAL(
        cs.constraints.size(), table.programs.size());
    for (uint32_t ordinal = 0;
         ordinal < table.programs.size(); ++ordinal) {
        Fp3 interpreted;
        BOOST_REQUIRE(
            cb::EvaluateProgram(
                table.programs[ordinal],
                current, next, interpreted));
        BOOST_CHECK(
            gf::Eq(
                interpreted,
                cs.constraints[ordinal].eval(
                    current, next)));
    }
}

// Differential test for a challenge-baked transport lane migrated to bytecode.
// Verifies: (1) the bytecode adapter and interpreter match the native LogUp
// lambdas bit-for-bit on random rows; (2) the committed table is
// challenge-independent while a different challenge really changes the
// relation. `native` is the full native CS; the migrated lane is its 6
// constraints starting at `native_offset`.
void DiffTestTransportLane(
    const cb::ProgramTable& table,
    const rc::air_quotient::AirConstraintSystem<Fp3>& native,
    uint32_t native_offset,
    const std::vector<Fp3>& challenge,
    uint32_t width,
    uint64_t rng)
{
    std::string why;
    BOOST_REQUIRE_MESSAGE(cb::ValidateProgramTable(table, &why), why);
    BOOST_CHECK(cb::ProgramTableIsChallengeIndependent(table));
    BOOST_REQUIRE_EQUAL(table.challenge_width, challenge.size());
    const uint32_t n_constraints =
        static_cast<uint32_t>(table.programs.size());
    BOOST_REQUIRE(
        native_offset + n_constraints <= native.constraints.size());

    rc::air_quotient::AirConstraintSystem<Fp3> adapter;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            table, /*n_rows=*/8, challenge, adapter, &why),
        why);
    // The no-challenge overload must refuse a post-challenge table.
    rc::air_quotient::AirConstraintSystem<Fp3> rejected;
    BOOST_CHECK(
        !cb::BuildAirConstraintSystemFromProgramTable(
            table, 8, rejected));

    const auto next_field = [&rng]() {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        return U(rng);
    };
    for (uint32_t trial = 0; trial < 64; ++trial) {
        std::vector<Fp3> current(width);
        std::vector<Fp3> next(width);
        for (uint32_t c = 0; c < width; ++c) current[c] = next_field();
        for (uint32_t c = 0; c < width; ++c) next[c] = next_field();
        for (uint32_t i = 0; i < n_constraints; ++i) {
            const Fp3 native_value =
                native.constraints[native_offset + i].eval(
                    current, next);
            const Fp3 adapter_value =
                adapter.constraints[i].eval(current, next);
            Fp3 interpreted;
            BOOST_REQUIRE(
                cb::EvaluateProgram(
                    table.programs[i], current, next,
                    challenge, interpreted));
            BOOST_CHECK(gf::Eq(native_value, adapter_value));
            BOOST_CHECK(gf::Eq(native_value, interpreted));
        }
    }

    // Challenge-independence: commitment stable across challenge vectors, yet a
    // different challenge changes at least one constraint's evaluation.
    const uint256 commitment = cb::CommitProgramTable(table);
    std::vector<Fp3> other(challenge.size());
    for (uint32_t i = 0; i < other.size(); ++i) other[i] = U(3 * i + 7);
    rc::air_quotient::AirConstraintSystem<Fp3> other_adapter;
    BOOST_REQUIRE(
        cb::BuildAirConstraintSystemFromProgramTable(
            table, 8, other, other_adapter));
    BOOST_CHECK_EQUAL(
        commitment.GetHex(), cb::CommitProgramTable(table).GetHex());
    std::vector<Fp3> probe_current(width);
    std::vector<Fp3> probe_next(width);
    for (uint32_t c = 0; c < width; ++c) probe_current[c] = U(c + 1);
    for (uint32_t c = 0; c < width; ++c) probe_next[c] = U(2 * c + 3);
    bool some_constraint_differs = false;
    for (uint32_t i = 0; i < n_constraints; ++i) {
        if (!gf::Eq(
                adapter.constraints[i].eval(probe_current, probe_next),
                other_adapter.constraints[i].eval(
                    probe_current, probe_next))) {
            some_constraint_differs = true;
            break;
        }
    }
    BOOST_CHECK(some_constraint_differs);
}

} // namespace

BOOST_AUTO_TEST_CASE(
    builder_dequant_table_is_exact_and_mutation_bound)
{
    cb::ProgramTable table;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3EpisodeBuilderTraceProgramTable(
            table, &why),
        why);
    BOOST_CHECK(
        table.role ==
        rc::RCStage3RelationRole::
            EpisodeDeterministicBuilder);
    BOOST_CHECK_EQUAL(table.current_width, 6U);
    BOOST_REQUIRE_EQUAL(table.programs.size(), 5U);

    std::vector<Fp3> row{
        gf::FromSigned3(-7), U(2), U(0), U(1),
        U(4), gf::FromSigned3(-28)};
    CheckAdapterMatchesPrograms(table, row);
    const std::vector<Fp3> next(6, Fp3::Zero());
    for (const auto& program : table.programs) {
        Fp3 result;
        BOOST_REQUIRE(
            cb::EvaluateProgram(
                program, row, next, result));
        BOOST_CHECK(gf::IsZero(result));
    }

    auto changed = table;
    auto& load = *std::find_if(
        changed.programs.back().instructions.begin(),
        changed.programs.back().instructions.end(),
        [](const cb::Instruction& instruction) {
            return instruction.opcode ==
                cb::Opcode::Current;
        });
    load.lhs = (load.lhs + 1) % table.current_width;
    BOOST_REQUIRE(cb::ValidateProgramTable(changed));
    BOOST_CHECK(
        cb::CommitProgramTable(changed) !=
        cb::CommitProgramTable(table));

    const auto manifest =
        rl::BuildRelationLocalShardManifestV1(
            table, 256);
    BOOST_REQUIRE_MESSAGE(manifest.valid, manifest.note);
    BOOST_CHECK_EQUAL(manifest.original_columns, 6U);
    BOOST_CHECK_EQUAL(manifest.original_constraints, 5U);
    BOOST_CHECK(
        !rl::ValidateRelationLocalShardManifestV1(
            changed, manifest));
}

BOOST_AUTO_TEST_CASE(
    role_separated_extract_tables_match_reference)
{
    std::vector<Fp3> row(
        rc::kRCStage3EpisodeExtractMixColumns,
        Fp3::Zero());
    for (uint32_t column = 0;
         column < row.size(); ++column) {
        row[column] = U(
            (UINT64_C(17) +
             UINT64_C(29) * column) &
            UINT64_C(0xffffffff));
    }
    cb::ProgramTable episode;
    cb::ProgramTable coupled;
    BOOST_REQUIRE(
        rc::BuildRCStage3ExtractMixProgramTable(
            rc::RCStage3RelationRole::EpisodeExtract,
            episode));
    BOOST_REQUIRE(
        rc::BuildRCStage3ExtractMixProgramTable(
            rc::RCStage3RelationRole::CoupledExtract,
            coupled));
    BOOST_CHECK_EQUAL(episode.current_width, 197U);
    BOOST_REQUIRE_EQUAL(episode.programs.size(), 201U);
    BOOST_CHECK_EQUAL(coupled.current_width, 197U);
    BOOST_REQUIRE_EQUAL(coupled.programs.size(), 201U);
    BOOST_CHECK(
        cb::CommitProgramTable(episode) !=
        cb::CommitProgramTable(coupled));
    CheckAdapterMatchesPrograms(episode, row);
    CheckAdapterMatchesPrograms(coupled, row);
    const std::vector<Fp3> next(row.size(), Fp3::Zero());
    for (uint32_t ordinal = 0;
         ordinal < episode.programs.size();
         ++ordinal) {
        Fp3 episode_value;
        Fp3 coupled_value;
        BOOST_REQUIRE(cb::EvaluateProgram(
            episode.programs[ordinal],
            row, next, episode_value));
        BOOST_REQUIRE(cb::EvaluateProgram(
            coupled.programs[ordinal],
            row, next, coupled_value));
        const Fp3 expected =
            ExtractReference(ordinal, row);
        BOOST_CHECK(gf::Eq(episode_value, expected));
        BOOST_CHECK(gf::Eq(coupled_value, expected));
    }
    BOOST_CHECK_EQUAL(
        episode.programs.back().declared_degree, 3U);

    cb::ProgramTable unsupported;
    BOOST_CHECK(
        !rc::BuildRCStage3ExtractMixProgramTable(
            rc::RCStage3RelationRole::EpisodeTileTree,
            unsupported));
}

BOOST_AUTO_TEST_CASE(
    root_chain_tables_are_role_bound_and_exact)
{
    std::vector<uint256> commitments;
    for (const auto role : {
             rc::RCStage3RelationRole::EpisodeDigest,
             rc::RCStage3RelationRole::CoupledBarrier,
             rc::RCStage3RelationRole::CoupledDigest}) {
        cb::ProgramTable table;
        BOOST_REQUIRE(
            rc::BuildRCStage3RootChainVectorProgramTable(
                role, table));
        BOOST_CHECK_EQUAL(table.current_width, 5U);
        BOOST_REQUIRE_EQUAL(table.programs.size(), 4U);
        commitments.push_back(
            cb::CommitProgramTable(table));
        std::vector<Fp3> row{
            Fp3::One(), U(123), U(42), U(42), U(42)};
        CheckAdapterMatchesPrograms(table, row);
        const std::vector<Fp3> next(5, Fp3::Zero());
        for (const auto& program : table.programs) {
            Fp3 result;
            BOOST_REQUIRE(
                cb::EvaluateProgram(
                    program, row, next, result));
            BOOST_CHECK(gf::IsZero(result));
        }
    }
    BOOST_CHECK(commitments[0] != commitments[1]);
    BOOST_CHECK(commitments[1] != commitments[2]);
    BOOST_CHECK(commitments[0] != commitments[2]);
}

BOOST_AUTO_TEST_CASE(
    digest_preimage_byte_bridge_is_range_and_value_exact)
{
    cb::ProgramTable table;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3EpisodeDigestPreimageByteBridgeProgramTable(
            table, &why),
        why);
    BOOST_CHECK(
        table.role ==
        rc::RCStage3RelationRole::EpisodeDigest);
    BOOST_CHECK_EQUAL(table.current_width, 13U);
    BOOST_REQUIRE_EQUAL(table.programs.size(), 13U);
    std::vector<Fp3> row(13, Fp3::Zero());
    row[0] = Fp3::One();
    row[1] = U(31);
    row[2] = U(0xa5);
    row[3] = U(0xa5);
    row[4] = U(0xa5);
    for (uint32_t bit = 0; bit < 8; ++bit) {
        row[5 + bit] = U((0xa5U >> bit) & 1U);
    }
    CheckAdapterMatchesPrograms(table, row);
    const std::vector<Fp3> next(13, Fp3::Zero());
    for (const auto& program : table.programs) {
        Fp3 value;
        BOOST_REQUIRE(
            cb::EvaluateProgram(
                program, row, next, value));
        BOOST_CHECK(gf::IsZero(value));
    }
    auto detached = row;
    detached[3] = U(0xa4);
    bool rejected = false;
    for (const auto& program : table.programs) {
        Fp3 value;
        BOOST_REQUIRE(
            cb::EvaluateProgram(
                program, detached, next, value));
        rejected |= !gf::IsZero(value);
    }
    BOOST_CHECK(rejected);
}

BOOST_AUTO_TEST_CASE(
    tile_tree_signed_byte_bridge_is_octet_unique)
{
    cb::ProgramTable table;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3EpisodeTileTreeByteBridgeProgramTable(
            table, &why),
        why);
    BOOST_CHECK(
        table.role ==
        rc::RCStage3RelationRole::EpisodeTileTree);
    BOOST_CHECK_EQUAL(table.current_width, 15U);
    BOOST_REQUIRE_EQUAL(table.programs.size(), 16U);
    std::vector<Fp3> row(15, Fp3::Zero());
    row[0] = Fp3::One();
    row[1] = U(9);
    row[2] = Fp3::FromFp(gf::FromSigned(-91));
    row[3] = Fp3::FromFp(gf::FromSigned(-91));
    row[4] = Fp3::FromFp(gf::FromSigned(-91));
    row[5] = U(0xa5);
    row[6] = Fp3::One();
    for (uint32_t bit = 0; bit < 8; ++bit) {
        row[7 + bit] = U((0xa5U >> bit) & 1U);
    }
    CheckAdapterMatchesPrograms(table, row);
    const std::vector<Fp3> next(15, Fp3::Zero());
    for (const auto& program : table.programs) {
        Fp3 value;
        BOOST_REQUIRE(
            cb::EvaluateProgram(
                program, row, next, value));
        BOOST_CHECK(gf::IsZero(value));
    }

    auto wrong_sign = row;
    wrong_sign[6] = Fp3::Zero();
    bool sign_rejected = false;
    for (const auto& program : table.programs) {
        Fp3 value;
        BOOST_REQUIRE(
            cb::EvaluateProgram(
                program, wrong_sign, next, value));
        sign_rejected |= !gf::IsZero(value);
    }
    BOOST_CHECK(sign_rejected);

    auto detached_octet = row;
    detached_octet[5] = U(0x25);
    bool octet_rejected = false;
    for (const auto& program : table.programs) {
        Fp3 value;
        BOOST_REQUIRE(
            cb::EvaluateProgram(
                program, detached_octet, next, value));
        octet_rejected |= !gf::IsZero(value);
    }
    BOOST_CHECK(octet_rejected);
}

BOOST_AUTO_TEST_CASE(
    every_episode_role_has_role_bound_memory_bytecode)
{
    std::vector<uint256> commitments;
    for (const auto role : {
             rc::RCStage3RelationRole::
                 EpisodeDeterministicBuilder,
             rc::RCStage3RelationRole::EpisodeGemm,
             rc::RCStage3RelationRole::EpisodeExtract,
             rc::RCStage3RelationRole::EpisodeWiring,
             rc::RCStage3RelationRole::EpisodeTileTree,
             rc::RCStage3RelationRole::EpisodeDigest}) {
        cb::ProgramTable table;
        BOOST_REQUIRE(
            rc::BuildRCStage3EpisodeSemanticMemoryProgramTable(
                role, table));
        BOOST_CHECK_EQUAL(table.current_width, 7U);
        BOOST_REQUIRE_EQUAL(table.programs.size(), 3U);
        std::vector<Fp3> row{
            Fp3::One(), U(9), U(8), U(7), U(6),
            U(44), U(44)};
        CheckAdapterMatchesPrograms(table, row);
        const std::vector<Fp3> next(7, Fp3::Zero());
        for (const auto& program : table.programs) {
            Fp3 value;
            BOOST_REQUIRE(
                cb::EvaluateProgram(
                    program, row, next, value));
            BOOST_CHECK(gf::IsZero(value));
        }
        commitments.push_back(
            cb::CommitProgramTable(table));
    }
    std::sort(commitments.begin(), commitments.end());
    BOOST_CHECK(
        std::adjacent_find(
            commitments.begin(), commitments.end()) ==
        commitments.end());
}

BOOST_AUTO_TEST_CASE(
    transpose_transport_bytecode_matches_native_logup_over_post_challenge_columns)
{
    // Build the challenge-INDEPENDENT transport table.
    cb::ProgramTable table;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3EpisodeWiringTransposeProgramTable(
            table, &why),
        why);
    BOOST_CHECK(
        table.role == rc::RCStage3RelationRole::EpisodeWiring);
    BOOST_CHECK_EQUAL(table.current_width, 8U);
    BOOST_CHECK_EQUAL(table.next_width, 8U);
    BOOST_CHECK_EQUAL(table.challenge_width, 4U);
    BOOST_REQUIRE_EQUAL(table.programs.size(), 6U);
    BOOST_CHECK(cb::ProgramTableIsChallengeIndependent(table));
    // Honest raw degree: LogUp lanes over verifier-owned columns are degree 3.
    BOOST_CHECK_EQUAL(table.programs[0].declared_degree, 3U);
    BOOST_CHECK(
        table.programs[0].kind ==
        rc::air_quotient::AirKind::kEverywhere);
    BOOST_CHECK_EQUAL(table.programs[1].declared_degree, 1U);
    BOOST_CHECK(
        table.programs[1].kind ==
        rc::air_quotient::AirKind::kFirstRow);
    BOOST_CHECK_EQUAL(table.programs[2].declared_degree, 3U);
    BOOST_CHECK_EQUAL(table.programs[3].declared_degree, 3U);
    BOOST_CHECK_EQUAL(table.programs[5].declared_degree, 3U);

    // Post-challenge column-class accounting records the 2 -> 3 raise.
    const auto pc = cb::AssessPostChallengeColumnClass();
    BOOST_CHECK(pc.challenge_columns_verifier_owned);
    BOOST_CHECK(!pc.challenge_columns_prover_committed);
    BOOST_CHECK(pc.committed_table_challenge_independent);
    BOOST_CHECK_EQUAL(pc.challenge_column_load_degree, 1U);
    BOOST_CHECK_EQUAL(
        pc.logup_degree_with_baked_constant_challenge, 2U);
    BOOST_CHECK_EQUAL(
        pc.logup_degree_with_challenge_column_class, 3U);
    BOOST_CHECK(!pc.global_soundness_composition_proved);

    // Native builder (production path) at a fixed transcript seed.
    rc::RCStage3EpisodeWiringAirPin pin;
    pin.n_rows = 8;
    pin.schedule_index = 3;
    pin.challenge_seed = SeedFromByte(0x11);
    const auto native =
        rc::BuildRCStage3EpisodeWiringTransposeConstraintSystem(pin);
    BOOST_REQUIRE_EQUAL(
        native.constraints.size(), table.programs.size());

    const auto challenge_array =
        rc::RCStage3EpisodeWiringTransposeChallengeVector(
            pin.challenge_seed, pin.schedule_index);
    const std::vector<Fp3> challenge(
        challenge_array.begin(), challenge_array.end());

    rc::air_quotient::AirConstraintSystem<Fp3> adapter;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            table, pin.n_rows, challenge, adapter, &why),
        why);
    BOOST_REQUIRE_EQUAL(
        adapter.constraints.size(), table.programs.size());

    // The no-challenge adapter overload must refuse a post-challenge table.
    rc::air_quotient::AirConstraintSystem<Fp3> rejected;
    BOOST_CHECK(
        !cb::BuildAirConstraintSystemFromProgramTable(
            table, pin.n_rows, rejected));

    // Differential test: adapter/interpreter == native lambdas on random rows.
    uint64_t rng = 0x9E3779B97F4A7C15ULL;
    const auto next_field = [&rng]() {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        return U(rng);
    };
    for (uint32_t trial = 0; trial < 64; ++trial) {
        std::vector<Fp3> current(8);
        std::vector<Fp3> next(8);
        for (uint32_t c = 0; c < 8; ++c) current[c] = next_field();
        for (uint32_t c = 0; c < 8; ++c) next[c] = next_field();
        for (uint32_t ordinal = 0;
             ordinal < table.programs.size(); ++ordinal) {
            const Fp3 native_value =
                native.constraints[ordinal].eval(current, next);
            const Fp3 adapter_value =
                adapter.constraints[ordinal].eval(current, next);
            Fp3 interpreted;
            BOOST_REQUIRE(
                cb::EvaluateProgram(
                    table.programs[ordinal],
                    current, next, challenge, interpreted));
            BOOST_CHECK(gf::Eq(native_value, adapter_value));
            BOOST_CHECK(gf::Eq(native_value, interpreted));
        }
    }

    // Challenge-independence: the committed table is identical regardless of
    // challenge, yet a different challenge vector really changes the relation.
    const uint256 commitment = cb::CommitProgramTable(table);
    const std::vector<Fp3> other_challenge{
        U(7), U(11), U(13), U(17)};
    rc::air_quotient::AirConstraintSystem<Fp3> other_adapter;
    BOOST_REQUIRE(
        cb::BuildAirConstraintSystemFromProgramTable(
            table, pin.n_rows, other_challenge, other_adapter));
    BOOST_CHECK_EQUAL(
        commitment.GetHex(),
        cb::CommitProgramTable(table).GetHex());
    std::vector<Fp3> probe_current(8);
    std::vector<Fp3> probe_next(8);
    for (uint32_t c = 0; c < 8; ++c) probe_current[c] = U(c + 1);
    for (uint32_t c = 0; c < 8; ++c) probe_next[c] = U(2 * c + 1);
    BOOST_CHECK(
        !gf::Eq(
            adapter.constraints[0].eval(probe_current, probe_next),
            other_adapter.constraints[0].eval(
                probe_current, probe_next)));

    // The migration is reflected honestly in the ledger without completing
    // the role or flipping any authority/composition flag.
    BOOST_CHECK(cb::MigratedTransportCtlLaneCount() >= 1U);
    const auto inventory = cb::CurrentRoleMigrationInventory();
    for (const auto& role : inventory) {
        if (role.role ==
            rc::RCStage3RelationRole::EpisodeWiring) {
            BOOST_CHECK_EQUAL(
                role.migrated_transport_ctl_lanes, 1U);
            BOOST_CHECK(
                role.state == cb::MigrationState::Partial);
            BOOST_CHECK(role.opaque_callbacks_remain);
        }
    }
    BOOST_CHECK(!cb::kAllRegisteredRoleBytecodeMigrated);
}

BOOST_AUTO_TEST_CASE(
    coupled_permutation_and_exchange_transport_bytecode_match_native_logup)
{
    rc::RCStage3CoupledExchangePermutationAirPin pin;
    pin.n_rows = 8;
    pin.schedule_index = 5;
    pin.challenge_seed = SeedFromByte(0x2c);
    const auto challenge_array =
        rc::RCStage3CoupledExchangePermutationTransportChallengeVector(
            pin.challenge_seed, pin.schedule_index);
    const std::vector<Fp3> challenge(
        challenge_array.begin(), challenge_array.end());
    BOOST_CHECK_EQUAL(challenge.size(), 12U);

    // Pure permutation: the whole native system is the two grand-product lanes.
    {
        cb::ProgramTable table;
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            rc::BuildRCStage3CoupledPermutationTransportProgramTable(
                table, &why),
            why);
        BOOST_CHECK(
            table.role ==
            rc::RCStage3RelationRole::CoupledPermutation);
        BOOST_CHECK_EQUAL(table.current_width, 14U);
        BOOST_CHECK_EQUAL(table.programs[0].declared_degree, 3U);
        BOOST_CHECK_EQUAL(table.programs[2].declared_degree, 3U);
        const auto native =
            rc::BuildRCStage3CoupledPermutationTransportConstraintSystem(
                pin);
        BOOST_REQUIRE_EQUAL(native.constraints.size(), 6U);
        DiffTestTransportLane(
            table, native, 0, challenge, 14U,
            0xD1B54A32D192ED03ULL);
    }

    // Exchange (material): the two grand-product lanes are the LAST 6
    // constraints, after the boolean/xor/limb-recompose mixing constraints.
    {
        cb::ProgramTable table;
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            rc::BuildRCStage3CoupledExchangeTransportProgramTable(
                table, &why),
            why);
        BOOST_CHECK(
            table.role ==
            rc::RCStage3RelationRole::CoupledExchange);
        BOOST_CHECK_EQUAL(table.current_width, 214U);
        const auto native =
            rc::BuildRCStage3CoupledExchangeTransportConstraintSystem(
                pin);
        BOOST_REQUIRE(native.constraints.size() >= 6U);
        DiffTestTransportLane(
            table, native,
            static_cast<uint32_t>(native.constraints.size()) - 6U,
            challenge, 214U, 0x2545F4914F6CDD1DULL);
    }

    BOOST_CHECK(cb::MigratedTransportCtlLaneCount() >= 3U);
}

BOOST_AUTO_TEST_CASE(
    additive_gamma_power_transport_bytecode_matches_native_logup)
{
    rc::RCStage3CtlChallenges challenges;
    challenges.gamma1 = U(0x1234567u);
    challenges.alpha1 = U(0x89abcdefu);
    challenges.gamma2 = U(0xfeed1234u);
    challenges.alpha2 = U(0x0badf00du);
    rc::RCStage3CtlTerminal terminal;
    terminal.alpha1_sum = U(0x11117777u);
    terminal.alpha2_sum = U(0x22228888u);
    // Shared packing [gamma1, alpha1, gamma2, alpha2, sum1, sum2].
    const std::vector<Fp3> challenge{
        challenges.gamma1, challenges.alpha1,
        challenges.gamma2, challenges.alpha2,
        terminal.alpha1_sum, terminal.alpha2_sum};

    // EpisodeExtract stream CTL: 12 constraints, whole native system.
    {
        const uint32_t tile = 9;
        const int8_t multiplicity = 1;
        cb::ProgramTable table;
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            rc::BuildRCStage3EpisodeExtractStreamTransportProgramTable(
                tile, multiplicity, table, &why),
            why);
        BOOST_CHECK(
            table.role ==
            rc::RCStage3RelationRole::EpisodeExtract);
        BOOST_CHECK_EQUAL(table.current_width, 7U);
        BOOST_CHECK_EQUAL(table.challenge_width, 6U);
        BOOST_REQUIRE_EQUAL(table.programs.size(), 12U);
        // Inverse constraints (ordinal 1 and 7) are recorded at raw degree 5.
        BOOST_CHECK_EQUAL(table.programs[1].declared_degree, 5U);
        BOOST_CHECK_EQUAL(table.programs[7].declared_degree, 5U);
        const auto native =
            rc::BuildRCStage3ExtractStreamSelectedCtlConstraintSystem(
                /*base_columns=*/1, /*n_rows=*/64,
                /*source_column=*/0, tile, multiplicity,
                challenges, terminal);
        BOOST_REQUIRE_EQUAL(native.constraints.size(), 12U);
        DiffTestTransportLane(
            table, native, 0, challenge, 7U,
            0x94D049BB133111EBULL);
    }

    // EpisodeTileTree producer CTL: 134 constraints, whole native system.
    {
        cb::ProgramTable table;
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            rc::BuildRCStage3EpisodeTileTreeProducerTransportProgramTable(
                table, &why),
            why);
        BOOST_CHECK(
            table.role ==
            rc::RCStage3RelationRole::EpisodeTileTree);
        BOOST_CHECK_EQUAL(table.current_width, 98U);
        BOOST_CHECK_EQUAL(table.challenge_width, 6U);
        BOOST_REQUIRE_EQUAL(table.programs.size(), 134U);
        // First byte/lane inverse constraint recorded at raw degree 5.
        BOOST_CHECK_EQUAL(table.programs[0].declared_degree, 5U);
        const auto native =
            rc::BuildRCStage3TileTreeProducerConstraintSystem(
                /*output_byte_base=*/0, /*n_rows=*/64,
                challenges, terminal);
        BOOST_REQUIRE_EQUAL(native.constraints.size(), 134U);
        DiffTestTransportLane(
            table, native, 0, challenge, 98U,
            0x2545F4914F6CDD1DULL);
    }

    // Six transport lanes now migrated as bytecode: transpose, permutation,
    // exchange, extract-stream, tile-tree, and the CoupledExtract T_M sampler
    // LogUp (see coupled_extract_sampler_transport_bytecode... below).
    BOOST_CHECK_EQUAL(cb::MigratedTransportCtlLaneCount(), 6U);
}

// The sixth and final transport lane: the CoupledExtract T_M sampler LogUp.
// Unblocked by moving the fingerprint ONLINE -- the committed f is bound to the
// challenge-independent table columns by logup.tfp.bind, so gamma/alpha enter
// only as verifier-owned challenge loads and the relation is challenge-
// independent bytecode. Differential-tested vs the native LogUp builder.
BOOST_AUTO_TEST_CASE(
    coupled_extract_sampler_transport_bytecode_matches_native_logup)
{
    const Fp3 gamma = U(0x0abc1234u);
    const Fp3 alpha = U(0x0def5678u);
    const std::vector<Fp3> challenge{gamma, alpha};

    cb::ProgramTable table;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledExtractSamplerTransportProgramTable(
            table, &why),
        why);
    BOOST_CHECK(
        table.role == rc::RCStage3RelationRole::CoupledExtract);
    BOOST_CHECK_EQUAL(table.current_width, 11U);
    BOOST_CHECK_EQUAL(table.challenge_width, 2U);
    BOOST_REQUIRE_EQUAL(table.programs.size(), 6U);
    // logup.phi carries gamma^2 in the post-challenge class -> raw degree 4;
    // logup.tfp.bind -> raw degree 3.
    BOOST_CHECK_EQUAL(table.programs[0].declared_degree, 4U);
    BOOST_CHECK_EQUAL(table.programs[1].declared_degree, 3U);

    const auto native =
        rc::BuildRCStage3CoupledExtractSamplerTransportConstraintSystem(
            gamma, alpha, /*n_rows=*/8);
    BOOST_REQUIRE_EQUAL(native.constraints.size(), 6U);
    DiffTestTransportLane(
        table, native, 0, challenge, 11U, 0x9E3779B97F4A7C15ULL);
}

BOOST_AUTO_TEST_CASE(
    transport_ctl_frontier_is_six_of_six_with_coupled_extract_migrated)
{
    const auto frontier = cb::AssessTransportCtlMigrationFrontier();
    // All six beta/gamma LogUp lanes migrated; honest target is 6 (CoupledBank-
    // narrow is a FRI-fold verifier, out of scope for this column class).
    BOOST_CHECK_EQUAL(frontier.migrated_lanes, 6U);
    BOOST_CHECK_EQUAL(
        frontier.migrated_lanes, cb::MigratedTransportCtlLaneCount());
    BOOST_CHECK_EQUAL(frontier.migratable_lane_target, 6U);
    BOOST_CHECK_EQUAL(frontier.fri_fold_out_of_scope_lanes, 1U);
    // CoupledExtract's transport lane is now migrated (kColTfp obstruction
    // resolved by the online-fingerprint re-plumb + passing differential test).
    BOOST_CHECK(frontier.coupled_extract_migrated);
    // Composition theorem is a separate, still-open obligation.
    BOOST_CHECK(!frontier.global_soundness_composition_proved);

    // CoupledExtract stays Partial (opaque SHA/product builders remain) but now
    // carries one migrated transport lane; its local mix CS is also bytecode.
    const auto inventory = cb::CurrentRoleMigrationInventory();
    for (const auto& role : inventory) {
        if (role.role ==
            rc::RCStage3RelationRole::CoupledExtract) {
            BOOST_CHECK_EQUAL(role.migrated_transport_ctl_lanes, 1U);
            BOOST_CHECK(
                role.state == cb::MigrationState::Partial);
            BOOST_CHECK(role.opaque_callbacks_remain);
        }
    }
    cb::ProgramTable mix;
    BOOST_REQUIRE(
        rc::BuildRCStage3ExtractMixProgramTable(
            rc::RCStage3RelationRole::CoupledExtract, mix));
    BOOST_CHECK_EQUAL(mix.challenge_width, 0U);  // local mix is pre-challenge
    BOOST_CHECK_EQUAL(cb::MigratedTransportCtlLaneCount(), 6U);
}

BOOST_AUTO_TEST_CASE(
    support_audit_counts_only_explicit_tables)
{
    const auto inventory =
        cb::CurrentRoleMigrationInventory();
    BOOST_REQUIRE_EQUAL(inventory.size(), 14U);
    uint32_t partial = 0;
    uint32_t not_started = 0;
    for (const auto& role : inventory) {
        partial += role.state ==
            cb::MigrationState::Partial;
        not_started += role.state ==
            cb::MigrationState::NotStarted;
        BOOST_CHECK(role.opaque_callbacks_remain);
    }
    BOOST_CHECK_EQUAL(partial, 14U);
    BOOST_CHECK_EQUAL(not_started, 0U);

    const auto audit =
        rl::AssessCurrentRelationLocalProductionAuditV1();
    BOOST_REQUIRE_MESSAGE(audit.valid, audit.note);
    BOOST_CHECK_EQUAL(
        audit.explicit_local_program_tables, 25U);
    BOOST_CHECK_EQUAL(
        audit.exact_support_columns, 790U);
    BOOST_CHECK_EQUAL(
        audit.exact_namespace_columns, 825U);
    BOOST_CHECK_EQUAL(
        audit.explicit_local_constraints, 804U);
    BOOST_CHECK_EQUAL(
        audit.explicit_local_shards, 25U);
    BOOST_CHECK(
        !audit.declared_width_manifest_derived);
    BOOST_CHECK(
        !audit.exact_support_hypergraph_available);
    BOOST_CHECK(
        !audit.all_registered_constraints_explicit);
    BOOST_CHECK(!audit.production_candidate);
}

BOOST_AUTO_TEST_CASE(
    pin_independent_header_and_bank_tables_are_role_separated)
{
    cb::ProgramTable header;
    cb::ProgramTable bank;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3EpisodeHeaderTargetEqualityProgramTable(
            header, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledBankDequantProgramTableCanonical(
            bank, &why),
        why);
    BOOST_CHECK(
        header.role ==
        rc::RCStage3RelationRole::EpisodeDigest);
    BOOST_CHECK(
        bank.role ==
        rc::RCStage3RelationRole::CoupledBank);
    BOOST_CHECK_EQUAL(header.current_width, 2U);
    BOOST_CHECK_EQUAL(header.programs.size(), 1U);
    BOOST_CHECK_EQUAL(bank.current_width, 6U);
    BOOST_CHECK_EQUAL(bank.programs.size(), 5U);
    CheckAdapterMatchesPrograms(header, {U(19), U(19)});
    CheckAdapterMatchesPrograms(
        bank,
        {gf::FromSigned3(-3), U(3), U(1), U(1),
         U(8), gf::FromSigned3(-24)});

    const cb::ProgramTable episode = [] {
        cb::ProgramTable table;
        BOOST_REQUIRE(
            rc::BuildRCStage3EpisodeBuilderTraceProgramTable(
                table));
        return table;
    }();
    BOOST_CHECK(
        cb::CommitProgramTable(episode) !=
        cb::CommitProgramTable(bank));
    BOOST_REQUIRE_EQUAL(
        episode.programs.size(), bank.programs.size());
    for (uint32_t ordinal = 0;
         ordinal < episode.programs.size(); ++ordinal) {
        BOOST_CHECK(
            episode.programs[ordinal].instructions ==
            bank.programs[ordinal].instructions);
        BOOST_CHECK(
            episode.programs[ordinal].role !=
            bank.programs[ordinal].role);
    }
}

// CoupledExtract local kernel: the full RcSampler relation as bytecode is
// bit-identical to air_quotient::BuildRcSamplerConstraintSystem, for every
// public scale exponent, over random rows and the [gamma, alpha] challenge.
BOOST_AUTO_TEST_CASE(
    coupled_extract_local_kernel_bytecode_matches_native_rc_sampler)
{
    namespace aq = rc::air_quotient;
    const Fp3 gamma = U(0x0abc1234u);
    const Fp3 alpha = U(0x0def5678u);
    const std::vector<Fp3> challenge{gamma, alpha};
    const rc::gkr_air::TableTM tm;

    uint32_t total_mismatches = 0;
    for (uint8_t scale_e = 0; scale_e <= 3; ++scale_e) {
        cb::ProgramTable table;
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            rc::BuildRCStage3CoupledExtractLocalKernelProgramTable(
                scale_e, table, &why),
            why);
        BOOST_CHECK(
            table.role == rc::RCStage3RelationRole::CoupledExtract);
        BOOST_CHECK_EQUAL(table.current_width, aq::kRcSamplerNumCols);
        BOOST_CHECK_EQUAL(table.challenge_width, 2U);
        BOOST_CHECK(cb::ProgramTableIsChallengeIndependent(table));

        const auto native =
            aq::BuildRcSamplerConstraintSystem<Fp3>(
                /*n_rows=*/8, gamma, alpha, scale_e, tm);
        BOOST_REQUIRE_EQUAL(
            table.programs.size(), native.constraints.size());
        BOOST_CHECK_EQUAL(table.programs.size(), 47U);

        uint64_t rng = 0x243F6A8885A308D3ULL + scale_e;
        const auto next_field = [&rng]() {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            return U(rng);
        };
        for (uint32_t trial = 0; trial < 64; ++trial) {
            std::vector<Fp3> current(table.current_width);
            std::vector<Fp3> next(table.current_width);
            for (auto& v : current) v = next_field();
            for (auto& v : next) v = next_field();
            for (uint32_t i = 0; i < table.programs.size(); ++i) {
                const Fp3 native_value =
                    native.constraints[i].eval(current, next);
                Fp3 interpreted;
                BOOST_REQUIRE(cb::EvaluateProgram(
                    table.programs[i], current, next, challenge,
                    interpreted));
                if (!gf::Eq(native_value, interpreted)) ++total_mismatches;
            }
        }
    }
    BOOST_CHECK_EQUAL(total_mismatches, 0U);
}

// CoupledBarrier / CoupledDigest hash kernel: the SHA-256 compression fixed-
// program AIR as bytecode is bit-identical to
// stage3_hash_air::BuildFixedProgramConstraintSystem over random rows. The two
// roles share the constraint bytecode but commit to distinct tables.
BOOST_AUTO_TEST_CASE(
    coupled_hash_kernel_bytecode_matches_native_sha256_fixed_program)
{
    namespace ha = rc::stage3_hash_air;
    const ha::FixedProgram program =
        ha::BuildCanonicalProgram(ha::ProgramKind::Sha256Compression);
    rc::air_quotient::AirConstraintSystem<Fp3> native;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildFixedProgramConstraintSystem(program, native, &why), why);

    cb::ProgramTable barrier;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3CoupledHashKernelProgramTable(
            rc::RCStage3RelationRole::CoupledBarrier, barrier, &why),
        why);
    BOOST_CHECK(
        barrier.role == rc::RCStage3RelationRole::CoupledBarrier);
    BOOST_CHECK_EQUAL(barrier.current_width, ha::kFixedProgramColumns);
    BOOST_CHECK_EQUAL(barrier.challenge_width, 0U);
    BOOST_REQUIRE_EQUAL(
        barrier.programs.size(), native.constraints.size());
    BOOST_CHECK_EQUAL(barrier.programs.size(), 462U);

    uint64_t rng = 0xB7E151628AED2A6BULL;
    const auto next_field = [&rng]() {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        return U(rng);
    };
    uint32_t mismatches = 0;
    for (uint32_t trial = 0; trial < 32; ++trial) {
        std::vector<Fp3> current(barrier.current_width);
        std::vector<Fp3> next(barrier.next_width);
        for (auto& v : current) v = next_field();
        for (auto& v : next) v = next_field();
        for (uint32_t i = 0; i < barrier.programs.size(); ++i) {
            const Fp3 native_value =
                native.constraints[i].eval(current, next);
            Fp3 interpreted;
            BOOST_REQUIRE(cb::EvaluateProgram(
                barrier.programs[i], current, next, interpreted));
            if (!gf::Eq(native_value, interpreted)) ++mismatches;
        }
    }
    BOOST_CHECK_EQUAL(mismatches, 0U);

    // Role separation: CoupledDigest shares the bytecode but commits distinctly.
    cb::ProgramTable digest;
    BOOST_REQUIRE(
        rc::BuildRCStage3CoupledHashKernelProgramTable(
            rc::RCStage3RelationRole::CoupledDigest, digest, &why));
    BOOST_REQUIRE_EQUAL(
        digest.programs.size(), barrier.programs.size());
    for (uint32_t i = 0; i < digest.programs.size(); ++i) {
        BOOST_CHECK(
            digest.programs[i].instructions ==
            barrier.programs[i].instructions);
    }
    BOOST_CHECK(
        cb::CommitProgramTable(digest) != cb::CommitProgramTable(barrier));

    // Non hash roles are refused.
    cb::ProgramTable rejected;
    BOOST_CHECK(
        !rc::BuildRCStage3CoupledHashKernelProgramTable(
            rc::RCStage3RelationRole::CoupledBank, rejected, &why));
}

// g2b (narrow follow-up): EpisodeTileTree and EpisodeDigest reach the exact
// same DirectSha256d-style fixed-program compression relation as
// CoupledBarrier/CoupledDigest (EpisodeDigest through
// DirectHashRelation::EpisodeDigest, EpisodeTileTree through
// BuildTileTreeManifestBoundaryInstances -> BuildShaManifestBoundaryInstances,
// see matmul_v4_rc_stage3_hash_air.cpp). This hand-authors + commits the two
// roles' ProgramTables (reusing the shared kernel body), differentially
// tests bytecode eval against the live stage3_hash_air AirConstraint
// closures on random AND boundary points (including a REAL SHA256("abc")
// compression witness, which must satisfy every bytecode constraint to
// exactly zero), and proves a mutated instruction rejects that same honest
// witness while also changing the committed table hash.
BOOST_AUTO_TEST_CASE(
    episode_tiletree_and_digest_hash_kernel_bytecode_matches_native_and_rejects_forgery)
{
    namespace ha = rc::stage3_hash_air;
    const ha::FixedProgram program =
        ha::BuildCanonicalProgram(ha::ProgramKind::Sha256Compression);
    rc::air_quotient::AirConstraintSystem<Fp3> native;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildFixedProgramConstraintSystem(program, native, &why), why);

    // A REAL SHA256("abc") compression witness (NIST test vector), so the
    // boundary/forgery checks below run over genuine satisfying columns, not
    // just uniform random field points.
    static constexpr uint32_t H0[8]{
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
    static constexpr uint32_t K[64]{
        0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
        0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
        0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
        0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
        0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
        0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
        0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
        0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U};
    std::vector<uint32_t> external(88, 0);
    external[0] = 0x61626380U; // "abc" plus SHA padding
    external[15] = 24U;        // big-endian bit length
    std::copy(std::begin(H0), std::end(H0), external.begin() + 16);
    std::copy(std::begin(K), std::end(K), external.begin() + 24);
    ha::ProgramWitness witness;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildProgramWitness(program, external, witness, &why), why);
    std::vector<std::vector<Fp3>> columns;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildFixedProgramAirWitness(program, witness, columns, &why),
        why);
    const uint32_t n_rows = native.n_rows;
    BOOST_REQUIRE_EQUAL(columns.size(), ha::kFixedProgramColumns);

    auto row_vectors = [&](const std::vector<std::vector<Fp3>>& cols,
                           uint32_t row, std::vector<Fp3>& cur,
                           std::vector<Fp3>& next) {
        cur.resize(cols.size());
        next.resize(cols.size());
        for (uint32_t col = 0; col < cols.size(); ++col) {
            cur[col] = cols[col][row];
            next[col] = cols[col][(row + 1) % n_rows];
        }
    };

    std::vector<cb::ProgramTable> tables_this_run;
    for (const rc::RCStage3RelationRole role :
         {rc::RCStage3RelationRole::EpisodeTileTree,
          rc::RCStage3RelationRole::EpisodeDigest}) {
        cb::ProgramTable table;
        BOOST_REQUIRE_MESSAGE(
            rc::BuildRCStage3CoupledHashKernelProgramTable(
                role, table, &why),
            why);
        BOOST_CHECK(table.role == role);
        BOOST_CHECK_EQUAL(table.current_width, ha::kFixedProgramColumns);
        BOOST_CHECK_EQUAL(table.challenge_width, 0U);
        BOOST_REQUIRE_EQUAL(
            table.programs.size(), native.constraints.size());
        BOOST_CHECK_EQUAL(table.programs.size(), 462U);
        BOOST_CHECK(cb::ProgramTableIsChallengeIndependent(table));

        for (uint32_t i = 0; i < table.programs.size(); ++i) {
            BOOST_CHECK_MESSAGE(
                table.programs[i].kind == native.constraints[i].kind &&
                    table.programs[i].declared_degree ==
                        native.constraints[i].alg_degree,
                "metadata mismatch at ordinal " << i
                << " table.degree=" << table.programs[i].declared_degree
                << " native.degree=" << native.constraints[i].alg_degree
                << " native.name=" << native.constraints[i].name);
        }

        uint32_t mismatches = 0;

        // (1) Random-point differential test: 32 uniform trials.
        uint64_t rng = 0xB7E151628AED2A6BULL ^
            (role == rc::RCStage3RelationRole::EpisodeTileTree
                 ? 0xA5A5A5A5ULL
                 : 0x5A5A5A5AULL);
        const auto next_field = [&rng]() {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            return U(rng);
        };
        for (uint32_t trial = 0; trial < 32; ++trial) {
            std::vector<Fp3> current(table.current_width);
            std::vector<Fp3> next(table.next_width);
            for (auto& v : current) v = next_field();
            for (auto& v : next) v = next_field();
            for (uint32_t i = 0; i < table.programs.size(); ++i) {
                const Fp3 native_value =
                    native.constraints[i].eval(current, next);
                Fp3 interpreted;
                BOOST_REQUIRE(cb::EvaluateProgram(
                    table.programs[i], current, next, interpreted));
                if (!gf::Eq(native_value, interpreted)) ++mismatches;
            }
        }

        // (2) Boundary-point differential test: all-zero, all-one, and the
        // REAL SHA256("abc") witness rows (first, middle, last).
        std::vector<std::vector<Fp3>> boundary_current = {
            std::vector<Fp3>(table.current_width, Fp3::Zero()),
            std::vector<Fp3>(table.current_width, Fp3::One())};
        std::vector<std::vector<Fp3>> boundary_next = {
            std::vector<Fp3>(table.next_width, Fp3::Zero()),
            std::vector<Fp3>(table.next_width, Fp3::One())};
        for (uint32_t row : {0U, n_rows / 2, n_rows - 1}) {
            std::vector<Fp3> cur, next;
            row_vectors(columns, row, cur, next);
            boundary_current.push_back(cur);
            boundary_next.push_back(next);
        }
        for (size_t b = 0; b < boundary_current.size(); ++b) {
            for (uint32_t i = 0; i < table.programs.size(); ++i) {
                const Fp3 native_value = native.constraints[i].eval(
                    boundary_current[b], boundary_next[b]);
                Fp3 interpreted;
                BOOST_REQUIRE(cb::EvaluateProgram(
                    table.programs[i], boundary_current[b],
                    boundary_next[b], interpreted));
                if (!gf::Eq(native_value, interpreted)) ++mismatches;
            }
        }
        BOOST_CHECK_EQUAL(mismatches, 0U);

        // (3) The REAL honest witness must satisfy every bytecode
        // constraint to exactly zero (not merely agree with the native
        // evaluator on an unconstrained point).
        uint32_t violations = 0;
        for (uint32_t row = 0; row < n_rows; ++row) {
            std::vector<Fp3> cur, next;
            row_vectors(columns, row, cur, next);
            for (const auto& prog : table.programs) {
                Fp3 value;
                BOOST_REQUIRE(
                    cb::EvaluateProgram(prog, cur, next, value));
                if (!gf::IsZero(value)) ++violations;
            }
        }
        BOOST_CHECK_EQUAL(violations, 0U);

        // (4) Forgery, sneaky variant: mutate the Constant(1) inside the
        // first constraint's EmitBool(v) = v*(v-1) to Constant(2). This
        // preserves every opcode/operand/degree (so ValidateProgram still
        // accepts the forged program structurally), but the SAME real
        // honest witness that satisfied every row of the honest program
        // must violate the forged one on at least one row (v*(v-1)==
        // v*(v-2) only when v==0; the honest bitstream is not all-zero),
        // and the committed table hash must change.
        cb::ProgramTable forged_constant = table;
        bool mutated_constant = false;
        for (auto& instr : forged_constant.programs.front().instructions) {
            if (instr.opcode == cb::Opcode::Constant &&
                gf::Eq(instr.constant, Fp3::One())) {
                instr.constant = gf::Add(instr.constant, Fp3::One());
                mutated_constant = true;
                break;
            }
        }
        BOOST_REQUIRE(mutated_constant);
        BOOST_CHECK(
            cb::CommitProgramTable(forged_constant) !=
            cb::CommitProgramTable(table));

        uint32_t forged_constant_violations = 0;
        for (uint32_t row = 0; row < n_rows; ++row) {
            std::vector<Fp3> cur, next;
            row_vectors(columns, row, cur, next);
            Fp3 value;
            BOOST_REQUIRE(cb::EvaluateProgram(
                forged_constant.programs.front(), cur, next, value));
            if (!gf::IsZero(value)) ++forged_constant_violations;
        }
        BOOST_CHECK_GT(forged_constant_violations, 0U);

        // (5) Forgery, structural variant: swapping the final Mul for Add
        // changes the program's raw SSA degree without touching
        // declared_degree, so ValidateProgram (invoked by EvaluateProgram)
        // must refuse it outright -- a stronger defense than a value-level
        // mismatch, defeating this class of bytecode tamper before any
        // witness is even evaluated.
        cb::ProgramTable forged_opcode = table;
        bool mutated_opcode = false;
        for (auto& instr : forged_opcode.programs.front().instructions) {
            if (instr.opcode == cb::Opcode::Mul) {
                instr.opcode = cb::Opcode::Add;
                mutated_opcode = true;
                break;
            }
        }
        BOOST_REQUIRE(mutated_opcode);
        BOOST_CHECK(
            cb::CommitProgramTable(forged_opcode) !=
            cb::CommitProgramTable(table));
        std::vector<Fp3> cur0, next0;
        row_vectors(columns, 0, cur0, next0);
        Fp3 forged_opcode_value;
        BOOST_CHECK(!cb::EvaluateProgram(
            forged_opcode.programs.front(), cur0, next0,
            forged_opcode_value));

        tables_this_run.push_back(table);
    }

    // Role separation: identical instructions across all four hash-kernel
    // roles, but every committed table hash differs (anti cross-role replay
    // now spans EpisodeTileTree/EpisodeDigest as well as CoupledBarrier/
    // CoupledDigest).
    cb::ProgramTable coupled_barrier;
    cb::ProgramTable coupled_digest;
    BOOST_REQUIRE(rc::BuildRCStage3CoupledHashKernelProgramTable(
        rc::RCStage3RelationRole::CoupledBarrier, coupled_barrier, &why));
    BOOST_REQUIRE(rc::BuildRCStage3CoupledHashKernelProgramTable(
        rc::RCStage3RelationRole::CoupledDigest, coupled_digest, &why));
    const std::vector<cb::ProgramTable> all_four{
        tables_this_run[0], tables_this_run[1], coupled_barrier,
        coupled_digest};
    for (size_t i = 0; i < all_four.size(); ++i) {
        BOOST_REQUIRE_EQUAL(
            all_four[i].programs.size(), all_four[0].programs.size());
        for (uint32_t p = 0; p < all_four[i].programs.size(); ++p) {
            BOOST_CHECK(
                all_four[i].programs[p].instructions ==
                all_four[0].programs[p].instructions);
        }
        for (size_t j = i + 1; j < all_four.size(); ++j) {
            BOOST_CHECK(
                cb::CommitProgramTable(all_four[i]) !=
                cb::CommitProgramTable(all_four[j]));
        }
    }

    // Roles with no DirectSha256d-style relation are still refused.
    cb::ProgramTable rejected;
    BOOST_CHECK(!rc::BuildRCStage3CoupledHashKernelProgramTable(
        rc::RCStage3RelationRole::EpisodeGemm, rejected, &why));
    BOOST_CHECK(!rc::BuildRCStage3CoupledHashKernelProgramTable(
        rc::RCStage3RelationRole::CoupledBank, rejected, &why));
}

BOOST_AUTO_TEST_SUITE_END()

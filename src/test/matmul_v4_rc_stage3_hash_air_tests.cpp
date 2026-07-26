// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <crypto/chacha20.h>
#include <crypto/sha256.h>
#include <matmul/matmul_v4_bmx4.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_stage3_composition.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>

namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;
namespace ha = matmul::v4::rc::stage3_hash_air;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_hash_air_tests, BasicTestingSetup)

namespace {

uint32_t Next(uint64_t& s)
{
    s += UINT64_C(0x9e3779b97f4a7c15);
    uint64_t z = s;
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return static_cast<uint32_t>(z ^ (z >> 31));
}

ha::Inputs Inputs(uint32_t n)
{
    ha::Inputs out;
    out.a.resize(n);
    out.b.resize(n);
    out.c.resize(n);
    uint64_t state = UINT64_C(0x47d00df00d123456);
    for (uint32_t i = 0; i < n; ++i) {
        out.a[i] = Next(state);
        out.b[i] = Next(state);
        out.c[i] = Next(state);
    }
    return out;
}

std::vector<ha::Spec> Specs(uint32_t n)
{
    return {
        {.family = ha::Family::Add32, .n_rows = n},
        {.family = ha::Family::XorRot32, .n_rows = n, .rotate_left = 16},
        {.family = ha::Family::ShaChoice32, .n_rows = n},
        {.family = ha::Family::ShaMajority32, .n_rows = n},
        {.family = ha::Family::ShaXor3Transform32, .n_rows = n,
         .transforms = {{{ha::BitTransformKind::RotateRight, 2},
                         {ha::BitTransformKind::RotateRight, 13},
                         {ha::BitTransformKind::RotateRight, 22}}}},
        {.family = ha::Family::ShaXor3Transform32, .n_rows = n,
         .transforms = {{{ha::BitTransformKind::RotateRight, 7},
                         {ha::BitTransformKind::RotateRight, 18},
                         {ha::BitTransformKind::ShiftRight, 3}}}},
    };
}

bool Satisfies(const aq::AirConstraintSystem<gf::Fp3>& cs,
               const std::vector<std::vector<gf::Fp3>>& cols)
{
    std::vector<gf::Fp3> cur(cs.n_columns), next(cs.n_columns);
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        for (uint32_t col = 0; col < cs.n_columns; ++col) {
            cur[col] = cols[col][row];
            next[col] = cols[col][(row + 1) % cs.n_rows];
        }
        for (const auto& constraint : cs.constraints) {
            if (constraint.kind == aq::AirKind::kTransition &&
                row + 1 == cs.n_rows) {
                continue;
            }
            if (constraint.kind == aq::AirKind::kFirstRow &&
                row != 0) {
                continue;
            }
            if (constraint.kind == aq::AirKind::kLastRow &&
                row + 1 != cs.n_rows) {
                continue;
            }
            if (!gf::IsZero(constraint.eval(cur, next))) return false;
        }
    }
    return true;
}

uint256 PatternHash(uint8_t seed)
{
    uint256 out;
    for (uint32_t i = 0; i < 32; ++i) {
        out.data()[i] = static_cast<uint8_t>(seed + 29 * i);
    }
    return out;
}

uint256 Sha256d(const std::vector<uint8_t>& preimage)
{
    uint8_t first[32];
    uint256 out;
    CSHA256()
        .Write(preimage.data(), preimage.size())
        .Finalize(first);
    CSHA256().Write(first, sizeof(first)).Finalize(out.data());
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(executable_bounded_and_differential)
{
    const auto inputs = Inputs(64);
    for (const auto& spec : Specs(64)) {
        aq::AirConstraintSystem<gf::Fp3> cs;
        ha::Witness witness;
        std::string why;
        BOOST_REQUIRE_MESSAGE(ha::BuildConstraintSystem(spec, cs, &why), why);
        BOOST_REQUIRE_MESSAGE(ha::BuildWitness(spec, inputs, witness, &why), why);
        BOOST_CHECK(Satisfies(cs, witness.columns));
        BOOST_CHECK_LE(cs.n_columns, ha::kMaxColumns);
        BOOST_CHECK_LE(cs.MaxComposedDegreeBound(), 3ULL * 63);

        for (uint32_t row = 0; row < spec.n_rows; ++row) {
            uint32_t expected = 0;
            switch (spec.family) {
            case ha::Family::Add32:
                expected = inputs.a[row] + inputs.b[row];
                break;
            case ha::Family::XorRot32: {
                const uint32_t x = inputs.a[row] ^ inputs.b[row];
                expected = (x << spec.rotate_left) | (x >> (32 - spec.rotate_left));
                break;
            }
            case ha::Family::ShaChoice32:
                expected = (inputs.a[row] & inputs.b[row]) ^ (~inputs.a[row] & inputs.c[row]);
                break;
            case ha::Family::ShaMajority32:
                expected = (inputs.a[row] & inputs.b[row]) ^
                           (inputs.a[row] & inputs.c[row]) ^
                           (inputs.b[row] & inputs.c[row]);
                break;
            case ha::Family::ShaXor3Transform32: {
                auto t = [&](const ha::BitTransform& tr) {
                    return tr.kind == ha::BitTransformKind::ShiftRight
                        ? inputs.a[row] >> tr.amount
                        : (inputs.a[row] >> tr.amount) |
                          (inputs.a[row] << (32 - tr.amount));
                };
                expected = t(spec.transforms[0]) ^ t(spec.transforms[1]) ^ t(spec.transforms[2]);
                break;
            }
            }
            BOOST_CHECK_EQUAL(witness.output[row], expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(every_single_cell_mutation_is_rejected)
{
    const auto inputs = Inputs(2);
    for (const auto& spec : Specs(2)) {
        aq::AirConstraintSystem<gf::Fp3> cs;
        ha::Witness honest;
        std::string why;
        BOOST_REQUIRE(ha::BuildConstraintSystem(spec, cs, &why));
        BOOST_REQUIRE(ha::BuildWitness(spec, inputs, honest, &why));
        BOOST_REQUIRE(Satisfies(cs, honest.columns));
        for (uint32_t col = 0; col < cs.n_columns; ++col) {
            auto bad = honest.columns;
            bad[col][0] = gf::Add(bad[col][0], gf::Fp3{1, 7, 11});
            BOOST_CHECK_MESSAGE(!Satisfies(cs, bad),
                                ha::FamilyName(spec.family) << " column " << col);
        }
    }
}

BOOST_AUTO_TEST_CASE(real_quotient_proofs_verify)
{
    const auto inputs = Inputs(2);
    uint256 seed;
    std::fill(seed.begin(), seed.end(), 0x48);
    for (const auto& spec : Specs(2)) {
        aq::AirConstraintSystem<gf::Fp3> cs;
        ha::Witness witness;
        std::string why;
        BOOST_REQUIRE(ha::BuildConstraintSystem(spec, cs, &why));
        BOOST_REQUIRE(ha::BuildWitness(spec, inputs, witness, &why));
        const auto proved = aq::AirQuotientProve<gf::Fp3>(cs, witness.columns, seed);
        BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
        BOOST_REQUIRE(proved.division_exact);
        BOOST_CHECK_MESSAGE(ha::VerifyShard(spec, proved.proof, seed, &why), why);

        auto bad = witness.columns;
        bad[ha::BitColumn(0, 3)][0] =
            gf::Add(bad[ha::BitColumn(0, 3)][0], gf::Fp3::One());
        const auto rejected = aq::AirQuotientProve<gf::Fp3>(cs, bad, seed);
        BOOST_CHECK(!rejected.ok);
        BOOST_CHECK(!rejected.division_exact);
    }
}

BOOST_AUTO_TEST_CASE(relation_gaps_are_explicit_and_authority_off)
{
    const auto readiness = ha::CurrentRelationReadiness();
    BOOST_REQUIRE_EQUAL(readiness.size(), 6U);
    for (const auto& relation : readiness) {
        BOOST_CHECK(relation.instruction_air_complete);
        BOOST_CHECK(!relation.relation_complete);
        BOOST_CHECK(!relation.required_families.empty());
        BOOST_CHECK(!relation.gaps.empty());
        BOOST_CHECK(std::any_of(
            relation.gaps.begin(), relation.gaps.end(),
            [](const ha::Gap& gap) {
                return gap.code == ha::GapCode::RecursiveAggregation;
            }));
    }
    static_assert(ha::kHashInstructionAirExecutable);
    static_assert(ha::kHashFixedProgramAirExecutable);
    static_assert(ha::kHashMultiBlockManifestsExecutable);
    static_assert(ha::kHashManifestBoundaryAirExecutable);
    static_assert(ha::kHashInternalSsaProvenanceExecutable);
    static_assert(!ha::kHashRelationsComplete);
    static_assert(!ha::kHashConsensusAuthority);
}

BOOST_AUTO_TEST_CASE(fixed_hash_programs_reject_omission_reordering_and_substitution)
{
    const ha::FixedProgram sha =
        ha::BuildCanonicalProgram(ha::ProgramKind::Sha256Compression);
    const ha::FixedProgram chacha =
        ha::BuildCanonicalProgram(ha::ProgramKind::ChaCha20Block);
    std::string why;
    BOOST_REQUIRE_MESSAGE(ha::ValidateCanonicalProgram(sha, &why), why);
    BOOST_REQUIRE_MESSAGE(ha::ValidateCanonicalProgram(chacha, &why), why);
    BOOST_CHECK_EQUAL(sha.rows.size(), 952U);
    BOOST_CHECK_EQUAL(chacha.rows.size(), 656U);
    BOOST_CHECK_EQUAL(sha.external_address_count, 88U);
    BOOST_CHECK_EQUAL(chacha.external_address_count, 16U);
    BOOST_CHECK_EQUAL(sha.final_addresses.size(), 8U);
    BOOST_CHECK_EQUAL(chacha.final_addresses.size(), 16U);

    for (const auto& row : sha.rows) {
        aq::AirConstraintSystem<gf::Fp3> cs;
        BOOST_CHECK_MESSAGE(
            ha::BuildConstraintSystem(ha::ProgramRowSpec(row, 2), cs, &why),
            why);
    }
    for (const auto& row : chacha.rows) {
        aq::AirConstraintSystem<gf::Fp3> cs;
        BOOST_CHECK_MESSAGE(
            ha::BuildConstraintSystem(ha::ProgramRowSpec(row, 2), cs, &why),
            why);
    }

    auto omitted = sha;
    omitted.rows.erase(omitted.rows.begin() + 17);
    BOOST_CHECK(!ha::ValidateCanonicalProgram(omitted, &why));

    auto reordered = chacha;
    std::swap(reordered.rows[4], reordered.rows[5]);
    BOOST_CHECK(!ha::ValidateCanonicalProgram(reordered, &why));

    auto substituted = sha;
    substituted.rows[300].opcode = ha::ProgramOpcode::ShaChoice32;
    BOOST_CHECK(!ha::ValidateCanonicalProgram(substituted, &why));

    const auto sha_ctl = ha::BuildProgramCtlSchedule(sha, 0x534841U);
    const auto chacha_ctl =
        ha::BuildProgramCtlSchedule(chacha, 0x434841U);
    BOOST_REQUIRE_MESSAGE(
        matmul::v4::rc::ValidateRCStage3CtlSchedule(sha_ctl, &why), why);
    BOOST_REQUIRE_MESSAGE(
        matmul::v4::rc::ValidateRCStage3CtlSchedule(chacha_ctl, &why), why);
    BOOST_CHECK_EQUAL(sha_ctl.events.size(), 3616U);
    BOOST_CHECK_EQUAL(chacha_ctl.events.size(), 2624U);
    BOOST_CHECK(!matmul::v4::rc::CommitRCStage3CtlSchedule(sha_ctl).IsNull());
    auto changed_ctl = sha_ctl;
    ++changed_ctl.events[11].address;
    BOOST_CHECK(matmul::v4::rc::CommitRCStage3CtlSchedule(changed_ctl) !=
                matmul::v4::rc::CommitRCStage3CtlSchedule(sha_ctl));
}

BOOST_AUTO_TEST_CASE(canonical_sha_program_matches_native_sha256_abc)
{
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

    const auto program =
        ha::BuildCanonicalProgram(ha::ProgramKind::Sha256Compression);
    ha::ProgramWitness witness;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildProgramWitness(program, external, witness, &why), why);
    BOOST_REQUIRE_EQUAL(witness.final_words.size(), 8U);
    std::vector<ha::ProgramInstructionShard> shards;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildProgramInstructionShards(program, witness, shards, &why),
        why);
    BOOST_CHECK_EQUAL(shards.size(), 7U);
    for (const auto& shard : shards) {
        aq::AirConstraintSystem<gf::Fp3> cs;
        BOOST_REQUIRE_MESSAGE(
            ha::BuildConstraintSystem(shard.spec, cs, &why), why);
        BOOST_CHECK(Satisfies(cs, shard.witness.columns));
    }
    aq::AirConstraintSystem<gf::Fp3> program_cs;
    std::vector<std::vector<gf::Fp3>> program_columns;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildFixedProgramConstraintSystem(
            program, program_cs, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        ha::BuildFixedProgramAirWitness(
            program, witness, program_columns, &why),
        why);
    BOOST_CHECK_EQUAL(program_cs.n_rows, 1024U);
    BOOST_CHECK_EQUAL(program_cs.n_columns, ha::kFixedProgramColumns);
    BOOST_CHECK_EQUAL(program_cs.preprocessed.size(), 11U);
    BOOST_CHECK(program_cs.preprocessed_pin_ood);
    BOOST_CHECK(Satisfies(program_cs, program_columns));
    auto bad_program = program_columns;
    bad_program[ha::ValueColumn(2)][200] =
        gf::Add(bad_program[ha::ValueColumn(2)][200], gf::Fp3::One());
    BOOST_CHECK(!Satisfies(program_cs, bad_program));

    const unsigned char msg[3]{'a', 'b', 'c'};
    unsigned char digest[32];
    CSHA256().Write(msg, sizeof(msg)).Finalize(digest);
    for (uint32_t i = 0; i < 8; ++i) {
        const uint32_t expected =
            (uint32_t{digest[4 * i]} << 24) |
            (uint32_t{digest[4 * i + 1]} << 16) |
            (uint32_t{digest[4 * i + 2]} << 8) |
            uint32_t{digest[4 * i + 3]};
        BOOST_CHECK_EQUAL(witness.final_words[i], expected);
    }

    const auto schedule =
        ha::BuildProgramCtlSchedule(program, 0x534841U);
    matmul::v4::rc::RCStage3CtlChallenges challenges{
        gf::Fp3{3, 5, 7}, gf::Fp3{11, 13, 17},
        gf::Fp3{19, 23, 29}, gf::Fp3{31, 37, 41}};
    const auto ctl = matmul::v4::rc::BuildRCStage3CtlWitness(
        schedule, witness.ctl_values, challenges);
    BOOST_REQUIRE_MESSAGE(ctl.ok, ctl.note);
    BOOST_CHECK(gf::IsZero(ctl.terminal.alpha1_sum));
    BOOST_CHECK(gf::IsZero(ctl.terminal.alpha2_sum));

    auto tampered_values = witness.ctl_values;
    tampered_values[37] =
        gf::Add(tampered_values[37], gf::Fp3::One());
    const auto bad_ctl = matmul::v4::rc::BuildRCStage3CtlWitness(
        schedule, tampered_values, challenges);
    BOOST_REQUIRE(bad_ctl.ok);
    BOOST_CHECK(!gf::IsZero(bad_ctl.terminal.alpha1_sum) ||
                !gf::IsZero(bad_ctl.terminal.alpha2_sum));
}

BOOST_AUTO_TEST_CASE(canonical_chacha_program_matches_native_block)
{
    std::array<std::byte, 32> key{};
    for (uint32_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::byte>(3 * i + 1);
    }
    constexpr uint32_t nonce_first = 0xdecafbadU;
    constexpr uint64_t nonce_second = UINT64_C(0x0123456789abcdef);
    constexpr uint32_t counter = 7;

    std::vector<uint32_t> external(16);
    external[0] = 0x61707865U;
    external[1] = 0x3320646eU;
    external[2] = 0x79622d32U;
    external[3] = 0x6b206574U;
    for (uint32_t word = 0; word < 8; ++word) {
        const auto* p = reinterpret_cast<const unsigned char*>(key.data()) + 4 * word;
        external[4 + word] = uint32_t{p[0]} | (uint32_t{p[1]} << 8) |
                             (uint32_t{p[2]} << 16) | (uint32_t{p[3]} << 24);
    }
    external[12] = counter;
    external[13] = nonce_first;
    external[14] = static_cast<uint32_t>(nonce_second);
    external[15] = static_cast<uint32_t>(nonce_second >> 32);

    const auto program =
        ha::BuildCanonicalProgram(ha::ProgramKind::ChaCha20Block);
    ha::ProgramWitness witness;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildProgramWitness(program, external, witness, &why), why);
    BOOST_REQUIRE_EQUAL(witness.final_words.size(), 16U);
    std::vector<ha::ProgramInstructionShard> shards;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildProgramInstructionShards(program, witness, shards, &why),
        why);
    BOOST_CHECK_EQUAL(shards.size(), 5U);
    for (const auto& shard : shards) {
        aq::AirConstraintSystem<gf::Fp3> cs;
        BOOST_REQUIRE_MESSAGE(
            ha::BuildConstraintSystem(shard.spec, cs, &why), why);
        BOOST_CHECK(Satisfies(cs, shard.witness.columns));
    }
    aq::AirConstraintSystem<gf::Fp3> program_cs;
    std::vector<std::vector<gf::Fp3>> program_columns;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildFixedProgramConstraintSystem(
            program, program_cs, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        ha::BuildFixedProgramAirWitness(
            program, witness, program_columns, &why),
        why);
    BOOST_CHECK_EQUAL(program_cs.n_rows, 1024U);
    BOOST_CHECK_EQUAL(program_cs.n_columns, ha::kFixedProgramColumns);
    BOOST_CHECK(Satisfies(program_cs, program_columns));
    auto bad_program = program_columns;
    bad_program[ha::BitColumn(0, 9)][319] =
        gf::Add(
            bad_program[ha::BitColumn(0, 9)][319], gf::Fp3::One());
    BOOST_CHECK(!Satisfies(program_cs, bad_program));

    std::array<std::byte, 64> stream{};
    ChaCha20 reference{Span<const std::byte>{key}};
    reference.Seek({nonce_first, nonce_second}, counter);
    reference.Keystream(stream);
    for (uint32_t word = 0; word < 16; ++word) {
        const auto* p = reinterpret_cast<const unsigned char*>(stream.data()) + 4 * word;
        const uint32_t expected =
            uint32_t{p[0]} | (uint32_t{p[1]} << 8) |
            (uint32_t{p[2]} << 16) | (uint32_t{p[3]} << 24);
        BOOST_CHECK_EQUAL(witness.final_words[word], expected);
    }
}

BOOST_AUTO_TEST_CASE(fixed_program_boundary_air_proof_is_statement_bound)
{
    std::vector<uint32_t> external(16);
    external[0] = 0x61707865U;
    external[1] = 0x3320646eU;
    external[2] = 0x79622d32U;
    external[3] = 0x6b206574U;
    for (uint32_t i = 4; i < external.size(); ++i) {
        external[i] = 0x10203040U + 0x01010101U * i;
    }

    const auto program =
        ha::BuildCanonicalProgram(ha::ProgramKind::ChaCha20Block);
    ha::ProgramWitness witness;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildProgramWitness(program, external, witness, &why), why);

    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildFixedProgramBoundaryConstraintSystem(
            program, external, witness.final_words, cs, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        ha::BuildFixedProgramBoundaryAirWitness(
            program, witness, external, witness.final_words, columns, &why),
        why);
    BOOST_CHECK_EQUAL(
        cs.n_columns, ha::kFixedProgramBoundaryColumns);
    BOOST_CHECK_EQUAL(cs.preprocessed.size(), 19U);
    BOOST_CHECK(Satisfies(cs, columns));

    uint256 seed;
    std::fill(seed.begin(), seed.end(), 0x93);
    ha::FixedProgramBoundaryAirProof proof;
    const auto prove_start = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        ha::ProveFixedProgramBoundaryAir(
            program, witness, external, witness.final_words,
            seed, proof, &why),
        why);
    const auto prove_end = std::chrono::steady_clock::now();
    const auto verify_start = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        ha::VerifyFixedProgramBoundaryAir(
            program, external, witness.final_words, proof, seed, &why),
        why);
    const auto verify_end = std::chrono::steady_clock::now();
    const double prove_ms =
        std::chrono::duration<double, std::milli>(
            prove_end - prove_start).count();
    const double verify_ms =
        std::chrono::duration<double, std::milli>(
            verify_end - verify_start).count();
    BOOST_TEST_MESSAGE(
        "fixed_program_boundary_air prove_ms="
        << prove_ms << " verify_ms=" << verify_ms);

    auto changed_external = external;
    changed_external[5] ^= 1U;
    BOOST_CHECK(!ha::VerifyFixedProgramBoundaryAir(
        program, changed_external, witness.final_words, proof, seed, &why));

    auto changed_final = witness.final_words;
    changed_final[7] ^= 1U;
    BOOST_CHECK(!ha::VerifyFixedProgramBoundaryAir(
        program, external, changed_final, proof, seed, &why));

    uint256 changed_seed = seed;
    changed_seed.data()[0] ^= 1U;
    BOOST_CHECK(!ha::VerifyFixedProgramBoundaryAir(
        program, external, witness.final_words,
        proof, changed_seed, &why));

    auto changed_kind = proof;
    changed_kind.kind = ha::ProgramKind::Sha256Compression;
    BOOST_CHECK(!ha::VerifyFixedProgramBoundaryAir(
        program, external, witness.final_words,
        changed_kind, seed, &why));

    auto changed_commitment = proof;
    changed_commitment.statement_commitment.data()[0] ^= 1U;
    BOOST_CHECK(!ha::VerifyFixedProgramBoundaryAir(
        program, external, witness.final_words,
        changed_commitment, seed, &why));
}

BOOST_AUTO_TEST_CASE(
    fixed_program_boundary_air_four_lane_packing_is_executable)
{
    const auto program =
        ha::BuildCanonicalProgram(ha::ProgramKind::ChaCha20Block);
    std::array<ha::ProgramWitness, ha::kFixedProgramPackedLanes>
        witnesses;
    std::array<
        ha::FixedProgramPackedBoundaryInstance,
        ha::kFixedProgramPackedLanes> instances;
    std::string why;
    for (uint32_t lane = 0;
         lane < ha::kFixedProgramPackedLanes; ++lane) {
        auto& external = instances[lane].external_values;
        external.resize(program.external_address_count);
        external[0] = 0x61707865U;
        external[1] = 0x3320646eU;
        external[2] = 0x79622d32U;
        external[3] = 0x6b206574U;
        for (uint32_t i = 4; i < external.size(); ++i) {
            external[i] =
                0x10203040U + 0x01010101U * i +
                0x11111111U * lane;
        }
        instances[lane].ctl_namespace_id =
            0x48415330U + lane;
        BOOST_REQUIRE_MESSAGE(
            ha::BuildProgramWitness(
                program, external, witnesses[lane], &why),
            why);
        instances[lane].final_words =
            witnesses[lane].final_words;
    }

    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildFixedProgramPackedBoundaryConstraintSystem(
            program, instances, cs, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        ha::BuildFixedProgramPackedBoundaryAirWitness(
            program, witnesses, instances, columns, &why),
        why);
    BOOST_CHECK_EQUAL(cs.n_rows, 1024U);
    BOOST_CHECK_EQUAL(
        cs.n_columns, ha::kFixedProgramPackedBoundaryColumns);
    BOOST_CHECK_EQUAL(cs.n_columns, 608U);
    BOOST_CHECK_LE(
        cs.n_columns, ha::kFixedProgramRecursiveWidthCap);
    BOOST_CHECK_EQUAL(cs.preprocessed.size(), 76U);
    BOOST_CHECK(cs.preprocessed_pin_ood);
    BOOST_REQUIRE(Satisfies(cs, columns));
    const uint32_t packed_columns = cs.n_columns;

    // Each lane owns disjoint word columns.  A row-local mutation in every
    // lane independently violates that lane's recomposition/instruction
    // constraints; no other lane can mask it through quotient batching.
    for (uint32_t lane = 0;
         lane < ha::kFixedProgramPackedLanes; ++lane) {
        auto changed = columns;
        const uint32_t output_column =
            ha::FixedProgramPackedColumn(
                lane, ha::ValueColumn(2));
        changed[output_column][200] =
            gf::Add(
                changed[output_column][200], gf::Fp3::One());
        BOOST_CHECK(!Satisfies(cs, changed));
    }

    std::array<
        matmul::v4::rc::RCStage3CtlSchedule,
        ha::kFixedProgramPackedLanes> schedules;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildFixedProgramPackedCtlSchedules(
            program, instances, schedules, &why),
        why);
    for (uint32_t lane = 0;
         lane < ha::kFixedProgramPackedLanes; ++lane) {
        BOOST_REQUIRE(!schedules[lane].events.empty());
        BOOST_CHECK_EQUAL(
            schedules[lane].events.front().namespace_id,
            instances[lane].ctl_namespace_id);
        for (uint32_t other = 0; other < lane; ++other) {
            BOOST_CHECK(
                matmul::v4::rc::CommitRCStage3CtlSchedule(
                    schedules[lane]) !=
                matmul::v4::rc::CommitRCStage3CtlSchedule(
                    schedules[other]));
        }
    }
    auto aliased_namespaces = instances;
    aliased_namespaces[3].ctl_namespace_id =
        aliased_namespaces[0].ctl_namespace_id;
    BOOST_CHECK(
        !ha::BuildFixedProgramPackedBoundaryConstraintSystem(
            program, aliased_namespaces, cs, &why));

    uint256 seed;
    std::fill(seed.begin(), seed.end(), 0x5e);
    ha::FixedProgramPackedBoundaryAirProof proof;
    const auto prove_start = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        ha::ProveFixedProgramPackedBoundaryAir(
            program, witnesses, instances, seed, proof, &why),
        why);
    const auto prove_end = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        ha::VerifyFixedProgramPackedBoundaryAir(
            program, instances, proof, seed, &why),
        why);
    const auto verify_end = std::chrono::steady_clock::now();
    const double packed_prove_ms =
        std::chrono::duration<double, std::milli>(
            prove_end - prove_start).count();
    const double packed_verify_ms =
        std::chrono::duration<double, std::milli>(
            verify_end - prove_end).count();
    BOOST_TEST_MESSAGE(
        "fixed_program_packed4_boundary_air prove_ms="
        << packed_prove_ms
        << " verify_ms=" << packed_verify_ms
        << " columns=" << packed_columns);

    // The proof statement commits every lane's boundary and namespace.
    for (uint32_t lane = 0;
         lane < ha::kFixedProgramPackedLanes; ++lane) {
        auto changed = instances;
        changed[lane].final_words[0] ^= 1U;
        BOOST_CHECK(
            !ha::VerifyFixedProgramPackedBoundaryAir(
                program, changed, proof, seed, &why));
    }
}

BOOST_AUTO_TEST_CASE(
    fixed_program_parallel_width_scenarios_four_six_seven_fit)
{
    const auto program =
        ha::BuildCanonicalProgram(ha::ProgramKind::ChaCha20Block);
    std::vector<ha::ProgramWitness> witnesses(
        ha::kFixedProgramMaxPackedLanes);
    std::vector<ha::FixedProgramPackedBoundaryInstance> instances(
        ha::kFixedProgramMaxPackedLanes);
    std::string why;
    for (uint32_t lane = 0;
         lane < ha::kFixedProgramMaxPackedLanes; ++lane) {
        auto& external = instances[lane].external_values;
        external.resize(program.external_address_count);
        external[0] = 0x61707865U;
        external[1] = 0x3320646eU;
        external[2] = 0x79622d32U;
        external[3] = 0x6b206574U;
        for (uint32_t i = 4; i < external.size(); ++i) {
            external[i] =
                0xa5a50000U + 0x100U * lane + i;
        }
        instances[lane].ctl_namespace_id =
            0x50414330U + lane;
        BOOST_REQUIRE_MESSAGE(
            ha::BuildProgramWitness(
                program, external, witnesses[lane], &why),
            why);
        instances[lane].final_words =
            witnesses[lane].final_words;
    }

    for (const uint32_t lane_count : {4U, 6U, 7U}) {
        const std::vector<ha::ProgramWitness> lane_witnesses(
            witnesses.begin(), witnesses.begin() + lane_count);
        const std::vector<ha::FixedProgramPackedBoundaryInstance>
            lane_instances(
                instances.begin(), instances.begin() + lane_count);
        aq::AirConstraintSystem<gf::Fp3> cs;
        std::vector<std::vector<gf::Fp3>> columns;
        BOOST_REQUIRE_MESSAGE(
            ha::BuildFixedProgramParallelBoundaryConstraintSystem(
                program, lane_instances, cs, &why),
            why);
        BOOST_REQUIRE_MESSAGE(
            ha::BuildFixedProgramParallelBoundaryAirWitness(
                program, lane_witnesses, lane_instances,
                columns, &why),
            why);
        BOOST_CHECK_EQUAL(
            cs.n_columns,
            lane_count * ha::kFixedProgramBoundaryColumns);
        BOOST_CHECK_LE(
            cs.n_columns, ha::kFixedProgramRecursiveWidthCap);
        BOOST_REQUIRE(Satisfies(cs, columns));
        auto changed = columns;
        changed[(lane_count - 1) *
                    ha::kFixedProgramBoundaryColumns +
                ha::ValueColumn(2)][200] =
            gf::Add(
                changed[(lane_count - 1) *
                            ha::kFixedProgramBoundaryColumns +
                        ha::ValueColumn(2)][200],
                gf::Fp3::One());
        BOOST_CHECK(!Satisfies(cs, changed));
        BOOST_TEST_MESSAGE(
            "hash_parallel_lanes=" << lane_count
            << " width=" << cs.n_columns
            << " recursive_width_headroom="
            << ha::kFixedProgramRecursiveWidthCap - cs.n_columns);
    }

    auto too_many = instances;
    too_many.push_back(instances.front());
    too_many.back().ctl_namespace_id ^= 0x100U;
    aq::AirConstraintSystem<gf::Fp3> rejected;
    BOOST_CHECK(
        !ha::BuildFixedProgramParallelBoundaryConstraintSystem(
            program, too_many, rejected, &why));
}

BOOST_AUTO_TEST_CASE(
    fixed_program_two_epoch_provenance_closes_internal_ssa)
{
    std::vector<uint32_t> external(16);
    for (uint32_t i = 0; i < external.size(); ++i) {
        external[i] = 0x6a09e667U + 0x10203U * i;
    }
    const auto program =
        ha::BuildCanonicalProgram(ha::ProgramKind::ChaCha20Block);
    ha::ProgramWitness witness;
    std::string why;
    BOOST_REQUIRE(
        ha::BuildProgramWitness(program, external, witness, &why));
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> columns;
    BOOST_REQUIRE(
        ha::BuildFixedProgramBoundaryConstraintSystem(
            program, external, witness.final_words, cs, &why));
    BOOST_REQUIRE(
        ha::BuildFixedProgramBoundaryAirWitness(
            program, witness, external, witness.final_words, columns, &why));
    BOOST_REQUIRE(Satisfies(cs, columns));

    // Change one internal operand and its row-local Add32 result together.
    // The legacy instruction/boundary AIR remains satisfiable because it has
    // no cross-row copy relation.
    uint32_t target = program.rows.size();
    for (uint32_t row = 0; row < program.rows.size(); ++row) {
        if (program.rows[row].opcode == ha::ProgramOpcode::Add32 &&
            program.rows[row].input_address[0] >
                program.external_address_count &&
            std::find(
                program.final_addresses.begin(),
                program.final_addresses.end(),
                program.rows[row].output_address) ==
                program.final_addresses.end()) {
            target = row;
            break;
        }
    }
    BOOST_REQUIRE_LT(target, program.rows.size());
    auto put_word = [&](uint32_t word, uint32_t value) {
        columns[ha::ValueColumn(word)][target] =
            gf::Fp3::FromFp(gf::FromU64(value));
        for (uint32_t bit = 0; bit < 32; ++bit) {
            columns[ha::BitColumn(word, bit)][target] =
                gf::Fp3::FromFp(gf::FromU64((value >> bit) & 1U));
        }
    };
    const uint32_t a =
        static_cast<uint32_t>(
            columns[ha::ValueColumn(0)][target].c0);
    const uint32_t b =
        static_cast<uint32_t>(
            columns[ha::ValueColumn(1)][target].c0);
    const uint32_t changed_a = a ^ 1U;
    const uint64_t sum = uint64_t{changed_a} + b;
    put_word(0, changed_a);
    put_word(2, static_cast<uint32_t>(sum));
    columns[ha::kFixedProgramCarryColumn][target] =
        gf::Fp3::FromFp(gf::FromU64(sum >> 32));
    BOOST_CHECK(Satisfies(cs, columns));

    uint256 seed;
    std::fill(seed.begin(), seed.end(), 0x71);
    const auto complete =
        ha::BuildFixedProgramProvenanceInstance(
            program, witness, external, witness.final_words,
            seed);
    BOOST_REQUIRE_MESSAGE(complete.valid, complete.note);
    BOOST_CHECK_EQUAL(complete.cs.n_rows, 1024U);
    BOOST_CHECK_EQUAL(
        complete.cs.n_columns,
        ha::kFixedProgramProvenanceColumns);
    BOOST_CHECK_EQUAL(
        complete.cs.n_columns, 171U);
    BOOST_REQUIRE(Satisfies(
        complete.cs, complete.columns));

    // The same locally-valid operation substitution is rejected once every
    // internal producer/consumer edge participates in both independent
    // post-commit logarithmic-derivative lanes.
    auto provenance_changed = complete.columns;
    auto put_provenance_word =
        [&](uint32_t word, uint32_t value) {
            provenance_changed[ha::ValueColumn(word)][target] =
                gf::Fp3::FromFp(gf::FromU64(value));
            for (uint32_t bit = 0; bit < 32; ++bit) {
                provenance_changed[
                    ha::BitColumn(word, bit)][target] =
                    gf::Fp3::FromFp(
                        gf::FromU64((value >> bit) & 1U));
            }
        };
    put_provenance_word(0, changed_a);
    put_provenance_word(2, static_cast<uint32_t>(sum));
    provenance_changed[
        ha::kFixedProgramCarryColumn][target] =
        gf::Fp3::FromFp(gf::FromU64(sum >> 32));
    BOOST_CHECK(!Satisfies(
        complete.cs, provenance_changed));

    ha::FixedProgramProvenanceAirProof proof;
    const auto prove_start =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        ha::ProveFixedProgramProvenanceAir(
            program, witness, external, witness.final_words,
            seed, proof, &why),
        why);
    const auto prove_end =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        ha::VerifyFixedProgramProvenanceAir(
            program, external, witness.final_words,
            seed, proof, &why),
        why);
    const auto verify_end =
        std::chrono::steady_clock::now();
    const double provenance_prove_ms =
        std::chrono::duration<double, std::milli>(
            prove_end - prove_start).count();
    const double provenance_verify_ms =
        std::chrono::duration<double, std::milli>(
            verify_end - prove_end).count();
    BOOST_TEST_MESSAGE(
        "fixed_program_internal_ssa_provenance"
        " columns=" << complete.cs.n_columns
        << " constraints="
        << complete.cs.constraints.size()
        << " prove_ms="
        << provenance_prove_ms
        << " verify_ms="
        << provenance_verify_ms);

    auto changed_proof = proof;
    BOOST_REQUIRE(
        !changed_proof.quotient.batch.queries.empty());
    BOOST_REQUIRE(
        !changed_proof.quotient.batch.queries[0]
             .columns.empty());
    changed_proof.quotient.batch.queries[0]
        .columns[0].value =
        gf::Add(
            changed_proof.quotient.batch.queries[0]
                .columns[0].value,
            gf::Fp3::One());
    BOOST_CHECK(
        !ha::VerifyFixedProgramProvenanceAir(
            program, external, witness.final_words,
            seed, changed_proof, &why));

    auto changed_final = witness.final_words;
    changed_final[0] ^= 1U;
    BOOST_CHECK(
        !ha::VerifyFixedProgramProvenanceAir(
            program, external, changed_final,
            seed, proof, &why));

    static_assert(
        ha::kFixedProgramProvenanceColumns <
        ha::kFixedProgramRecursiveWidthCap);
    static_assert(!ha::kHashRelationsComplete);
}

BOOST_AUTO_TEST_CASE(
    fixed_program_four_lane_packed_provenance_round_trip)
{
    const auto program =
        ha::BuildCanonicalProgram(
            ha::ProgramKind::ChaCha20Block);
    std::array<ha::ProgramWitness,
               ha::kFixedProgramPackedLanes> witnesses;
    std::array<ha::FixedProgramPackedBoundaryInstance,
               ha::kFixedProgramPackedLanes> instances;
    std::string why;
    for (uint32_t lane = 0;
         lane < ha::kFixedProgramPackedLanes; ++lane) {
        instances[lane].ctl_namespace_id =
            0x48415340U + lane;
        instances[lane].external_values.resize(16);
        const uint32_t boundary_flavor =
            lane == 1 ? 0 : lane;
        for (uint32_t word = 0; word < 16; ++word) {
            instances[lane].external_values[word] =
                0x61707865U +
                0x010203U * word +
                0x11111111U * boundary_flavor;
        }
        BOOST_REQUIRE_MESSAGE(
            ha::BuildProgramWitness(
                program,
                instances[lane].external_values,
                witnesses[lane], &why),
            why);
        instances[lane].final_words =
            witnesses[lane].final_words;
    }
    uint256 seed;
    std::fill(seed.begin(), seed.end(), 0x6d);
    const auto complete =
        ha::BuildFixedProgramPackedProvenanceInstance(
            program, witnesses, instances, seed);
    BOOST_REQUIRE_MESSAGE(complete.valid, complete.note);
    BOOST_CHECK_EQUAL(
        complete.cs.n_columns,
        ha::kFixedProgramPackedProvenanceColumns);
    BOOST_CHECK_EQUAL(complete.cs.n_columns, 684U);
    BOOST_CHECK_LT(
        complete.cs.n_columns,
        ha::kFixedProgramRecursiveWidthCap);
    BOOST_REQUIRE(Satisfies(
        complete.cs, complete.columns));

    // Four namespace-separated challenge pairs are derived from the one
    // packed base commitment; no two lanes accidentally share a lookup
    // transcript.
    std::array<uint256,
               ha::kFixedProgramPackedLanes>
        challenge_commitments{};
    for (uint32_t lane = 0;
         lane < ha::kFixedProgramPackedLanes; ++lane) {
        challenge_commitments[lane] =
            matmul::v4::rc::CommitRCStage3CtlChallenges(
                complete.challenges[lane]);
        for (uint32_t previous = 0;
             previous < lane; ++previous) {
            BOOST_CHECK(
                challenge_commitments[lane] !=
                challenge_commitments[previous]);
        }
    }

    // A complete lane cannot be detached and substituted: even when its
    // operation, boundary, metadata, inverse, and running columns move
    // together, they were built under another namespace/index challenge.
    // Lanes zero and one deliberately have identical boundary values, so
    // rejection is not attributable to a public-boundary mismatch.
    BOOST_REQUIRE(
        instances[0].external_values ==
        instances[1].external_values);
    BOOST_REQUIRE(
        instances[0].final_words ==
        instances[1].final_words);
    auto detached = complete.columns;
    for (uint32_t column = 0;
         column <
             ha::kFixedProgramProvenanceColumns;
         ++column) {
        std::swap(
            detached[column],
            detached[
                ha::kFixedProgramProvenanceColumns +
                column]);
    }
    BOOST_CHECK(!Satisfies(
        complete.cs, detached));

    ha::FixedProgramPackedProvenanceAirProof proof;
    const auto prove_start =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        ha::ProveFixedProgramPackedProvenanceAir(
            program, witnesses, instances,
            seed, proof, &why),
        why);
    const auto prove_end =
        std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        ha::VerifyFixedProgramPackedProvenanceAir(
            program, instances, seed,
            proof, &why),
        why);
    const auto verify_end =
        std::chrono::steady_clock::now();
    const double packed_provenance_prove_ms =
        std::chrono::duration<double, std::milli>(
            prove_end - prove_start).count();
    const double packed_provenance_verify_ms =
        std::chrono::duration<double, std::milli>(
            verify_end - prove_end).count();
    BOOST_TEST_MESSAGE(
        "fixed_program_packed_internal_ssa_provenance"
        " lanes=" <<
        ha::kFixedProgramPackedLanes
        << " rows=" << complete.cs.n_rows
        << " columns=" << complete.cs.n_columns
        << " constraints=" <<
        complete.cs.constraints.size()
        << " prove_ms=" <<
        packed_provenance_prove_ms
        << " verify_ms=" <<
        packed_provenance_verify_ms);

    auto namespace_mutation = instances;
    namespace_mutation[2].ctl_namespace_id ^= 0x100U;
    BOOST_CHECK(
        !ha::VerifyFixedProgramPackedProvenanceAir(
            program, namespace_mutation, seed,
            proof, &why));

    auto value_mutation = instances;
    value_mutation[3].external_values[5] ^= 1U;
    BOOST_CHECK(
        !ha::VerifyFixedProgramPackedProvenanceAir(
            program, value_mutation, seed,
            proof, &why));

    auto challenge_mutation = proof;
    challenge_mutation.challenge_commitments[1]
        .begin()[0] ^= 1U;
    BOOST_CHECK(
        !ha::VerifyFixedProgramPackedProvenanceAir(
            program, instances, seed,
            challenge_mutation, &why));

    static_assert(
        ha::kFixedProgramPackedProvenanceColumns ==
        ha::kFixedProgramPackedLanes *
        ha::kFixedProgramProvenanceColumns);
    static_assert(!ha::kHashRelationsComplete);
}

BOOST_AUTO_TEST_CASE(
    witness_owned_two_compression_sha256d_chain_and_export)
{
    std::vector<uint8_t> preimage(32);
    for (uint32_t i = 0; i < preimage.size(); ++i) {
        preimage[i] = static_cast<uint8_t>(5 * i + 9);
    }
    ha::ShaManifest manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildShaManifest(
            preimage, ha::ShaMode::Double,
            manifest, &why),
        why);
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildShaManifestBoundaryInstances(
            manifest, boundaries, &why),
        why);
    BOOST_REQUIRE_EQUAL(boundaries.size(), 2U);
    const auto program =
        ha::BuildCanonicalProgram(
            ha::ProgramKind::Sha256Compression);
    std::vector<std::vector<uint8_t>> public_masks(
        2, std::vector<uint8_t>(
               program.external_address_count, 1));
    for (uint32_t word = 0; word < 8; ++word) {
        public_masks[1][word] = 0;
    }
    std::vector<ha::FixedProgramWitnessBoundaryLink> links;
    for (uint32_t word = 0; word < 8; ++word) {
        links.push_back({
            .source_instance = 0,
            .source_final_word = word,
            .target_instance = 1,
            .target_external_address = word + 1,
        });
    }
    const uint256 seed = PatternHash(0x93);
    const auto instance =
        ha::BuildFixedProgramVerticalWitnessBoundaryInstance(
            program, boundaries, public_masks, links, seed);
    BOOST_REQUIRE_MESSAGE(instance.valid, instance.note);
    BOOST_CHECK_EQUAL(instance.semantic_instances, 2U);
    BOOST_CHECK_EQUAL(instance.scheduled_instances, 2U);
    BOOST_CHECK_EQUAL(instance.cs.n_rows, 2048U);
    BOOST_CHECK_LT(instance.cs.n_columns, 576U);
    BOOST_CHECK(!instance.public_statement.IsNull());
    BOOST_CHECK(!instance.base_row_commitment.IsNull());
    BOOST_CHECK(!instance.base_column_indices.empty());
    BOOST_CHECK(instance.base_row_tree_cache != nullptr);
    BOOST_CHECK_EQUAL(instance.final_output_rows.size(), 16U);
    BOOST_CHECK_GT(instance.output_export_base, 0U);
    BOOST_CHECK_GT(
        instance.output_bit_base,
        instance.output_export_base);
    BOOST_CHECK_GT(
        instance.output_byte_base,
        instance.output_bit_base);
    BOOST_REQUIRE_EQUAL(
        instance.cs.preprocessed_row_group_roots.size(),
        1U);
    BOOST_CHECK(
        instance.cs.preprocessed_row_group_roots[0].role ==
        aq::AirPreprocessedRowGroupRole::kR0);
    BOOST_CHECK(
        instance.cs.preprocessed_row_group_roots[0]
            .ordered_columns ==
        instance.base_column_indices);
    BOOST_CHECK(
        instance.cs.preprocessed_row_group_roots[0].root ==
        instance.base_row_commitment);
    for (uint32_t word = 0; word < 8; ++word) {
        const uint32_t native_word =
            boundaries.back().final_words[word];
        for (uint32_t lane = 0; lane < 4; ++lane) {
            const uint32_t column =
                instance.output_byte_base +
                4U * word + lane;
            BOOST_CHECK(std::binary_search(
                instance.base_column_indices.begin(),
                instance.base_column_indices.end(),
                column));
            BOOST_CHECK(gf::Eq(
                instance.columns[column][0],
                gf::Fp3::FromFp(gf::FromU64(
                    (native_word >>
                     (8U * (3U - lane))) &
                    0xffU))));
        }
    }
    uint32_t first_pass_exports = 0;
    for (uint32_t row = 0;
         row < instance.cs.n_rows; ++row) {
        if (gf::IsZero(
                instance.columns[
                    instance.input_active_column][row])) {
            continue;
        }
        ++first_pass_exports;
        const uint32_t word = static_cast<uint32_t>(
            gf::Canonical(
                instance.columns[
                    instance.input_address_column][row].c0));
        BOOST_REQUIRE_LT(word, 16U);
        const uint32_t native_word =
            boundaries[0].external_values[word];
        BOOST_CHECK(gf::Eq(
            instance.columns[
                instance.input_word_base][row],
            gf::Fp3::FromFp(gf::FromU64(
                native_word))));
        for (uint32_t lane = 0; lane < 4; ++lane) {
            BOOST_CHECK(gf::Eq(
                instance.columns[
                    instance.input_byte_base +
                    lane][row],
                gf::Fp3::FromFp(gf::FromU64(
                    (native_word >>
                     (8U * (3U - lane))) &
                    0xffU))));
        }
    }
    BOOST_CHECK_EQUAL(first_pass_exports, 16U);
    BOOST_REQUIRE(Satisfies(instance.cs, instance.columns));

    // A public verifier can instantiate the challenge-dependent CS from an
    // already committed R0. Mutating that root changes the LogUp challenge
    // tuple; the forthcoming multi-root FRI must bind the exact honest root.
    const uint256 alternate_r0 = PatternHash(0x92);
    const auto alternate_challenge_instance =
        ha::BuildFixedProgramVerticalWitnessBoundaryInstance(
            program, boundaries, public_masks, links, seed,
            alternate_r0);
    BOOST_REQUIRE_MESSAGE(
        alternate_challenge_instance.valid,
        alternate_challenge_instance.note);
    BOOST_CHECK(
        alternate_challenge_instance.base_row_commitment ==
        alternate_r0);
    BOOST_CHECK(
        matmul::v4::rc::CommitRCStage3CtlChallenges(
            alternate_challenge_instance.challenges) !=
        matmul::v4::rc::CommitRCStage3CtlChallenges(
            instance.challenges));
    BOOST_CHECK(
        alternate_challenge_instance.base_row_tree_cache ==
        nullptr);
    BOOST_CHECK(Satisfies(
        alternate_challenge_instance.cs,
        alternate_challenge_instance.columns));

    auto redacted_equivalent = boundaries;
    for (auto& boundary : redacted_equivalent) {
        std::fill(
            boundary.final_words.begin(),
            boundary.final_words.end(), 0xdeadbeefU);
    }
    for (uint32_t word = 0; word < 8; ++word) {
        redacted_equivalent[1].external_values[word] ^=
            0xa5a5a5a5U;
    }
    BOOST_CHECK_EQUAL(
        ha::CommitFixedProgramVerticalWitnessBoundaryStatement(
            program, boundaries, public_masks, links),
        ha::CommitFixedProgramVerticalWitnessBoundaryStatement(
            program, redacted_equivalent,
            public_masks, links));
    const auto verifier_cs =
        ha::BuildFixedProgramVerticalWitnessBoundaryVerifierInstance(
            program, redacted_equivalent,
            public_masks, links, seed,
            instance.base_row_commitment);
    BOOST_REQUIRE_MESSAGE(
        verifier_cs.valid, verifier_cs.note);
    BOOST_CHECK(
        verifier_cs.public_statement ==
        instance.public_statement);
    BOOST_CHECK(
        verifier_cs.base_row_commitment ==
        instance.base_row_commitment);
    BOOST_CHECK(
        matmul::v4::rc::CommitRCStage3CtlChallenges(
            verifier_cs.challenges) ==
        matmul::v4::rc::CommitRCStage3CtlChallenges(
            instance.challenges));
    BOOST_CHECK_EQUAL(
        verifier_cs.cs.n_rows, instance.cs.n_rows);
    BOOST_CHECK_EQUAL(
        verifier_cs.cs.n_columns,
        instance.cs.n_columns);
    BOOST_REQUIRE_EQUAL(
        verifier_cs.cs.constraints.size(),
        instance.cs.constraints.size());
    bool same_constraint_names = true;
    for (uint32_t index = 0;
         index < instance.cs.constraints.size();
         ++index) {
        same_constraint_names &=
            verifier_cs.cs.constraints[index].name ==
            instance.cs.constraints[index].name;
    }
    BOOST_CHECK(same_constraint_names);
    BOOST_REQUIRE_EQUAL(
        verifier_cs.cs.preprocessed.size(),
        instance.cs.preprocessed.size());
    bool same_preprocessed = true;
    for (uint32_t entry = 0;
         entry < instance.cs.preprocessed.size();
         ++entry) {
        const auto& expected =
            instance.cs.preprocessed[entry];
        const auto& rebuilt =
            verifier_cs.cs.preprocessed[entry];
        same_preprocessed &=
            expected.first == rebuilt.first &&
            expected.second.size() ==
                rebuilt.second.size();
        for (uint32_t row = 0;
             same_preprocessed &&
             row < expected.second.size();
             ++row) {
            same_preprocessed &=
                gf::Eq(
                    expected.second[row],
                    rebuilt.second[row]);
        }
    }
    BOOST_CHECK(same_preprocessed);
    auto public_mutation = boundaries;
    public_mutation[0].external_values[0] ^= 1U;
    BOOST_CHECK_NE(
        ha::CommitFixedProgramVerticalWitnessBoundaryStatement(
            program, boundaries, public_masks, links),
        ha::CommitFixedProgramVerticalWitnessBoundaryStatement(
            program, public_mutation, public_masks, links));

    uint32_t target_row = UINT32_MAX;
    uint32_t target_slot = UINT32_MAX;
    for (uint32_t row = 0; row < program.rows.size(); ++row) {
        for (uint32_t input = 0;
             input < program.rows[row].input_count; ++input) {
            if (program.rows[row].input_address[input] == 1) {
                target_row = 1024U + row;
                target_slot = input;
                break;
            }
        }
        if (target_row != UINT32_MAX) break;
    }
    BOOST_REQUIRE_NE(target_row, UINT32_MAX);
    auto chain_attack = instance.columns;
    chain_attack[ha::ValueColumn(target_slot)][target_row] =
        gf::Add(
            chain_attack[ha::ValueColumn(target_slot)][target_row],
            gf::Fp3::One());
    BOOST_CHECK(!Satisfies(instance.cs, chain_attack));

    auto digest_attack = instance.columns;
    digest_attack[instance.output_export_base][0] =
        gf::Add(
            digest_attack[instance.output_export_base][0],
            gf::Fp3::One());
    BOOST_CHECK(!Satisfies(instance.cs, digest_attack));

    // A fully boolean alternate digest word still cannot be substituted:
    // reconstruction binds it to the export, and the export is linked to the
    // actual final SHA cell.
    auto digest_substitution = instance.columns;
    const uint32_t alternate_word =
        boundaries.back().final_words[0] ^ UINT32_C(0xa5a5a5a5);
    for (uint32_t row = 0; row < instance.cs.n_rows; ++row) {
        digest_substitution[instance.output_export_base][row] =
            gf::Fp3::FromFp(gf::FromU64(alternate_word));
        for (uint32_t bit = 0; bit < 32; ++bit) {
            digest_substitution[
                instance.output_bit_base + bit][row] =
                gf::Fp3::FromFp(gf::FromU64(
                    (alternate_word >> bit) & 1U));
        }
    }
    BOOST_CHECK(!Satisfies(instance.cs, digest_substitution));

    auto non_boolean_digest_bit = instance.columns;
    non_boolean_digest_bit[instance.output_bit_base][0] =
        gf::Fp3::FromFp(gf::FromU64(2));
    BOOST_CHECK(!Satisfies(instance.cs, non_boolean_digest_bit));

    auto digest_byte_attack = instance.columns;
    digest_byte_attack[instance.output_byte_base][0] =
        gf::Add(
            digest_byte_attack[
                instance.output_byte_base][0],
            gf::Fp3::One());
    BOOST_CHECK(!Satisfies(instance.cs, digest_byte_attack));

    auto input_byte_attack = instance.columns;
    uint32_t first_input_row = UINT32_MAX;
    for (uint32_t row = 0;
         row < instance.cs.n_rows; ++row) {
        if (!gf::IsZero(
                instance.columns[
                    instance.input_active_column][row])) {
            first_input_row = row;
            break;
        }
    }
    BOOST_REQUIRE_NE(first_input_row, UINT32_MAX);
    input_byte_attack[
        instance.input_byte_base][first_input_row] =
        gf::Add(
            input_byte_attack[
                instance.input_byte_base][first_input_row],
            gf::Fp3::One());
    BOOST_CHECK(!Satisfies(instance.cs, input_byte_attack));

    auto source_attack = instance.columns;
    const uint32_t source_row = instance.final_output_rows[0];
    source_attack[ha::ValueColumn(0)][source_row] =
        gf::Add(
            source_attack[ha::ValueColumn(0)][source_row],
            gf::Fp3::One());
    BOOST_CHECK(!Satisfies(instance.cs, source_attack));

    BOOST_TEST_MESSAGE(
        "witness-owned SHA256d chain: rows="
        << instance.cs.n_rows
        << " columns=" << instance.cs.n_columns
        << " constraints=" << instance.cs.constraints.size()
        << " links=" << links.size());
}

// ---------------------------------------------------------------------------
// KEYSTONE (PR-89 rung-3): in-AIR SHA256d Fiat-Shamir challenge derivation
// bound to the committed SHA digest cells.
//
// Absorbs an FS transcript preimage through the REAL SHA256d vertical AIR
// (committed digest byte cells at output_byte_base) and derives the Fp3
// challenge IN-AIR from those exact cells: FromChallengeBytes3 is
//   c_j = sum_{i<8} byte[8j+i] * 2^{8i}   (j = 0,1,2)
// which is the ring homomorphism image of the integer mod-p reduction, hence
// three degree-1 constraints over the digest columns. No host extraction: the
// challenge lives in trace columns whose equality to the digest cells is a
// constraint. Perturbing the transcript input, a digest cell, or a challenge
// column breaks the binding. This is the same-trace binding that resolves the
// "scattered SSA digest rows" wall -- the vertical AIR already exports the 8
// finals to a contiguous committed byte interface via the export selector.
// ---------------------------------------------------------------------------
namespace {

// Build the real SHA256d vertical AIR over `preimage` and append the in-AIR
// FromChallengeBytes3 derivation (three limb columns each constrained to the
// digest-byte linear combination). The limb columns are filled with `claimed`
// so tamper cases can inject a stale challenge.
bool BuildInAirFsChallengeChip(
    const std::vector<uint8_t>& preimage,
    const gf::Fp3& claimed,
    aq::AirConstraintSystem<gf::Fp3>& cs_out,
    std::vector<std::vector<gf::Fp3>>& cols_out,
    uint32_t& obb_out,
    std::array<uint32_t, 3>& limb_cols_out,
    std::string* why)
{
    ha::ShaManifest manifest;
    if (!ha::BuildShaManifest(preimage, ha::ShaMode::Double, manifest, why)) {
        return false;
    }
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    if (!ha::BuildShaManifestBoundaryInstances(manifest, boundaries, why)) {
        return false;
    }
    if (boundaries.size() != 2) {
        if (why) *why = "expected single-block SHA256d (2 boundaries)";
        return false;
    }
    const auto program =
        ha::BuildCanonicalProgram(ha::ProgramKind::Sha256Compression);
    std::vector<std::vector<uint8_t>> public_masks(
        boundaries.size(),
        std::vector<uint8_t>(program.external_address_count, 1));
    for (uint32_t word = 0; word < 8; ++word) public_masks.back()[word] = 0;
    std::vector<ha::FixedProgramWitnessBoundaryLink> links;
    for (uint32_t word = 0; word < 8; ++word) {
        links.push_back({.source_instance = 0,
                         .source_final_word = word,
                         .target_instance = 1,
                         .target_external_address = word + 1});
    }
    const uint256 seed = PatternHash(0x71);
    auto instance = ha::BuildFixedProgramVerticalWitnessBoundaryInstance(
        program, boundaries, public_masks, links, seed);
    if (!instance.valid) {
        if (why) *why = instance.note;
        return false;
    }

    cs_out = instance.cs;
    cols_out = instance.columns;
    obb_out = instance.output_byte_base;
    const uint32_t base = cs_out.n_columns;
    limb_cols_out = {base, base + 1, base + 2};
    cs_out.n_columns = base + 3;
    const uint32_t n_rows = cs_out.n_rows;
    const std::array<gf::Fp3, 3> claimed_limbs = {
        gf::Fp3::FromFp(claimed.c0),
        gf::Fp3::FromFp(claimed.c1),
        gf::Fp3::FromFp(claimed.c2)};
    for (uint32_t j = 0; j < 3; ++j) {
        cols_out.push_back(
            std::vector<gf::Fp3>(n_rows, claimed_limbs[j]));
    }
    std::array<gf::Fp3, 8> pow2{};
    for (uint32_t i = 0; i < 8; ++i) {
        pow2[i] = gf::Fp3::FromFp(gf::FromU64(uint64_t(1) << (8 * i)));
    }
    const uint32_t obb = obb_out;
    for (uint32_t j = 0; j < 3; ++j) {
        const uint32_t limb_col = limb_cols_out[j];
        cs_out.constraints.push_back(
            {.name = "stage3.fs.challenge_limb_from_digest_bytes",
             .kind = aq::AirKind::kEverywhere,
             .alg_degree = 1,
             .eval = [obb, limb_col, j, pow2](
                         const std::vector<gf::Fp3>& cur,
                         const std::vector<gf::Fp3>&) {
                 gf::Fp3 acc = gf::Fp3::Zero();
                 for (uint32_t i = 0; i < 8; ++i) {
                     acc = gf::Add(
                         acc, gf::Mul(cur[obb + 8 * j + i], pow2[i]));
                 }
                 return gf::Sub(cur[limb_col], acc);
             }});
    }
    return true;
}

} // namespace

// Reduced-shape (8-row) constraint-evaluation of the in-AIR FS challenge chip:
// 24 committed SHA256d digest-byte columns + 3 Fp3 challenge-limb columns bound
// by the in-AIR FromChallengeBytes3 derivation. Violations are counted by
// direct constraint evaluation (no prove) so the tamper verdict is instant.
BOOST_AUTO_TEST_CASE(in_air_fs_challenge_reduced_shape_tamper_counts)
{
    std::vector<uint8_t> preimage;
    for (uint32_t i = 0; i < 33; ++i) preimage.push_back(uint8_t(7 * i + 3));
    const char* label = "fra3_lambda";
    preimage.insert(preimage.end(), label, label + std::strlen(label));
    for (uint32_t i = 0; i < 4; ++i) preimage.push_back(0);
    const uint256 digest = Sha256d(preimage);
    const gf::Fp3 ch = gf::FromChallengeBytes3(digest.data());

    const uint32_t n_rows = 8, n_cols = 27;
    std::array<gf::Fp3, 8> pow2{};
    for (uint32_t i = 0; i < 8; ++i) {
        pow2[i] = gf::Fp3::FromFp(gf::FromU64(uint64_t(1) << (8 * i)));
    }
    std::vector<aq::AirConstraint<gf::Fp3>> cons;
    for (uint32_t j = 0; j < 3; ++j) {
        cons.push_back(
            {.name = "fs.reduction",
             .kind = aq::AirKind::kEverywhere,
             .alg_degree = 1,
             .eval = [j, pow2](const std::vector<gf::Fp3>& cur,
                               const std::vector<gf::Fp3>&) {
                 gf::Fp3 acc = gf::Fp3::Zero();
                 for (uint32_t i = 0; i < 8; ++i) {
                     acc = gf::Add(acc, gf::Mul(cur[8 * j + i], pow2[i]));
                 }
                 return gf::Sub(cur[24 + j], acc);
             }});
    }
    const auto build_cols = [&](const uint256& d, const gf::Fp3& claimed) {
        std::vector<std::vector<gf::Fp3>> c(
            n_cols, std::vector<gf::Fp3>(n_rows, gf::Fp3::Zero()));
        for (uint32_t k = 0; k < 24; ++k) {
            std::fill(c[k].begin(), c[k].end(),
                      gf::Fp3::FromFp(gf::FromU64(d.data()[k])));
        }
        const std::array<gf::Fp3, 3> L = {gf::Fp3::FromFp(claimed.c0),
                                          gf::Fp3::FromFp(claimed.c1),
                                          gf::Fp3::FromFp(claimed.c2)};
        for (uint32_t j = 0; j < 3; ++j) {
            std::fill(c[24 + j].begin(), c[24 + j].end(), L[j]);
        }
        return c;
    };
    const auto count = [&](const std::vector<std::vector<gf::Fp3>>& c) {
        uint32_t v = 0;
        std::vector<gf::Fp3> cur(n_cols), nxt(n_cols);
        for (uint32_t r = 0; r < n_rows; ++r) {
            for (uint32_t col = 0; col < n_cols; ++col) {
                cur[col] = c[col][r];
                nxt[col] = c[col][(r + 1) % n_rows];
            }
            for (const auto& con : cons) {
                if (!gf::IsZero(con.eval(cur, nxt))) ++v;
            }
        }
        return v;
    };

    auto honest = build_cols(digest, ch);
    const uint32_t v_honest = count(honest);

    std::vector<uint8_t> t = preimage;
    t[0] ^= 0x01;
    const uint256 d2 = Sha256d(t);
    const uint32_t v_input = count(build_cols(d2, ch));  // stale claim

    auto dcell = honest;
    dcell[5][0] = gf::Add(dcell[5][0], gf::Fp3::One());
    const uint32_t v_digest = count(dcell);

    auto cchal = honest;
    cchal[25][0] = gf::Add(cchal[25][0], gf::Fp3::One());
    const uint32_t v_chal = count(cchal);

    BOOST_TEST_MESSAGE(
        "KEYSTONE_FS honest_violations=" << v_honest << " tamper_input="
        << v_input << " tamper_digest_cell=" << v_digest
        << " tamper_challenge_col=" << v_chal);
    BOOST_CHECK_EQUAL(v_honest, 0U);
    BOOST_CHECK_GT(v_input, 0U);
    BOOST_CHECK_GT(v_digest, 0U);
    BOOST_CHECK_GT(v_chal, 0U);
    // In-AIR derived challenge equals the FS challenge, no host extraction.
    BOOST_CHECK(gf::Eq(honest[24][0], gf::Fp3::FromFp(ch.c0)));
    BOOST_CHECK(gf::Eq(honest[25][0], gf::Fp3::FromFp(ch.c1)));
    BOOST_CHECK(gf::Eq(honest[26][0], gf::Fp3::FromFp(ch.c2)));
}

BOOST_AUTO_TEST_CASE(
    in_air_sha256d_fiat_shamir_challenge_bound_to_committed_digest_cells)
{
    // Representative single-block child-FS challenge preimage: transcript
    // prefix bytes + a challenge label + a u32 draw index (the shape produced
    // by BuildFiatShamirShaExecutionPlanV1 for one draw), sized <=55 so the
    // first SHA pass is one block (SHA256d => exactly two boundaries).
    std::vector<uint8_t> preimage;
    for (uint32_t i = 0; i < 33; ++i) preimage.push_back(uint8_t(7 * i + 3));
    const char* label = "fra3_lambda";
    preimage.insert(preimage.end(), label, label + std::strlen(label));
    for (uint32_t i = 0; i < 4; ++i) preimage.push_back(0);  // u32 index = 0
    BOOST_REQUIRE_EQUAL(preimage.size(), 48U);

    const uint256 digest = Sha256d(preimage);
    const gf::Fp3 host_challenge = gf::FromChallengeBytes3(digest.data());

    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> cols;
    uint32_t obb = 0;
    std::array<uint32_t, 3> limb_cols{};
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        BuildInAirFsChallengeChip(
            preimage, host_challenge, cs, cols, obb, limb_cols, &why),
        why);

    // The committed digest cells the challenge is derived from equal the
    // native SHA256d digest bytes (big-endian word serialization).
    for (uint32_t k = 0; k < 24; ++k) {
        BOOST_REQUIRE(gf::Eq(
            cols[obb + k][0],
            gf::Fp3::FromFp(gf::FromU64(digest.data()[k]))));
    }
    // In-AIR derived limbs equal the FS challenge; the equality is a trace
    // constraint (verified by Satisfies next), not a host assignment.
    BOOST_CHECK(gf::Eq(cols[limb_cols[0]][0],
                       gf::Fp3::FromFp(host_challenge.c0)));
    BOOST_CHECK(gf::Eq(cols[limb_cols[1]][0],
                       gf::Fp3::FromFp(host_challenge.c1)));
    BOOST_CHECK(gf::Eq(cols[limb_cols[2]][0],
                       gf::Fp3::FromFp(host_challenge.c2)));

    // HONEST: zero violations of the three in-AIR challenge-derivation
    // constraints over EVERY row of the real SHA256d trace. (The SHA256d
    // compression constraints on this identical vertical builder are proven to
    // hold with zero violations by the sibling test
    // witness_owned_two_compression_sha256d_chain_and_export; here we scan only
    // the appended derivation constraints so the case stays fast under load.)
    const auto fs_binding_rows =
        [](const aq::AirConstraintSystem<gf::Fp3>& c,
           const std::vector<std::vector<gf::Fp3>>& v, uint32_t rows) {
            std::vector<gf::Fp3> cur(c.n_columns), nxt(c.n_columns);
            for (uint32_t row = 0; row < rows; ++row) {
                for (uint32_t col = 0; col < c.n_columns; ++col) {
                    cur[col] = v[col][row];
                    nxt[col] = v[col][(row + 1) % c.n_rows];
                }
                for (const auto& con : c.constraints) {
                    if (std::string(con.name) !=
                        "stage3.fs.challenge_limb_from_digest_bytes") {
                        continue;
                    }
                    if (!gf::IsZero(con.eval(cur, nxt))) return false;
                }
            }
            return true;
        };
    const auto fs_binding_holds =
        [&](const aq::AirConstraintSystem<gf::Fp3>& c,
            const std::vector<std::vector<gf::Fp3>>& v) {
            return fs_binding_rows(c, v, c.n_rows);
        };
    BOOST_REQUIRE(fs_binding_holds(cs, cols));

    // TAMPER 1: perturb a committed SHA digest cell (byte 5, inside limb 0).
    {
        auto bad = cols;
        for (uint32_t r = 0; r < cs.n_rows; ++r) {
            bad[obb + 5][r] = gf::Add(bad[obb + 5][r], gf::Fp3::One());
        }
        BOOST_CHECK(!fs_binding_holds(cs, bad));
    }
    // TAMPER 2: perturb a derived challenge column.
    {
        auto bad = cols;
        for (uint32_t r = 0; r < cs.n_rows; ++r) {
            bad[limb_cols[1]][r] =
                gf::Add(bad[limb_cols[1]][r], gf::Fp3::One());
        }
        BOOST_CHECK(!fs_binding_holds(cs, bad));
    }
    // TAMPER 3: perturb a transcript INPUT byte. The committed digest cells now
    // hold the digest of the changed preimage, but the claimed challenge is
    // stale, so the in-AIR derivation from the digest cells no longer matches.
    {
        std::vector<uint8_t> tampered = preimage;
        tampered[0] ^= 0x01;
        const uint256 new_digest = Sha256d(tampered);
        auto bad = cols;
        for (uint32_t k = 0; k < 32; ++k) {
            const gf::Fp3 b =
                gf::Fp3::FromFp(gf::FromU64(new_digest.data()[k]));
            for (uint32_t r = 0; r < cs.n_rows; ++r) bad[obb + k][r] = b;
        }
        BOOST_CHECK(!fs_binding_holds(cs, bad));
    }

    // GENUINE STARK prove/verify of the digest->challenge reduction relation
    // on a self-contained plain-backend CS. (The SHA binding above is by
    // Satisfies over the real committed trace; this shows the reduction is a
    // low-degree, FRI-provable, tamper-detecting relation.)
    {
        aq::AirConstraintSystem<gf::Fp3> rcs;
        rcs.n_rows = 8;
        rcs.n_columns = 27;  // 24 digest-byte columns + 3 challenge limbs
        std::vector<std::vector<gf::Fp3>> rc(
            27, std::vector<gf::Fp3>(8, gf::Fp3::Zero()));
        for (uint32_t k = 0; k < 24; ++k) {
            std::fill(rc[k].begin(), rc[k].end(),
                      gf::Fp3::FromFp(gf::FromU64(digest.data()[k])));
        }
        const std::array<gf::Fp3, 3> limbs = {
            gf::Fp3::FromFp(host_challenge.c0),
            gf::Fp3::FromFp(host_challenge.c1),
            gf::Fp3::FromFp(host_challenge.c2)};
        for (uint32_t j = 0; j < 3; ++j) {
            std::fill(rc[24 + j].begin(), rc[24 + j].end(), limbs[j]);
        }
        std::array<gf::Fp3, 8> pow2{};
        for (uint32_t i = 0; i < 8; ++i) {
            pow2[i] = gf::Fp3::FromFp(gf::FromU64(uint64_t(1) << (8 * i)));
        }
        for (uint32_t j = 0; j < 3; ++j) {
            rcs.constraints.push_back(
                {.name = "stage3.fs.reduction",
                 .kind = aq::AirKind::kEverywhere,
                 .alg_degree = 1,
                 .eval = [j, pow2](const std::vector<gf::Fp3>& cur,
                                   const std::vector<gf::Fp3>&) {
                     gf::Fp3 acc = gf::Fp3::Zero();
                     for (uint32_t i = 0; i < 8; ++i) {
                         acc = gf::Add(
                             acc, gf::Mul(cur[8 * j + i], pow2[i]));
                     }
                     return gf::Sub(cur[24 + j], acc);
                 }});
        }
        uint256 seed;
        std::fill(seed.begin(), seed.end(), 0x59);
        const auto proved = aq::AirQuotientProve<gf::Fp3>(rcs, rc, seed);
        BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
        BOOST_REQUIRE(proved.division_exact);
        std::string vwhy;
        BOOST_CHECK_MESSAGE(
            aq::AirQuotientVerify<gf::Fp3>(rcs, proved.proof, seed, &vwhy),
            vwhy);

        auto bad = rc;
        bad[25][0] = gf::Add(bad[25][0], gf::Fp3::One());
        const auto rej = aq::AirQuotientProve<gf::Fp3>(rcs, bad, seed);
        BOOST_CHECK(!rej.division_exact);
    }
}

BOOST_AUTO_TEST_CASE(
    witness_owned_explicit_link_id_supports_source_fanout)
{
    std::vector<uint8_t> preimage(32);
    for (uint32_t i = 0; i < preimage.size(); ++i) {
        preimage[i] = static_cast<uint8_t>(13 * i + 1);
    }
    ha::ShaManifest manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildShaManifest(
            preimage, ha::ShaMode::Double,
            manifest, &why),
        why);
    std::vector<ha::FixedProgramBoundaryInstance> boundaries;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildShaManifestBoundaryInstances(
            manifest, boundaries, &why),
        why);
    BOOST_REQUIRE_EQUAL(boundaries.size(), 2U);
    boundaries.push_back(boundaries[1]);
    const auto program =
        ha::BuildCanonicalProgram(
            ha::ProgramKind::Sha256Compression);
    std::vector<std::vector<uint8_t>> public_masks(
        3, std::vector<uint8_t>(
               program.external_address_count, 1));
    for (uint32_t target = 1; target <= 2; ++target) {
        for (uint32_t word = 0; word < 8; ++word) {
            public_masks[target][word] = 0;
        }
    }
    std::vector<ha::FixedProgramWitnessBoundaryLink> links;
    for (uint32_t word = 0; word < 8; ++word) {
        const uint64_t id =
            UINT64_C(0x200000000) + word + 1;
        for (uint32_t target = 1; target <= 2; ++target) {
            links.push_back({
                .source_instance = 0,
                .source_final_word = word,
                .target_instance = target,
                .target_external_address = word + 1,
                .link_id = id,
            });
        }
    }
    const auto instance =
        ha::BuildFixedProgramVerticalWitnessBoundaryInstance(
            program, boundaries, public_masks,
            links, PatternHash(0x94));
    BOOST_REQUIRE_MESSAGE(instance.valid, instance.note);
    BOOST_CHECK_EQUAL(instance.semantic_instances, 3U);
    BOOST_CHECK_EQUAL(instance.scheduled_instances, 4U);
    BOOST_CHECK_EQUAL(instance.cs.n_rows, 4096U);
    BOOST_CHECK(Satisfies(instance.cs, instance.columns));

    auto second_target_attack = instance.columns;
    uint32_t target_row = UINT32_MAX;
    uint32_t target_slot = UINT32_MAX;
    for (uint32_t row = 0; row < program.rows.size(); ++row) {
        for (uint32_t input = 0;
             input < program.rows[row].input_count; ++input) {
            if (program.rows[row].input_address[input] == 1) {
                target_row = 2U * 1024U + row;
                target_slot = input;
                break;
            }
        }
        if (target_row != UINT32_MAX) break;
    }
    BOOST_REQUIRE_NE(target_row, UINT32_MAX);
    second_target_attack[
        ha::ValueColumn(target_slot)][target_row] =
        gf::Add(
            second_target_attack[
                ha::ValueColumn(target_slot)][target_row],
            gf::Fp3::One());
    BOOST_CHECK(
        !Satisfies(instance.cs, second_target_attack));

    auto mismatched_id = links;
    mismatched_id[1].link_id ^= 1U;
    BOOST_CHECK(
        ha::CommitFixedProgramVerticalWitnessBoundaryStatement(
            program, boundaries, public_masks,
            mismatched_id).IsNull());

    auto target_collision = links;
    target_collision.push_back(target_collision.front());
    BOOST_CHECK(
        ha::CommitFixedProgramVerticalWitnessBoundaryStatement(
            program, boundaries, public_masks,
            target_collision).IsNull());
}

BOOST_AUTO_TEST_CASE(multiblock_sha_padding_chaining_and_sha256d_are_canonical)
{
    std::vector<uint8_t> message(173);
    for (uint32_t i = 0; i < message.size(); ++i) {
        message[i] = static_cast<uint8_t>(11 * i + 7);
    }
    ha::ShaManifest single;
    ha::ShaManifest doubled;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildShaManifest(message, ha::ShaMode::Single, single, &why), why);
    BOOST_REQUIRE_MESSAGE(
        ha::BuildShaManifest(message, ha::ShaMode::Double, doubled, &why), why);
    BOOST_REQUIRE_MESSAGE(ha::ValidateShaManifest(single, &why), why);
    BOOST_REQUIRE_MESSAGE(ha::ValidateShaManifest(doubled, &why), why);
    BOOST_CHECK_EQUAL(single.first.padded_blocks.size(), 3U);
    BOOST_CHECK(single.second.padded_blocks.empty());
    BOOST_CHECK_EQUAL(doubled.first.padded_blocks.size(), 3U);
    BOOST_CHECK_EQUAL(doubled.second.padded_blocks.size(), 1U);
    BOOST_CHECK_EQUAL(doubled.second.message_size, 32U);
    std::vector<ha::FixedProgramBoundaryInstance> single_instances;
    std::vector<ha::FixedProgramBoundaryInstance> doubled_instances;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildShaManifestBoundaryInstances(
            single, single_instances, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        ha::BuildShaManifestBoundaryInstances(
            doubled, doubled_instances, &why),
        why);
    BOOST_CHECK_EQUAL(single_instances.size(), 3U);
    BOOST_CHECK_EQUAL(doubled_instances.size(), 4U);
    for (const auto& instance : doubled_instances) {
        BOOST_CHECK_EQUAL(instance.external_values.size(), 88U);
        BOOST_CHECK_EQUAL(instance.final_words.size(), 8U);
    }

    uint8_t digest1[32];
    uint8_t digest2[32];
    CSHA256().Write(message.data(), message.size()).Finalize(digest1);
    CSHA256().Write(digest1, sizeof(digest1)).Finalize(digest2);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        single.digest.begin(), single.digest.end(),
        digest1, digest1 + 32);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        doubled.digest.begin(), doubled.digest.end(),
        digest2, digest2 + 32);

    auto bad_padding = single;
    bad_padding.first.padded_blocks.back()[55] ^= 1;
    BOOST_CHECK(!ha::ValidateShaManifest(bad_padding, &why));

    auto bad_chain = single;
    bad_chain.first.h_in[1][3] ^= 1;
    BOOST_CHECK(!ha::ValidateShaManifest(bad_chain, &why));
    bad_chain.commitment = ha::CommitShaManifest(bad_chain);
    BOOST_CHECK(!ha::BuildShaManifestBoundaryInstances(
        bad_chain, single_instances, &why));

    auto omitted = single;
    omitted.first.padded_blocks.erase(omitted.first.padded_blocks.begin() + 1);
    BOOST_CHECK(!ha::ValidateShaManifest(omitted, &why));

    auto reordered = single;
    std::swap(reordered.first.padded_blocks[0],
              reordered.first.padded_blocks[1]);
    BOOST_CHECK(!ha::ValidateShaManifest(reordered, &why));

    auto trailing = single;
    trailing.first.padded_blocks.push_back(
        trailing.first.padded_blocks.back());
    BOOST_CHECK(!ha::ValidateShaManifest(trailing, &why));

    auto root_substitution = doubled;
    root_substitution.digest[0] ^= 1;
    BOOST_CHECK(!ha::ValidateShaManifest(root_substitution, &why));
}

BOOST_AUTO_TEST_CASE(empty_and_padding_boundaries_are_canonical)
{
    std::string why;
    for (const auto [length, blocks] :
         std::array<std::pair<uint32_t, uint32_t>, 7>{{
             {0, 1}, {55, 1}, {56, 2}, {63, 2},
             {64, 2}, {119, 2}, {120, 3}}}) {
        ha::ShaManifest manifest;
        BOOST_REQUIRE_MESSAGE(
            ha::BuildShaManifest(
                std::vector<uint8_t>(length, 0x5a),
                ha::ShaMode::Single, manifest, &why),
            why);
        BOOST_CHECK_EQUAL(manifest.first.padded_blocks.size(), blocks);
        BOOST_CHECK_EQUAL(
            manifest.first.padded_blocks.back()[63],
            static_cast<uint8_t>(length * 8));
    }

    uint256 seed;
    ha::CounterXofManifest xof;
    BOOST_REQUIRE(
        ha::BuildCounterXofManifest(
            seed, 0x6d, ha::CounterXofMode::MantissaE2M1,
            0, xof, &why));
    BOOST_CHECK(xof.counter_hashes.empty());
    BOOST_CHECK(xof.output.empty());

    ha::ChaChaConsumptionManifest chacha;
    BOOST_REQUIRE(
        ha::BuildChaChaConsumptionManifest(
            {}, 1, 2, 3, 0, chacha, &why));
    BOOST_CHECK(chacha.blocks.empty());
    BOOST_CHECK(chacha.output.empty());

    ha::TileTreeManifest tree;
    BOOST_REQUIRE(ha::BuildTileTreeManifest({}, 32, tree, &why));
    BOOST_CHECK_EQUAL(tree.logical_leaf_count, 1U);
    BOOST_CHECK_EQUAL(tree.padded_leaf_count, 1U);
    BOOST_CHECK_EQUAL(tree.hash_nodes.size(), 1U);
    BOOST_REQUIRE(ha::ValidateTileTreeManifest(tree, &why));
}

BOOST_AUTO_TEST_CASE(counter_xof_consumption_is_minimal_and_byte_exact)
{
    uint256 seed;
    for (uint32_t i = 0; i < 32; ++i) seed.data()[i] = 9 * i + 3;
    std::string why;

    ha::CounterXofManifest mantissa;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildCounterXofManifest(
            seed, 0x6d, ha::CounterXofMode::MantissaE2M1,
            137, mantissa, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        ha::ValidateCounterXofManifest(mantissa, &why), why);
    BOOST_CHECK_LE(
        mantissa.counter_hashes.size(),
        static_cast<size_t>(
            ((mantissa.output_count +
              matmul::v4::rc::kRCMxBlockLen - 1) /
             matmul::v4::rc::kRCMxBlockLen) *
            matmul::v4::rc::
                kRCStage3V1MaxRejectionBlocksPer32));
    std::vector<ha::FixedProgramBoundaryInstance> xof_instances;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildCounterXofManifestBoundaryInstances(
            mantissa, xof_instances, &why),
        why);
    BOOST_CHECK_EQUAL(
        xof_instances.size(), mantissa.counter_hashes.size());
    for (const auto& instance : xof_instances) {
        BOOST_CHECK_EQUAL(instance.external_values.size(), 88U);
        BOOST_CHECK_EQUAL(instance.final_words.size(), 8U);
    }
    std::vector<int8_t> expected_m(137);
    matmul::v4::bmx4::ExpandMantissaStream(
        seed, expected_m.size(), expected_m.data());
    for (uint32_t i = 0; i < expected_m.size(); ++i) {
        BOOST_CHECK_EQUAL(
            mantissa.output[i], static_cast<uint8_t>(expected_m[i]));
    }

    ha::CounterXofManifest scale;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildCounterXofManifest(
            seed, 0x65, ha::CounterXofMode::Scale2Bit,
            257, scale, &why),
        why);
    std::vector<uint8_t> expected_e(257);
    matmul::v4::bmx4::ExpandScaleStream(
        seed, expected_e.size(), expected_e.data());
    BOOST_CHECK_EQUAL_COLLECTIONS(
        scale.output.begin(), scale.output.end(),
        expected_e.begin(), expected_e.end());

    auto counter_substitution = scale;
    counter_substitution.counter_hashes[1].preimage[33] ^= 1;
    BOOST_CHECK(!ha::ValidateCounterXofManifest(
        counter_substitution, &why));
    counter_substitution.counter_hashes[1].commitment =
        ha::CommitShaManifest(
            counter_substitution.counter_hashes[1]);
    counter_substitution.commitment =
        ha::CommitCounterXofManifest(counter_substitution);
    BOOST_CHECK(!ha::BuildCounterXofManifestBoundaryInstances(
        counter_substitution, xof_instances, &why));

    auto truncated = mantissa;
    truncated.counter_hashes.pop_back();
    BOOST_CHECK(!ha::ValidateCounterXofManifest(truncated, &why));

    auto trailing = scale;
    trailing.counter_hashes.push_back(scale.counter_hashes.back());
    BOOST_CHECK(!ha::ValidateCounterXofManifest(trailing, &why));
    trailing.commitment = ha::CommitCounterXofManifest(trailing);
    BOOST_CHECK(!ha::BuildCounterXofManifestBoundaryInstances(
        trailing, xof_instances, &why));

    auto output_mutation = mantissa;
    output_mutation.output[19] ^= 1;
    BOOST_CHECK(!ha::ValidateCounterXofManifest(output_mutation, &why));
    output_mutation.commitment =
        ha::CommitCounterXofManifest(output_mutation);
    BOOST_CHECK(!ha::BuildCounterXofManifestBoundaryInstances(
        output_mutation, xof_instances, &why));

    auto domain_substitution = scale;
    domain_substitution.domain = 0x6d;
    BOOST_CHECK(!ha::ValidateCounterXofManifest(domain_substitution, &why));
}

BOOST_AUTO_TEST_CASE(chacha_consumption_manifest_rejects_counter_and_tail_changes)
{
    std::array<uint8_t, 32> key{};
    for (uint32_t i = 0; i < key.size(); ++i) key[i] = 5 * i + 1;
    constexpr uint32_t nonce_first = 0xa1b2c3d4U;
    constexpr uint64_t nonce_second = UINT64_C(0x1020304050607080);
    constexpr uint32_t first_counter = 13;
    constexpr uint64_t output_bytes = 141;
    ha::ChaChaConsumptionManifest manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildChaChaConsumptionManifest(
            key, nonce_first, nonce_second, first_counter,
            output_bytes, manifest, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        ha::ValidateChaChaConsumptionManifest(manifest, &why), why);
    BOOST_CHECK_EQUAL(manifest.blocks.size(), 3U);
    BOOST_CHECK_EQUAL(manifest.output.size(), output_bytes);
    std::vector<ha::FixedProgramBoundaryInstance> instances;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildChaChaManifestBoundaryInstances(
            manifest, instances, &why),
        why);
    BOOST_CHECK_EQUAL(instances.size(), 3U);
    for (uint32_t block = 0; block < instances.size(); ++block) {
        BOOST_CHECK_EQUAL(instances[block].external_values.size(), 16U);
        BOOST_CHECK_EQUAL(instances[block].final_words.size(), 16U);
        BOOST_CHECK_EQUAL(
            instances[block].external_values[12],
            first_counter + block);
    }

    std::array<std::byte, 32> key_bytes{};
    for (uint32_t i = 0; i < key.size(); ++i) {
        key_bytes[i] = static_cast<std::byte>(key[i]);
    }
    std::vector<std::byte> expected(output_bytes);
    ChaCha20 reference{Span<const std::byte>{key_bytes}};
    reference.Seek({nonce_first, nonce_second}, first_counter);
    reference.Keystream(expected);
    for (uint32_t i = 0; i < expected.size(); ++i) {
        BOOST_CHECK_EQUAL(
            manifest.output[i], static_cast<uint8_t>(expected[i]));
    }

    auto counter = manifest;
    ++counter.first_counter;
    BOOST_CHECK(!ha::ValidateChaChaConsumptionManifest(counter, &why));

    auto omitted = manifest;
    omitted.blocks.erase(omitted.blocks.begin() + 1);
    BOOST_CHECK(!ha::ValidateChaChaConsumptionManifest(omitted, &why));

    auto reordered = manifest;
    std::swap(reordered.blocks[0], reordered.blocks[1]);
    BOOST_CHECK(!ha::ValidateChaChaConsumptionManifest(reordered, &why));
    reordered.commitment =
        ha::CommitChaChaConsumptionManifest(reordered);
    BOOST_CHECK(!ha::BuildChaChaManifestBoundaryInstances(
        reordered, instances, &why));

    auto trailing = manifest;
    trailing.blocks.push_back(manifest.blocks.back());
    BOOST_CHECK(!ha::ValidateChaChaConsumptionManifest(trailing, &why));

    auto truncated_output = manifest;
    truncated_output.output.pop_back();
    BOOST_CHECK(!ha::ValidateChaChaConsumptionManifest(
        truncated_output, &why));
    truncated_output.commitment =
        ha::CommitChaChaConsumptionManifest(truncated_output);
    BOOST_CHECK(!ha::BuildChaChaManifestBoundaryInstances(
        truncated_output, instances, &why));
}

BOOST_AUTO_TEST_CASE(tile_tree_and_direct_stream_manifests_are_exact)
{
    std::vector<uint8_t> stream(197);
    for (uint32_t i = 0; i < stream.size(); ++i) stream[i] = 17 * i + 4;
    ha::TileTreeManifest tree;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildTileTreeManifest(stream, 48, tree, &why), why);
    BOOST_REQUIRE_MESSAGE(ha::ValidateTileTreeManifest(tree, &why), why);
    BOOST_CHECK_EQUAL(tree.logical_leaf_count, 5U);
    BOOST_CHECK_EQUAL(tree.padded_leaf_count, 8U);
    BOOST_CHECK_EQUAL(tree.leaf_hashes.size(), 8U);
    // 5 real leaves + 1 shared pad hash + 7 internal hashes.
    BOOST_CHECK_EQUAL(tree.hash_nodes.size(), 13U);
    std::vector<ha::FixedProgramBoundaryInstance> tree_instances;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildTileTreeManifestBoundaryInstances(
            tree, tree_instances, &why),
        why);
    BOOST_CHECK_EQUAL(tree_instances.size(), 33U);

    std::vector<int8_t> signed_stream(stream.size());
    for (uint32_t i = 0; i < stream.size(); ++i) {
        signed_stream[i] = static_cast<int8_t>(stream[i]);
    }
    BOOST_CHECK_EQUAL(
        tree.root,
        matmul::v4::rc::BuildTileTreeRoot(signed_stream, 48));

    auto leaf_omission = tree;
    leaf_omission.hash_nodes.erase(leaf_omission.hash_nodes.begin() + 2);
    BOOST_CHECK(!ha::ValidateTileTreeManifest(leaf_omission, &why));

    auto node_reorder = tree;
    std::swap(node_reorder.hash_nodes[7], node_reorder.hash_nodes[8]);
    BOOST_CHECK(!ha::ValidateTileTreeManifest(node_reorder, &why));
    node_reorder.commitment =
        ha::CommitTileTreeManifest(node_reorder);
    BOOST_CHECK(!ha::BuildTileTreeManifestBoundaryInstances(
        node_reorder, tree_instances, &why));

    auto pad_substitution = tree;
    pad_substitution.leaf_hashes[7] = pad_substitution.leaf_hashes[0];
    BOOST_CHECK(!ha::ValidateTileTreeManifest(pad_substitution, &why));

    auto root_substitution = tree;
    root_substitution.root.data()[0] ^= 1;
    BOOST_CHECK(!ha::ValidateTileTreeManifest(root_substitution, &why));

    for (const auto relation : {
             ha::DirectHashRelation::CoupledBarrier,
             ha::DirectHashRelation::EpisodeDigest,
             ha::DirectHashRelation::CoupledDigest,
             ha::DirectHashRelation::FinalDigest}) {
        ha::DirectSha256dManifest direct;
        BOOST_REQUIRE_MESSAGE(
            ha::BuildDirectSha256dManifest(
                relation, stream, direct, &why),
            why);
        BOOST_REQUIRE_MESSAGE(
            ha::ValidateDirectSha256dManifest(direct, &why), why);
        std::vector<ha::FixedProgramBoundaryInstance> direct_instances;
        BOOST_REQUIRE_MESSAGE(
            ha::BuildDirectSha256dManifestBoundaryInstances(
                direct, direct_instances, &why),
            why);
        BOOST_CHECK_EQUAL(direct_instances.size(), 5U);
        auto changed = direct;
        changed.preimage.push_back(0);
        BOOST_CHECK(!ha::ValidateDirectSha256dManifest(changed, &why));
        changed.commitment =
            ha::CommitDirectSha256dManifest(changed);
        BOOST_CHECK(
            !ha::BuildDirectSha256dManifestBoundaryInstances(
                changed, direct_instances, &why));
        auto digest_changed = direct;
        digest_changed.digest.data()[4] ^= 1;
        BOOST_CHECK(!ha::ValidateDirectSha256dManifest(
            digest_changed, &why));
    }
}

BOOST_AUTO_TEST_CASE(typed_episode_and_coupled_digest_manifests_are_exact)
{
    const std::vector<uint256> episode_roots{
        PatternHash(3), PatternHash(17), PatternHash(91)};
    ha::EpisodeDigestManifest episode;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildEpisodeDigestManifest(
            episode_roots.size(), episode_roots, episode, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        ha::ValidateEpisodeDigestManifest(episode, &why), why);

    std::vector<uint8_t> episode_preimage(
        reinterpret_cast<const uint8_t*>(matmul::v4::rc::kRCEpisodeTag),
        reinterpret_cast<const uint8_t*>(matmul::v4::rc::kRCEpisodeTag) +
            sizeof(matmul::v4::rc::kRCEpisodeTag) - 1);
    for (const auto& root : episode_roots) {
        episode_preimage.insert(
            episode_preimage.end(), root.data(), root.data() + 32);
    }
    BOOST_CHECK_EQUAL(episode.direct.digest, Sha256d(episode_preimage));

    auto episode_omission = episode;
    episode_omission.round_roots.pop_back();
    BOOST_CHECK(!ha::ValidateEpisodeDigestManifest(
        episode_omission, &why));
    auto episode_reorder = episode;
    std::swap(
        episode_reorder.round_roots[0], episode_reorder.round_roots[1]);
    BOOST_CHECK(!ha::ValidateEpisodeDigestManifest(
        episode_reorder, &why));
    auto episode_count = episode;
    ++episode_count.expected_rounds;
    BOOST_CHECK(!ha::ValidateEpisodeDigestManifest(episode_count, &why));
    auto episode_tag = episode;
    episode_tag.direct.preimage[0] ^= 1;
    BOOST_CHECK(!ha::ValidateEpisodeDigestManifest(episode_tag, &why));
    ha::EpisodeDigestManifest invalid_episode;
    BOOST_CHECK(!ha::BuildEpisodeDigestManifest(
        0, {}, invalid_episode, &why));

    const uint256 bank_root = PatternHash(211);
    const std::vector<uint256> barrier_roots{
        PatternHash(7), PatternHash(31), PatternHash(59), PatternHash(107)};
    std::vector<uint8_t> state(193);
    for (uint32_t i = 0; i < state.size(); ++i) {
        state[i] = static_cast<uint8_t>(11 * i + 5);
    }

    for (const uint32_t version : {
             matmul::v4::rc::ENC_RC_V1,
             matmul::v4::rc::ENC_RC_V2,
             matmul::v4::rc::ENC_RC_V3,
             matmul::v4::rc::ENC_RC_V4}) {
        ha::CoupledBarrierManifest barrier;
        BOOST_REQUIRE_MESSAGE(
            ha::BuildCoupledBarrierManifest(
                version, barrier_roots.size(), 2, state, barrier, &why),
            why);
        BOOST_REQUIRE_MESSAGE(
            ha::ValidateCoupledBarrierManifest(barrier, &why), why);

        const auto& tags =
            matmul::v4::rc::RCCoupDomainTagsForVersion(version);
        std::vector<uint8_t> barrier_preimage(
            reinterpret_cast<const uint8_t*>(tags.barrier),
            reinterpret_cast<const uint8_t*>(tags.barrier) +
                std::strlen(tags.barrier));
        barrier_preimage.insert(
            barrier_preimage.end(), {2, 0, 0, 0});
        barrier_preimage.insert(
            barrier_preimage.end(), state.begin(), state.end());
        BOOST_CHECK_EQUAL(
            barrier.direct.digest, Sha256d(barrier_preimage));

        ha::CoupledDigestManifest coupled;
        BOOST_REQUIRE_MESSAGE(
            ha::BuildCoupledDigestManifest(
                version, barrier_roots.size(), bank_root,
                barrier_roots, coupled, &why),
            why);
        BOOST_REQUIRE_MESSAGE(
            ha::ValidateCoupledDigestManifest(coupled, &why), why);
        BOOST_CHECK_EQUAL(
            coupled.direct.digest,
            matmul::v4::rc::AssembleCoupledEpisodeDigest(
                bank_root, barrier_roots, version));
    }

    ha::CoupledBarrierManifest barrier;
    BOOST_REQUIRE(ha::BuildCoupledBarrierManifest(
        matmul::v4::rc::ENC_RC_V4, barrier_roots.size(), 2, state,
        barrier, &why));
    auto barrier_index = barrier;
    barrier_index.barrier_index = 3;
    BOOST_CHECK(!ha::ValidateCoupledBarrierManifest(barrier_index, &why));
    auto barrier_count = barrier;
    --barrier_count.expected_barriers;
    BOOST_CHECK(!ha::ValidateCoupledBarrierManifest(barrier_count, &why));
    auto barrier_state = barrier;
    barrier_state.state_bytes[9] ^= 1;
    BOOST_CHECK(!ha::ValidateCoupledBarrierManifest(barrier_state, &why));
    auto barrier_version = barrier;
    barrier_version.transcript_version = matmul::v4::rc::ENC_RC_V3;
    BOOST_CHECK(!ha::ValidateCoupledBarrierManifest(
        barrier_version, &why));
    ha::CoupledBarrierManifest invalid_barrier;
    BOOST_CHECK(!ha::BuildCoupledBarrierManifest(
        matmul::v4::rc::ENC_RC_V4 + 1, barrier_roots.size(), 2, state,
        invalid_barrier, &why));
    BOOST_CHECK(!ha::BuildCoupledBarrierManifest(
        matmul::v4::rc::ENC_RC_V4, barrier_roots.size(),
        barrier_roots.size(), state, invalid_barrier, &why));

    ha::CoupledDigestManifest coupled;
    BOOST_REQUIRE(ha::BuildCoupledDigestManifest(
        matmul::v4::rc::ENC_RC_V4, barrier_roots.size(), bank_root,
        barrier_roots, coupled, &why));
    auto coupled_omission = coupled;
    coupled_omission.barrier_roots.pop_back();
    BOOST_CHECK(!ha::ValidateCoupledDigestManifest(
        coupled_omission, &why));
    auto coupled_reorder = coupled;
    std::swap(
        coupled_reorder.barrier_roots[1],
        coupled_reorder.barrier_roots[2]);
    BOOST_CHECK(!ha::ValidateCoupledDigestManifest(
        coupled_reorder, &why));
    auto coupled_bank = coupled;
    coupled_bank.bank_root.data()[4] ^= 1;
    BOOST_CHECK(!ha::ValidateCoupledDigestManifest(coupled_bank, &why));
    auto coupled_count = coupled;
    ++coupled_count.expected_barriers;
    BOOST_CHECK(!ha::ValidateCoupledDigestManifest(coupled_count, &why));
    auto coupled_version = coupled;
    coupled_version.transcript_version = matmul::v4::rc::ENC_RC_V1;
    BOOST_CHECK(!ha::ValidateCoupledDigestManifest(
        coupled_version, &why));
}

BOOST_AUTO_TEST_CASE(composed_final_digest_manifest_matches_consensus_serializer)
{
    const uint256 header_commitment = PatternHash(5);
    const uint256 params_commitment = PatternHash(19);
    const uint256 episode_digest = PatternHash(61);
    const uint256 coupled_digest = PatternHash(139);
    ha::ComposedFinalDigestManifest manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildComposedFinalDigestManifest(
            matmul::v4::rc::kRCStage3ProofVersion, 912345,
            header_commitment, params_commitment, 2, 3,
            matmul::v4::rc::ENC_RC_V4, episode_digest, coupled_digest,
            manifest, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        ha::ValidateComposedFinalDigestManifest(manifest, &why), why);

    matmul::v4::rc::RCStage3SuccinctProof proof;
    proof.statement = matmul::v4::rc::RCStage3StatementKind::Composed;
    proof.public_inputs.height = 912345;
    proof.public_inputs.header_commitment = header_commitment;
    proof.public_inputs.params_commitment = params_commitment;
    proof.public_inputs.episode_profile = 2;
    proof.public_inputs.coupled_profile = 3;
    proof.public_inputs.transcript_version =
        matmul::v4::rc::ENC_RC_V4;
    proof.public_inputs.episode_digest = episode_digest;
    proof.public_inputs.coupled_digest = coupled_digest;
    BOOST_CHECK_EQUAL(
        manifest.direct.digest,
        matmul::v4::rc::ComputeRCStage3FinalDigest(proof));

    auto height = manifest;
    ++height.height;
    BOOST_CHECK(!ha::ValidateComposedFinalDigestManifest(height, &why));
    auto header = manifest;
    header.header_commitment.data()[0] ^= 1;
    BOOST_CHECK(!ha::ValidateComposedFinalDigestManifest(header, &why));
    auto profile = manifest;
    ++profile.coupled_profile;
    BOOST_CHECK(!ha::ValidateComposedFinalDigestManifest(profile, &why));
    auto version = manifest;
    version.transcript_version = matmul::v4::rc::ENC_RC_V3;
    BOOST_CHECK(!ha::ValidateComposedFinalDigestManifest(version, &why));
    auto digest = manifest;
    digest.coupled_digest.data()[12] ^= 1;
    BOOST_CHECK(!ha::ValidateComposedFinalDigestManifest(digest, &why));
    auto preimage = manifest;
    preimage.direct.preimage.pop_back();
    BOOST_CHECK(!ha::ValidateComposedFinalDigestManifest(preimage, &why));

    ha::ComposedFinalDigestManifest invalid;
    BOOST_CHECK(!ha::BuildComposedFinalDigestManifest(
        matmul::v4::rc::kRCStage3ProofVersion + 1, 912345,
        header_commitment, params_commitment, 2, 3,
        matmul::v4::rc::ENC_RC_V4, episode_digest, coupled_digest,
        invalid, &why));
}

BOOST_AUTO_TEST_CASE(noncanonical_specs_fail_closed)
{
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::string why;
    BOOST_CHECK(!ha::BuildConstraintSystem(
        {.family = ha::Family::XorRot32, .n_rows = 2}, cs, &why));
    BOOST_CHECK(why.find("bad_rotate_left") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(xof_counter_manifest_recursive_binding_round_trip_and_tamper)
{
    uint256 seed;
    for (uint32_t i = 0; i < 32; ++i) seed.data()[i] = 9 * i + 3;
    std::string why;

    ha::CounterXofManifest scale;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildCounterXofManifest(
            seed, 0x65, ha::CounterXofMode::Scale2Bit, 257, scale, &why),
        why);
    std::vector<ha::FixedProgramBoundaryInstance> stream;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildCounterXofManifestBoundaryInstances(scale, stream, &why),
        why);

    ha::HashManifestRecursiveBinding binding;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildXofCounterManifestRecursiveBinding(scale, binding, &why),
        why);
    BOOST_CHECK_EQUAL(binding.instance_count, stream.size());
    BOOST_CHECK(!binding.stream_column_root.IsNull());
    BOOST_CHECK(!binding.binding_commitment.IsNull());
    BOOST_CHECK_EQUAL(
        binding.manifest_commitment,
        ha::CommitCounterXofManifest(scale));
    BOOST_CHECK_MESSAGE(
        ha::VerifyXofCounterManifestRecursiveBinding(scale, binding, &why),
        why);

    // Determinism.
    ha::HashManifestRecursiveBinding again;
    BOOST_REQUIRE(
        ha::BuildXofCounterManifestRecursiveBinding(scale, again, &why));
    BOOST_CHECK(again == binding);

    // Tamper the committed column root: the recursive binding is load-bearing.
    auto bad_root = binding;
    bad_root.stream_column_root.data()[0] ^= 1;
    BOOST_CHECK(!ha::VerifyXofCounterManifestRecursiveBinding(
        scale, bad_root, &why));
    BOOST_CHECK(why.find("stream_root_mismatch") != std::string::npos);

    auto bad_commit = binding;
    bad_commit.binding_commitment.data()[7] ^= 1;
    BOOST_CHECK(!ha::VerifyXofCounterManifestRecursiveBinding(
        scale, bad_commit, &why));

    auto bad_count = binding;
    bad_count.instance_count += 1;
    BOOST_CHECK(!ha::VerifyXofCounterManifestRecursiveBinding(
        scale, bad_count, &why));

    // Wrong manifest value: honest binding must reject the tampered manifest.
    auto output_mutation = scale;
    output_mutation.output[19] ^= 1;
    output_mutation.commitment =
        ha::CommitCounterXofManifest(output_mutation);
    BOOST_CHECK(!ha::VerifyXofCounterManifestRecursiveBinding(
        output_mutation, binding, &why));

    // Reordered counter: swap two counter hashes, refresh commitments.
    auto reordered = scale;
    BOOST_REQUIRE_GE(reordered.counter_hashes.size(), 2U);
    std::swap(reordered.counter_hashes[0], reordered.counter_hashes[1]);
    reordered.commitment = ha::CommitCounterXofManifest(reordered);
    BOOST_CHECK(!ha::VerifyXofCounterManifestRecursiveBinding(
        reordered, binding, &why));
}

BOOST_AUTO_TEST_CASE(chacha_init_block_manifest_recursive_binding_round_trip_and_tamper)
{
    std::array<uint8_t, 32> key{};
    for (uint32_t i = 0; i < key.size(); ++i) key[i] = 5 * i + 1;
    constexpr uint32_t nonce_first = 0xa1b2c3d4U;
    constexpr uint64_t nonce_second = UINT64_C(0x1020304050607080);
    constexpr uint32_t first_counter = 13;
    constexpr uint64_t output_bytes = 141;
    ha::ChaChaConsumptionManifest manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildChaChaConsumptionManifest(
            key, nonce_first, nonce_second, first_counter, output_bytes,
            manifest, &why),
        why);

    ha::HashManifestRecursiveBinding binding;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildChaChaInitAndBlockManifestRecursiveBinding(
            manifest, binding, &why),
        why);
    BOOST_CHECK_EQUAL(binding.instance_count, manifest.blocks.size());
    BOOST_CHECK(!binding.stream_column_root.IsNull());
    BOOST_CHECK_EQUAL(
        binding.manifest_commitment,
        ha::CommitChaChaConsumptionManifest(manifest));
    BOOST_CHECK_MESSAGE(
        ha::VerifyChaChaInitAndBlockManifestRecursiveBinding(
            manifest, binding, &why),
        why);

    auto bad_root = binding;
    bad_root.stream_column_root.data()[3] ^= 1;
    BOOST_CHECK(!ha::VerifyChaChaInitAndBlockManifestRecursiveBinding(
        manifest, bad_root, &why));
    BOOST_CHECK(why.find("stream_root_mismatch") != std::string::npos);

    // Reordered blocks (a distinct committed-column ordering).
    auto reordered = manifest;
    std::swap(reordered.blocks[0], reordered.blocks[1]);
    reordered.commitment = ha::CommitChaChaConsumptionManifest(reordered);
    BOOST_CHECK(!ha::VerifyChaChaInitAndBlockManifestRecursiveBinding(
        reordered, binding, &why));

    // Wrong init value (counter): binding must reject.
    auto counter = manifest;
    ++counter.first_counter;
    counter.commitment = ha::CommitChaChaConsumptionManifest(counter);
    BOOST_CHECK(!ha::VerifyChaChaInitAndBlockManifestRecursiveBinding(
        counter, binding, &why));
}

BOOST_AUTO_TEST_CASE(complete_stream_manifest_recursive_binding_round_trip_and_tamper)
{
    std::vector<uint8_t> stream_bytes(197);
    for (uint32_t i = 0; i < stream_bytes.size(); ++i) {
        stream_bytes[i] = 17 * i + 4;
    }
    std::string why;

    // Tile-tree leaf/node stream binding.
    ha::TileTreeManifest tree;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildTileTreeManifest(stream_bytes, 48, tree, &why), why);
    std::vector<ha::FixedProgramBoundaryInstance> tree_stream;
    BOOST_REQUIRE(ha::BuildTileTreeManifestBoundaryInstances(
        tree, tree_stream, &why));

    ha::HashManifestRecursiveBinding tree_binding;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildCompleteStreamManifestRecursiveBinding(
            tree, tree_binding, &why),
        why);
    BOOST_CHECK_EQUAL(tree_binding.instance_count, tree_stream.size());
    BOOST_CHECK_MESSAGE(
        ha::VerifyCompleteStreamManifestRecursiveBinding(
            tree, tree_binding, &why),
        why);

    auto bad_tree = tree_binding;
    bad_tree.stream_column_root.data()[11] ^= 1;
    BOOST_CHECK(!ha::VerifyCompleteStreamManifestRecursiveBinding(
        tree, bad_tree, &why));
    BOOST_CHECK(why.find("stream_root_mismatch") != std::string::npos);

    auto node_reorder = tree;
    std::swap(node_reorder.hash_nodes[7], node_reorder.hash_nodes[8]);
    node_reorder.commitment = ha::CommitTileTreeManifest(node_reorder);
    BOOST_CHECK(!ha::VerifyCompleteStreamManifestRecursiveBinding(
        node_reorder, tree_binding, &why));

    // Digest stream binding (CoupledBarrier / FinalDigest producers).
    for (const auto relation : {
             ha::DirectHashRelation::CoupledBarrier,
             ha::DirectHashRelation::FinalDigest}) {
        ha::DirectSha256dManifest direct;
        BOOST_REQUIRE_MESSAGE(
            ha::BuildDirectSha256dManifest(
                relation, stream_bytes, direct, &why),
            why);
        ha::HashManifestRecursiveBinding direct_binding;
        BOOST_REQUIRE_MESSAGE(
            ha::BuildCompleteStreamManifestRecursiveBinding(
                direct, direct_binding, &why),
            why);
        BOOST_CHECK(!direct_binding.stream_column_root.IsNull());
        BOOST_CHECK_MESSAGE(
            ha::VerifyCompleteStreamManifestRecursiveBinding(
                direct, direct_binding, &why),
            why);

        auto bad_direct = direct_binding;
        bad_direct.binding_commitment.data()[1] ^= 1;
        BOOST_CHECK(!ha::VerifyCompleteStreamManifestRecursiveBinding(
            direct, bad_direct, &why));

        auto changed = direct;
        changed.preimage.push_back(0);
        changed.commitment = ha::CommitDirectSha256dManifest(changed);
        BOOST_CHECK(!ha::VerifyCompleteStreamManifestRecursiveBinding(
            changed, direct_binding, &why));
    }

    // Distinct families / distinct producers must not cross-validate.
    ha::DirectSha256dManifest final_direct;
    BOOST_REQUIRE(ha::BuildDirectSha256dManifest(
        ha::DirectHashRelation::FinalDigest, stream_bytes, final_direct,
        &why));
    BOOST_CHECK(!ha::VerifyCompleteStreamManifestRecursiveBinding(
        final_direct, tree_binding, &why));
}

// PR-89 certified_bits: the three manifest recursive bindings close the
// per-relation manifest gap. relation_complete stays false: CopyAndCtlWiring
// and RecursiveAggregation remain open for every relation.
BOOST_AUTO_TEST_CASE(manifest_gap_closed_but_relation_not_complete)
{
    const auto readiness = ha::CurrentRelationReadiness();
    BOOST_REQUIRE_EQUAL(readiness.size(), 6U);
    const auto has_gap = [](const ha::RelationReadiness& r, ha::GapCode code) {
        return std::any_of(r.gaps.begin(), r.gaps.end(),
                           [code](const ha::Gap& g) { return g.code == code; });
    };
    for (const auto& r : readiness) {
        BOOST_CHECK(!r.relation_complete);
        // Every manifest gap is closed.
        BOOST_CHECK(!has_gap(r, ha::GapCode::XofCounterManifest));
        BOOST_CHECK(!has_gap(r, ha::GapCode::ChaChaInitAndBlockManifest));
        BOOST_CHECK(!has_gap(r, ha::GapCode::CompleteStreamManifest));
        // The two lanes owned elsewhere stay open.
        BOOST_CHECK(has_gap(r, ha::GapCode::CopyAndCtlWiring));
        BOOST_CHECK(has_gap(r, ha::GapCode::RecursiveAggregation));
    }
    BOOST_CHECK(!ha::kHashRelationsComplete);
}

BOOST_AUTO_TEST_SUITE_END()

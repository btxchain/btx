// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_extract.h>
#include <matmul/matmul_v4_rc_gkr_air.h>
#include <matmul/matmul_v4_rc_gkr_field_ext.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <limits>
#include <vector>

namespace air = matmul::v4::rc::gkr_air;
namespace gf = matmul::v4::rc::gkr_field;
using matmul::v4::rc::kRCMxBlockLen;

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_gkr_air_tests)

namespace {

uint256 MakePrf(uint8_t seed)
{
    std::array<uint8_t, 32> b{};
    for (int i = 0; i < 32; ++i) b[i] = static_cast<uint8_t>(seed * 7 + i * 31 + 1);
    return uint256{Span<const unsigned char>{b.data(), b.size()}};
}

air::TilePublic MakePub(uint8_t seed, uint32_t i, uint32_t bj)
{
    air::TilePublic p;
    p.prf_key = MakePrf(seed);
    p.i = i;
    p.bj = bj;
    return p;
}

// A cheap deterministic PRNG for input generation (test-only).
struct Lcg {
    uint64_t s;
    explicit Lcg(uint64_t seed) : s(seed) {}
    uint64_t next() { s = s * 6364136223846793005ULL + 1442695040888963407ULL; return s; }
};

// Dual-alpha challenges chosen to avoid collision with any fingerprint.
gf::Fp2 Alpha1() { return gf::Fp2{0x1234567890ABCDEFull % gf::kP, 0x0FEDCBA987654321ull % gf::kP}; }
gf::Fp2 Alpha2() { return gf::Fp2{0x0A1B2C3D4E5F6071ull % gf::kP, 0x7160504E3D2C1B0Aull % gf::kP}; }
gf::Fp2 Gamma()  { return gf::Fp2{0x00000000DEADBEEFull, 0x00000000FEEDFACEull}; }

} // namespace

// ---------------------------------------------------------------------------
// Preprocessed table self-check (§5.3): tables agree with the int64 reference.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(air_tables_selfcheck)
{
    BOOST_CHECK(air::SelfCheckTables());
}

// ---------------------------------------------------------------------------
// Byte-exactness vs the immutable reference (ExtractMXTileInt64) — real tiles.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(air_byte_exact_random_tiles)
{
    for (uint8_t seed = 1; seed <= 8; ++seed) {
        for (uint32_t bj = 0; bj < 3; ++bj) {
            air::TilePublic pub = MakePub(seed, /*i=*/seed * 3 + 1, bj);
            std::array<int64_t, kRCMxBlockLen> in{};
            Lcg rng(0xF00D0000ull + seed * 131 + bj);
            for (auto& v : in) {
                // Spread across int32 range plus occasional int64 magnitudes.
                const uint64_t r = rng.next();
                if ((r & 7) == 0) {
                    in[&v - in.data()] = static_cast<int64_t>(r);  // may exceed 2^31
                } else {
                    v = static_cast<int32_t>(static_cast<uint32_t>(r));
                }
            }
            BOOST_CHECK_MESSAGE(air::ByteExactVsReference(pub, in),
                                "byte-exact failed seed=" << int(seed) << " bj=" << bj);
        }
    }
}

// ---------------------------------------------------------------------------
// Byte-exactness on boundary tiles: ~2^24, cancellation, max scale, the >2^31
// fold branch, INT32 boundaries, INT64 extremes. (Blueprint hard rule.)
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(air_byte_exact_boundary_tiles)
{
    const int64_t kI32Min = std::numeric_limits<int32_t>::min();
    const int64_t kI32Max = std::numeric_limits<int32_t>::max();
    std::vector<std::array<int64_t, kRCMxBlockLen>> cases;

    // Case A: values around ±2^24.
    {
        std::array<int64_t, kRCMxBlockLen> in{};
        for (uint32_t t = 0; t < kRCMxBlockLen; ++t)
            in[t] = (int64_t{1} << 24) + (t - 16) * 3;
        cases.push_back(in);
    }
    // Case B: cancellation / zeros / small.
    {
        std::array<int64_t, kRCMxBlockLen> in{};
        for (uint32_t t = 0; t < kRCMxBlockLen; ++t)
            in[t] = (t % 2 == 0) ? 0 : ((t % 4 == 1) ? -1 : 1);
        cases.push_back(in);
    }
    // Case C: the >2^31 fold branch (fold path in ExtractMixBitsFromInt64).
    {
        std::array<int64_t, kRCMxBlockLen> in{};
        for (uint32_t t = 0; t < kRCMxBlockLen; ++t)
            in[t] = (int64_t{1} << 40) + (int64_t{1} << 33) * (t + 1);
        cases.push_back(in);
    }
    // Case D: large NEGATIVE beyond -2^31 (fold branch, sign set).
    {
        std::array<int64_t, kRCMxBlockLen> in{};
        for (uint32_t t = 0; t < kRCMxBlockLen; ++t)
            in[t] = -((int64_t{1} << 40) + (int64_t{1} << 32) * (t + 1));
        cases.push_back(in);
    }
    // Case E: exact INT32 boundaries and INT64 extremes.
    {
        std::array<int64_t, kRCMxBlockLen> in{};
        const int64_t vals[] = {kI32Min, kI32Max, kI32Min - 1, kI32Max + 1,
                                std::numeric_limits<int64_t>::min(),
                                std::numeric_limits<int64_t>::max(), 0, -1};
        for (uint32_t t = 0; t < kRCMxBlockLen; ++t) in[t] = vals[t % 8];
        cases.push_back(in);
    }
    // Case F: negative in-range [-2^31, 0) — exercises the branch DIFFERENCE
    // (in-range keeps lo; fold would xor with 0xFFFFFFFF).
    {
        std::array<int64_t, kRCMxBlockLen> in{};
        for (uint32_t t = 0; t < kRCMxBlockLen; ++t)
            in[t] = -(int64_t{1} + (t << 20));
        cases.push_back(in);
    }

    // Try multiple scale values by varying (prf,i,bj) so all e in {0,1,2,3}
    // (max scale = 8x) are exercised across the sweep.
    for (uint8_t seed = 1; seed <= 6; ++seed) {
        for (uint32_t bj = 0; bj < 4; ++bj) {
            air::TilePublic pub = MakePub(seed, seed + bj, bj);
            for (const auto& in : cases) {
                BOOST_CHECK_MESSAGE(air::ByteExactVsReference(pub, in),
                    "boundary byte-exact failed seed=" << int(seed) << " bj=" << bj);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Full constraint system accepts an honest witness.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(air_constraints_accept_honest)
{
    air::TableTM tm; air::TableTX tx;
    for (uint8_t seed = 1; seed <= 4; ++seed) {
        air::TilePublic pub = MakePub(seed, 5 + seed, seed % 3);
        std::array<int64_t, kRCMxBlockLen> in{};
        Lcg rng(seed * 999 + 7);
        for (auto& v : in) v = static_cast<int64_t>(rng.next());
        air::TileWitness w = air::TraceTile(pub, in);
        air::TileCheckResult r = air::CheckTileConstraints(w, tm, tx);
        BOOST_CHECK_MESSAGE(r.ok, "honest witness rejected: " << r.failure);
    }
}

// ---------------------------------------------------------------------------
// Dual-alpha LogUp: honest aggregate verifies over BOTH alphas; report bits.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(air_logup_dual_alpha_honest)
{
    air::TableTM tm; air::TableTX tx;
    air::LogUpInstance i_tm, i_tx, i_r16;
    air::TilePublic pub = MakePub(3, 11, 1);
    std::array<int64_t, kRCMxBlockLen> in{};
    Lcg rng(0x5151);
    for (auto& v : in) v = static_cast<int64_t>(rng.next());
    air::TileWitness w = air::TraceTile(pub, in);
    air::AppendTileLookups(w, tm, tx, Gamma(), i_tm, i_tx, i_r16);
    air::FinalizeTableMultiplicities(i_tm, i_tx, i_r16);

    std::vector<air::LogUpInstance> insts = {i_tm, i_tx, i_r16};
    air::LogUpVerifyResult res = air::LogUpDualAlphaVerify(insts, Alpha1(), Alpha2());
    BOOST_CHECK_MESSAGE(res.ok, "honest dual-alpha LogUp failed: " << res.failure);
    BOOST_CHECK(res.sum_ok_a1 && res.sum_ok_a2);
    BOOST_TEST_MESSAGE("dual-alpha achieved bits (this N) = " << res.achieved_bits
                       << "  (N_w=" << res.n_witness << " N_t=" << res.n_table << ")");
    // Even a single tile clears the 64-bit target by a wide margin.
    BOOST_CHECK(res.achieved_bits > 64.0);
}

// ---------------------------------------------------------------------------
// ADVERSARIAL (a): forge an Extract witness inconsistent with its input.
// MUST reject.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(air_forgery_output_inconsistent_with_input)
{
    air::TableTM tm; air::TableTX tx;
    air::TilePublic pub = MakePub(2, 4, 0);
    std::array<int64_t, kRCMxBlockLen> in{};
    Lcg rng(0xABCD);
    for (auto& v : in) v = static_cast<int64_t>(rng.next());

    // Forgery 1: tamper the final output (claim a wrong extract_out).
    {
        air::TileWitness w = air::TraceTile(pub, in);
        BOOST_REQUIRE(air::CheckTileConstraints(w, tm, tx).ok);
        w.out[7] = static_cast<int8_t>(w.out[7] + 1);
        air::TileCheckResult r = air::CheckTileConstraints(w, tm, tx);
        BOOST_CHECK_MESSAGE(!r.ok, "forged output was NOT rejected");
    }
    // Forgery 2: tamper a mantissa (accepted value) without touching sampler.
    {
        air::TileWitness w = air::TraceTile(pub, in);
        w.mantissa[3] = static_cast<int8_t>(-w.mantissa[3] - 1);
        air::TileCheckResult r = air::CheckTileConstraints(w, tm, tx);
        BOOST_CHECK_MESSAGE(!r.ok, "forged mantissa was NOT rejected");
    }
    // Forgery 3: swap the committed input y for one candidate but keep the
    // downstream mixing witnesses — breaks the field-embedding/golden binding.
    {
        air::TileWitness w = air::TraceTile(pub, in);
        w.input[0] = w.input[0] ^ int64_t{0x5555};  // mutate committed input
        air::TileCheckResult r = air::CheckTileConstraints(w, tm, tx);
        BOOST_CHECK_MESSAGE(!r.ok, "input/witness inconsistency was NOT rejected");
    }
    // Forgery 4: flip the MixBits branch bit (claim in-range for a fold value).
    {
        // Force a fold-branch value so flipping the branch changes u_mix.
        std::array<int64_t, kRCMxBlockLen> fold_in = in;
        for (auto& v : fold_in) v = (int64_t{1} << 45) + 12345;
        air::TileWitness w = air::TraceTile(pub, fold_in);
        BOOST_REQUIRE(air::CheckTileConstraints(w, tm, tx).ok);
        // find a candidate on a fold value and flip its branch + keep u_mix.
        bool flipped = false;
        for (auto& c : w.cands) {
            if (c.branch == 0) { c.branch = 1; flipped = true; break; }
        }
        BOOST_REQUIRE(flipped);
        air::TileCheckResult r = air::CheckTileConstraints(w, tm, tx);
        BOOST_CHECK_MESSAGE(!r.ok, "forged branch bit was NOT rejected");
    }
}

// ---------------------------------------------------------------------------
// ADVERSARIAL (b): forge a lookup multiplicity. MUST reject.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(air_forgery_lookup_multiplicity)
{
    air::TableTM tm; air::TableTX tx;
    air::LogUpInstance i_tm, i_tx, i_r16;
    air::TilePublic pub = MakePub(5, 2, 2);
    std::array<int64_t, kRCMxBlockLen> in{};
    Lcg rng(0x0202);
    for (auto& v : in) v = static_cast<int64_t>(rng.next());
    air::TileWitness w = air::TraceTile(pub, in);
    air::AppendTileLookups(w, tm, tx, Gamma(), i_tm, i_tx, i_r16);
    air::FinalizeTableMultiplicities(i_tm, i_tx, i_r16);

    // Bump one T_X multiplicity: the psi-side sum no longer matches phi-side.
    // Find a table row with nonzero mult to perturb (any row works for the sum).
    i_tx.table_mult[0] += 1;
    std::vector<air::LogUpInstance> insts = {i_tm, i_tx, i_r16};
    air::LogUpVerifyResult res = air::LogUpDualAlphaVerify(insts, Alpha1(), Alpha2());
    BOOST_CHECK_MESSAGE(!res.ok, "forged multiplicity was NOT rejected");
}

// A false membership (witness tuple absent from the preprocessed table) must
// also be rejected under dual-alpha.
BOOST_AUTO_TEST_CASE(air_forgery_false_membership)
{
    air::TableTM tm; air::TableTX tx;
    air::LogUpInstance i_tm, i_tx, i_r16;
    air::TilePublic pub = MakePub(6, 3, 0);
    std::array<int64_t, kRCMxBlockLen> in{};
    Lcg rng(0x0303);
    for (auto& v : in) v = static_cast<int64_t>(rng.next());
    air::TileWitness w = air::TraceTile(pub, in);
    air::AppendTileLookups(w, tm, tx, Gamma(), i_tm, i_tx, i_r16);
    air::FinalizeTableMultiplicities(i_tm, i_tx, i_r16);

    // Inject a witness tuple that is NOT a valid T_M row (acc/mu mismatch):
    // claim nibble 1 (a REJECTED code) has acc=1, mu=5.
    i_tm.witness.push_back(
        gf::Add(gf::Fp2::FromFp(gf::FromU64(1)),
                gf::Add(gf::Mul(Gamma(), gf::Fp2::FromFp(gf::FromU64(1))),
                        gf::Mul(gf::Mul(Gamma(), Gamma()), gf::Fp2::FromFp(gf::FromU64(5))))));

    std::vector<air::LogUpInstance> insts = {i_tm, i_tx, i_r16};
    air::LogUpVerifyResult res = air::LogUpDualAlphaVerify(insts, Alpha1(), Alpha2());
    BOOST_CHECK_MESSAGE(!res.ok, "false T_M membership was NOT rejected");
}

// ---------------------------------------------------------------------------
// ADVERSARIAL (c): swap a ChaCha20 / SHA-256 intermediate. MUST reject.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(air_forgery_swap_chacha_sha_intermediate)
{
    air::TableTM tm; air::TableTX tx;
    air::TilePublic pub = MakePub(4, 9, 1);
    std::array<int64_t, kRCMxBlockLen> in{};
    Lcg rng(0x0909);
    for (auto& v : in) v = static_cast<int64_t>(rng.next());

    // Swap a ChaCha keystream byte: C-E1 keystream binding must fail.
    {
        air::TileWitness w = air::TraceTile(pub, in);
        BOOST_REQUIRE(air::CheckTileConstraints(w, tm, tx).ok);
        BOOST_REQUIRE(!w.keystream.empty());
        w.keystream[5] = static_cast<uint8_t>(w.keystream[5] ^ 0x40);
        air::TileCheckResult r = air::CheckTileConstraints(w, tm, tx);
        BOOST_CHECK_MESSAGE(!r.ok, "swapped ChaCha keystream byte NOT rejected");
    }
    // Swap the SHA scale byte0: C-E10 scale binding must fail.
    {
        air::TileWitness w = air::TraceTile(pub, in);
        BOOST_REQUIRE(air::CheckTileConstraints(w, tm, tx).ok);
        w.scale_byte0 = static_cast<uint8_t>(w.scale_byte0 ^ 0x80);
        air::TileCheckResult r = air::CheckTileConstraints(w, tm, tx);
        BOOST_CHECK_MESSAGE(!r.ok, "swapped SHA scale byte NOT rejected");
    }
    // Forge the derived scale e (claim a different power-of-two scale): the
    // in-circuit SHA recomputation disagrees.
    {
        air::TileWitness w = air::TraceTile(pub, in);
        w.scale_e = static_cast<uint8_t>((w.scale_e + 1) & 3);
        air::TileCheckResult r = air::CheckTileConstraints(w, tm, tx);
        BOOST_CHECK_MESSAGE(!r.ok, "forged scale e NOT rejected");
    }
    // AIR-level intermediate swaps: tamper a ChaCha quarter-round add result
    // and a SHA round working variable — both must be rejected by the ARX
    // constraint checker directly (not just at the output boundary).
    BOOST_CHECK_MESSAGE(air::ChaChaIntermediateTamperRejected(),
                        "tampered ChaCha20 intermediate NOT rejected");
    BOOST_CHECK_MESSAGE(air::ShaIntermediateTamperRejected(),
                        "tampered SHA-256 intermediate NOT rejected");
}

// ---------------------------------------------------------------------------
// MxExpand operand-expansion AIR (§5.7): byte-exact vs ExpandMxDequantInt8 and
// SHA-intermediate tamper rejection.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(air_mxexpand_byte_exact_and_tamper)
{
    // Byte-exact binding vs the immutable reference over several seeds/dims.
    for (uint8_t s = 1; s <= 5; ++s) {
        const uint256 seed = MakePrf(s);
        BOOST_CHECK_MESSAGE(air::MxExpandByteExactVsReference(seed, 32, 32),
                            "MxExpand AIR not byte-exact vs ExpandMxDequantInt8 (32x32)");
        BOOST_CHECK_MESSAGE(air::MxExpandByteExactVsReference(seed, 32, 64),
                            "MxExpand AIR not byte-exact vs ExpandMxDequantInt8 (32x64)");
    }
    // A tampered mantissa-XOF SHA intermediate must be rejected.
    BOOST_CHECK_MESSAGE(air::MxExpandIntermediateTamperRejected(),
                        "tampered MxExpand SHA intermediate NOT rejected");
    // A forged operand column (one byte flipped) must fail the dequant binding.
    {
        const uint256 seed = MakePrf(9);
        std::vector<int8_t> col = matmul::v4::rc::ExpandMxDequantInt8(seed, 32, 32);
        col[17] = static_cast<int8_t>(col[17] ^ 0x02);
        air::TableTM tm;
        air::LogUpInstance inst_tm;
        const air::MxExpandVerifyResult r =
            air::VerifyMxExpandColumn(seed, 32, 32, col, tm, Gamma(), inst_tm);
        BOOST_CHECK_MESSAGE(!r.ok, "forged MxExpand operand byte NOT rejected");
    }
}

// ---------------------------------------------------------------------------
// Tile-tree AIR (§6.3): recomputes the RoundMerkleStream root in-circuit,
// matches the reference, and rejects a forged root / tampered SHA intermediate.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(air_tiletree_binding_and_tamper)
{
    // Build a stream and check the in-circuit root equals BuildTileTreeRoot.
    std::vector<int8_t> stream(1000);
    Lcg rng(0xBEEF);
    for (auto& v : stream) v = static_cast<int8_t>(rng.next());
    const uint32_t t_leaf = 64;
    const uint256 root = matmul::v4::rc::BuildTileTreeRoot(stream, t_leaf);

    air::TileTreeCheckResult ok = air::CheckTileTreeInCircuit(stream, t_leaf, root);
    BOOST_CHECK_MESSAGE(ok.ok, "in-circuit tile-tree root != reference: " + ok.failure);
    BOOST_CHECK(ok.root == root);

    // A forged root must be rejected.
    uint256 bad = root;
    bad.data()[0] ^= 0xFF;
    air::TileTreeCheckResult r = air::CheckTileTreeInCircuit(stream, t_leaf, bad);
    BOOST_CHECK_MESSAGE(!r.ok, "forged tile-tree root NOT rejected");

    // A tampered stream byte changes the root → reject against the honest root.
    std::vector<int8_t> tampered = stream;
    tampered[123] = static_cast<int8_t>(tampered[123] ^ 0x40);
    air::TileTreeCheckResult r2 = air::CheckTileTreeInCircuit(tampered, t_leaf, root);
    BOOST_CHECK_MESSAGE(!r2.ok, "tampered tile-tree stream NOT rejected");

    // A tampered SHA intermediate inside a tile-tree hash must be rejected.
    BOOST_CHECK_MESSAGE(air::TileTreeIntermediateTamperRejected(),
                        "tampered tile-tree SHA intermediate NOT rejected");
}

BOOST_AUTO_TEST_SUITE_END()

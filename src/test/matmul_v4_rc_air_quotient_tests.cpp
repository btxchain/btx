// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_extract.h>
#include <matmul/matmul_v4_rc_fri.h>
#include <matmul/matmul_v4_rc_gkr_air.h>
#include <matmul/matmul_v4_rc_gkr_field_ext.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace aq = matmul::v4::rc::air_quotient;
namespace air = matmul::v4::rc::gkr_air;
namespace gf = matmul::v4::rc::gkr_field;
using matmul::v4::rc::kRCMxBlockLen;

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_air_quotient_tests)

namespace {

uint256 MakePrf(uint8_t seed)
{
    std::array<uint8_t, 32> b{};
    for (int i = 0; i < 32; ++i) b[i] = static_cast<uint8_t>(seed * 7 + i * 31 + 1);
    return uint256{Span<const unsigned char>{b.data(), b.size()}};
}

uint256 MakeSeed(uint8_t tag)
{
    std::array<uint8_t, 32> b{};
    for (int i = 0; i < 32; ++i) b[i] = static_cast<uint8_t>(tag * 13 + i * 5 + 3);
    return uint256{Span<const unsigned char>{b.data(), b.size()}};
}

std::array<int64_t, kRCMxBlockLen> MakeInput(int64_t base)
{
    std::array<int64_t, kRCMxBlockLen> in{};
    for (uint32_t t = 0; t < kRCMxBlockLen; ++t) {
        const int64_t v = base + static_cast<int64_t>(t) * 977;
        in[t] = (t % 3 == 0) ? -v : v;  // mix signs to exercise the MixBits branch
    }
    in[5] = int64_t{1} << 40;  // out-of-int32-range value (fold branch)
    in[9] = -(int64_t{1} << 45);
    return in;
}

const air::TileWitness& SharedWitness()
{
    static const air::TileWitness w = [] {
        air::TilePublic pub;
        pub.prf_key = MakePrf(11);
        pub.i = 3;
        pub.bj = 7;
        return air::TraceTile(pub, MakeInput(1000));
    }();
    return w;
}

gf::Fp PowBase(gf::Fp b, uint64_t e)
{
    gf::Fp r = 1;
    while (e > 0) {
        if (e & 1) r = gf::Mul(r, b);
        b = gf::Mul(b, b);
        e >>= 1;
    }
    return r;
}

} // namespace

// The degree-4 acceptance selector must agree with the row-scan AIR's
// polynomial and with the canonical T_M acceptance bit on all 16 codes.
BOOST_AUTO_TEST_CASE(accept_poly_matches_reference)
{
    const air::TableTM tm;
    for (uint16_t n = 0; n < 16; ++n) {
        const gf::Fp2 b0 = gf::Fp2::FromFp((n >> 0) & 1);
        const gf::Fp2 b1 = gf::Fp2::FromFp((n >> 1) & 1);
        const gf::Fp2 b2 = gf::Fp2::FromFp((n >> 2) & 1);
        const gf::Fp2 b3 = gf::Fp2::FromFp((n >> 3) & 1);
        const gf::Fp2 got = aq::AirAcceptPoly<gf::Fp2>(b0, b1, b2, b3);
        BOOST_CHECK(gf::Eq(got, gf::Fp2::FromFp(gf::FromU64(tm.acc[n]))));
        const gf::Fp ref = air::AirAcceptNibblePoly((n >> 0) & 1, (n >> 1) & 1,
                                                    (n >> 2) & 1, (n >> 3) & 1);
        BOOST_CHECK_EQUAL(gf::Canonical(got.c0), gf::Canonical(ref));
    }
}

// Honest trace: exact division, verifier accepts at the Q = 128 query points;
// a wrong PUBLIC input (scale_e) is rejected.
BOOST_AUTO_TEST_CASE(honest_roundtrip_fp2)
{
    const air::TableTM tm;
    const air::TileWitness& w = SharedWitness();
    const uint256 seed = MakeSeed(1);

    aq::RcSamplerBuild<gf::Fp2> b = aq::BuildRcSamplerInstance<gf::Fp2>(w, tm, seed);
    BOOST_REQUIRE_MESSAGE(b.ok, b.note);
    BOOST_REQUIRE_EQUAL(b.columns.size(), static_cast<size_t>(aq::kRcSamplerNumCols));

    const aq::AirQuotientProveResult<gf::Fp2> pr =
        aq::AirQuotientProve<gf::Fp2>(b.cs, b.columns, seed);
    BOOST_REQUIRE_MESSAGE(pr.ok, pr.note);
    BOOST_CHECK(pr.division_exact);
    for (const auto& r : pr.remainder) BOOST_CHECK(gf::IsZero(r));
    BOOST_CHECK_EQUAL(pr.proof.batch.queries.size(),
                      static_cast<size_t>(matmul::v4::rc::kRCFriBatchNumQueries));
    BOOST_CHECK_EQUAL(pr.proof.batch.columns.size(),
                      static_cast<size_t>(aq::kRcSamplerNumCols) + 1);

    std::string why;
    BOOST_CHECK_MESSAGE(
        aq::RcSamplerAirVerify<gf::Fp2>(pr.proof, seed, w.scale_e, tm, &why), why);

    // Public-input binding: verifying against a different scale must fail.
    BOOST_CHECK(!aq::RcSamplerAirVerify<gf::Fp2>(
        pr.proof, seed, static_cast<uint8_t>(w.scale_e ^ 1u), tm, &why));

    // Fiat–Shamir seed binding: a different seed must fail.
    BOOST_CHECK(!aq::RcSamplerAirVerify<gf::Fp2>(pr.proof, MakeSeed(2), w.scale_e, tm, &why));
}

// The coset shift keeps Z_H nonzero at EVERY point the batched FRI can open:
// (g·ω^i)^N != 1 for the whole LDE domain (g = 7, ord(g) = p−1 has odd
// factors, so g·x never lies in a power-of-two subgroup).
BOOST_AUTO_TEST_CASE(zh_nonzero_on_whole_coset_domain)
{
    const uint32_t N = 64;
    const uint32_t n_lde = 256 * matmul::v4::rc::kRCFriBlowup;  // n_coeffs=256 as in the demo
    // omega for the LDE domain: kAirOmega2_32^(2^32 / n_lde) — recompute via
    // the public FriNextPow2-free route: omega_lde = root of unity of order n_lde.
    const gf::Fp omega32 = 0x185629dcda58878cULL;
    uint32_t logn = 0;
    for (uint32_t t = n_lde; t > 1; t >>= 1) ++logn;
    const gf::Fp omega_lde = PowBase(omega32, 1ull << (32 - logn));
    gf::Fp x = 1;
    uint32_t in_h = 0;
    for (uint32_t i = 0; i < n_lde; ++i) {
        const gf::Fp y = gf::Mul(7, x);
        BOOST_REQUIRE(gf::Canonical(PowBase(y, N)) != 1);       // coset: Z_H(y) != 0
        if (gf::Canonical(PowBase(x, N)) == 1) ++in_h;          // plain domain hits H
        x = gf::Mul(x, omega_lde);
    }
    // Without the coset shift, exactly N of the n_lde plain-domain points lie
    // in H (Z_H = 0 there) — the shift is what removes every such degeneracy.
    BOOST_CHECK_EQUAL(in_h, N);
}

// A single tampered row makes the division inexact (nonzero remainder) and a
// force-committed proof is rejected at the query points.
BOOST_AUTO_TEST_CASE(tampered_row_rejected_fp2)
{
    const air::TableTM tm;
    const air::TileWitness& w = SharedWitness();
    const uint256 seed = MakeSeed(3);

    aq::RcSamplerBuild<gf::Fp2> b = aq::BuildRcSamplerInstance<gf::Fp2>(w, tm, seed);
    BOOST_REQUIRE_MESSAGE(b.ok, b.note);

    // (a) Tamper the dequant output of one row.
    {
        auto cols = b.columns;
        cols[aq::kColOut][3] = gf::Add(cols[aq::kColOut][3], gf::Fp2::One());
        aq::AirProveOptions opt;
        const aq::AirQuotientProveResult<gf::Fp2> strict =
            aq::AirQuotientProve<gf::Fp2>(b.cs, cols, seed, opt);
        BOOST_CHECK(!strict.ok);            // refuses to commit by default
        BOOST_CHECK(!strict.division_exact);
        bool any_nonzero = false;
        for (const auto& r : strict.remainder) any_nonzero |= !gf::IsZero(r);
        BOOST_CHECK(any_nonzero);

        opt.force_commit_on_inexact = true;
        const aq::AirQuotientProveResult<gf::Fp2> forced =
            aq::AirQuotientProve<gf::Fp2>(b.cs, cols, seed, opt);
        BOOST_REQUIRE_MESSAGE(forced.ok, forced.note);
        BOOST_CHECK(!forced.division_exact);
        std::string why;
        BOOST_CHECK(!aq::RcSamplerAirVerify<gf::Fp2>(forced.proof, seed, w.scale_e, tm, &why));
        BOOST_TEST_MESSAGE("tampered out[] rejected: " << why);
    }

    // (b) Tamper an acceptance bit on a candidate row (sampler rule).
    {
        auto cols = b.columns;
        cols[aq::kColAcc][2] =
            gf::Sub(gf::Fp2::One(), cols[aq::kColAcc][2]);  // flip 0<->1
        aq::AirProveOptions opt;
        opt.force_commit_on_inexact = true;
        const aq::AirQuotientProveResult<gf::Fp2> forced =
            aq::AirQuotientProve<gf::Fp2>(b.cs, cols, seed, opt);
        BOOST_REQUIRE_MESSAGE(forced.ok, forced.note);
        BOOST_CHECK(!forced.division_exact);
        std::string why;
        BOOST_CHECK(!aq::RcSamplerAirVerify<gf::Fp2>(forced.proof, seed, w.scale_e, tm, &why));
    }
}

// Degree-bound enforcement: a quotient committed with any length other than
// the declared bound (in particular an over-degree one) is rejected
// structurally before any query work.
BOOST_AUTO_TEST_CASE(overdegree_quotient_rejected_fp2)
{
    const air::TableTM tm;
    const air::TileWitness& w = SharedWitness();
    const uint256 seed = MakeSeed(4);

    aq::RcSamplerBuild<gf::Fp2> b = aq::BuildRcSamplerInstance<gf::Fp2>(w, tm, seed);
    BOOST_REQUIRE_MESSAGE(b.ok, b.note);

    aq::AirProveOptions opt;
    opt.quotient_len_override = b.cs.QuotientLen() + 8;
    const aq::AirQuotientProveResult<gf::Fp2> pr =
        aq::AirQuotientProve<gf::Fp2>(b.cs, b.columns, seed, opt);
    BOOST_REQUIRE_MESSAGE(pr.ok, pr.note);
    BOOST_CHECK(pr.division_exact);  // the trace is honest; only the bound lies

    std::string why;
    BOOST_CHECK(!aq::RcSamplerAirVerify<gf::Fp2>(pr.proof, seed, w.scale_e, tm, &why));
    BOOST_CHECK_EQUAL(why, "quotient degree bound mismatch");
}

// Theorem-5.1 style clone attack: replace the LogUp table side with the
// witness multiset itself (t := w, m := 1, ψ := φ, S := 0). Every ALGEBRAIC
// constraint then holds (the division is exact!) — the attack is caught ONLY
// by the preprocessed-column root regeneration.
BOOST_AUTO_TEST_CASE(logup_clone_table_rejected_fp2)
{
    const air::TableTM tm;
    const air::TileWitness& w = SharedWitness();
    const uint256 seed = MakeSeed(5);

    aq::RcSamplerBuild<gf::Fp2> b = aq::BuildRcSamplerInstance<gf::Fp2>(w, tm, seed);
    BOOST_REQUIRE_MESSAGE(b.ok, b.note);
    const uint32_t N = b.n_rows;

    auto cols = b.columns;
    const gf::Fp2 g2 = gf::Mul(b.gamma, b.gamma);
    for (uint32_t r = 0; r < N; ++r) {
        const gf::Fp2 wfp =
            gf::Add(cols[aq::kColMixed][r],
                    gf::Add(gf::Mul(b.gamma, cols[aq::kColAcc][r]),
                            gf::Mul(g2, cols[aq::kColMu][r])));
        cols[aq::kColTfp][r] = wfp;                       // table := witness (clone)
        cols[aq::kColM][r] = gf::Fp2::One();              // multiplicity 1 each
        cols[aq::kColPsi][r] = cols[aq::kColPhi][r];      // ψ = φ trivially balances
        cols[aq::kColS][r] = gf::Fp2::Zero();             // telescope stays at zero
    }

    aq::AirProveOptions opt;
    const aq::AirQuotientProveResult<gf::Fp2> pr =
        aq::AirQuotientProve<gf::Fp2>(b.cs, cols, seed, opt);
    BOOST_REQUIRE_MESSAGE(pr.ok, pr.note);
    BOOST_CHECK(pr.division_exact);  // algebra alone cannot see the clone

    std::string why;
    BOOST_CHECK(!aq::RcSamplerAirVerify<gf::Fp2>(pr.proof, seed, w.scale_e, tm, &why));
    BOOST_CHECK_EQUAL(why, "preprocessed column root mismatch");
}

// Tampering a supplemental next-row opening is caught by its Merkle path.
BOOST_AUTO_TEST_CASE(next_opening_tamper_rejected_fp2)
{
    const air::TableTM tm;
    const air::TileWitness& w = SharedWitness();
    const uint256 seed = MakeSeed(6);

    aq::RcSamplerBuild<gf::Fp2> b = aq::BuildRcSamplerInstance<gf::Fp2>(w, tm, seed);
    BOOST_REQUIRE_MESSAGE(b.ok, b.note);
    aq::AirQuotientProveResult<gf::Fp2> pr = aq::AirQuotientProve<gf::Fp2>(b.cs, b.columns, seed);
    BOOST_REQUIRE_MESSAGE(pr.ok, pr.note);

    std::string why;
    BOOST_REQUIRE(aq::RcSamplerAirVerify<gf::Fp2>(pr.proof, seed, w.scale_e, tm, &why));
    pr.proof.next_openings[0][aq::kColPos].leaf =
        gf::Add(pr.proof.next_openings[0][aq::kColPos].leaf, gf::Fp2::One());
    BOOST_CHECK(!aq::RcSamplerAirVerify<gf::Fp2>(pr.proof, seed, w.scale_e, tm, &why));
    BOOST_CHECK_EQUAL(why, "next-opening merkle");
}

// Field-genericity: the same construction runs over Fp3 (Fri3 batch backend);
// honest accepts, tampered row rejects.
BOOST_AUTO_TEST_CASE(roundtrip_and_tamper_fp3)
{
    const air::TableTM tm;
    const air::TileWitness& w = SharedWitness();
    const uint256 seed = MakeSeed(7);

    aq::RcSamplerBuild<gf::Fp3> b = aq::BuildRcSamplerInstance<gf::Fp3>(w, tm, seed);
    BOOST_REQUIRE_MESSAGE(b.ok, b.note);

    const aq::AirQuotientProveResult<gf::Fp3> pr =
        aq::AirQuotientProve<gf::Fp3>(b.cs, b.columns, seed);
    BOOST_REQUIRE_MESSAGE(pr.ok, pr.note);
    BOOST_CHECK(pr.division_exact);
    std::string why;
    BOOST_CHECK_MESSAGE(
        aq::RcSamplerAirVerify<gf::Fp3>(pr.proof, seed, w.scale_e, tm, &why), why);

    auto cols = b.columns;
    cols[aq::kColOut][7] = gf::Add(cols[aq::kColOut][7], gf::Fp3::One());
    aq::AirProveOptions opt;
    opt.force_commit_on_inexact = true;
    const aq::AirQuotientProveResult<gf::Fp3> forced =
        aq::AirQuotientProve<gf::Fp3>(b.cs, cols, seed, opt);
    BOOST_REQUIRE_MESSAGE(forced.ok, forced.note);
    BOOST_CHECK(!forced.division_exact);
    BOOST_CHECK(!aq::RcSamplerAirVerify<gf::Fp3>(forced.proof, seed, w.scale_e, tm, &why));
}

BOOST_AUTO_TEST_SUITE_END()

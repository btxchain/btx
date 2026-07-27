// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_alg_hash.h>
#include <matmul/matmul_v4_rc_stage3_poseidon_air.h>
#include <matmul/matmul_v4_rc_extract.h>
#include <matmul/matmul_v4_rc_fri.h>
#include <matmul/matmul_v4_rc_gkr_air.h>
#include <matmul/matmul_v4_rc_gkr_field_ext.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

namespace aq = matmul::v4::rc::air_quotient;
namespace air = matmul::v4::rc::gkr_air;
namespace gf = matmul::v4::rc::gkr_field;
namespace rc = matmul::v4::rc;
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

void AppendU32(std::vector<unsigned char>& out, uint32_t value)
{
    for (uint32_t i = 0; i < 4; ++i) {
        out.push_back(
            static_cast<unsigned char>(value >> (8U * i)));
    }
}

void PutLE32(
    std::vector<unsigned char>& bytes,
    size_t offset,
    uint32_t value)
{
    BOOST_REQUIRE_LE(offset + 4, bytes.size());
    for (uint32_t byte = 0; byte < 4; ++byte) {
        bytes[offset + byte] =
            static_cast<unsigned char>(
                value >> (8 * byte));
    }
}

void AppendU64(std::vector<unsigned char>& out, uint64_t value)
{
    for (uint32_t i = 0; i < 8; ++i) {
        out.push_back(
            static_cast<unsigned char>(value >> (8U * i)));
    }
}

void AppendUint256(
    std::vector<unsigned char>& out, const uint256& value)
{
    out.insert(
        out.end(), value.data(), value.data() + value.size());
}

void AppendFp3(
    std::vector<unsigned char>& out, const gf::Fp3& value)
{
    AppendU64(out, gf::Canonical(value.c0));
    AppendU64(out, gf::Canonical(value.c1));
    AppendU64(out, gf::Canonical(value.c2));
}

template <typename Backend>
bool SerializeAirFp3ProofForTest(
    const aq::AirQuotientProof<gf::Fp3, Backend>& proof,
    std::vector<unsigned char>& out)
{
    std::vector<unsigned char> batch;
    if (matmul::v4::rc::SerializeFri3BatchProof(
            proof.batch, batch) == 0) {
        return false;
    }
    out.clear();
    AppendU32(out, static_cast<uint32_t>(batch.size()));
    out.insert(out.end(), batch.begin(), batch.end());
    AppendUint256(out, proof.trace_commit);
    AppendU32(
        out, static_cast<uint32_t>(proof.next_openings.size()));
    for (const auto& row : proof.next_openings) {
        AppendU32(out, static_cast<uint32_t>(row.size()));
        for (const auto& path : row) {
            AppendU32(out, path.index);
            AppendFp3(out, path.leaf);
            AppendU32(
                out,
                static_cast<uint32_t>(path.siblings.size()));
            for (const auto& sibling : path.siblings) {
                AppendUint256(out, sibling);
            }
        }
    }
    return true;
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
// witness multiset itself (t := w, m := 1, ψ := φ, S := 0). Under the ONLINE
// fingerprint the committed f = kColTfp is bound by the in-circuit
// logup.tfp.bind identity to the CHALLENGE-INDEPENDENT preprocessed table
// columns (tbl_a/b/c). The clone sets f to the witness fingerprint while the
// table columns stay canonical, so f != tbl_a+γ·tbl_b+γ²·tbl_c on the grafted
// rows: the ALGEBRA now catches the clone (the division is inexact), where the
// old γ-baked preprocessed t_fp could only be caught by root regeneration.
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
        cols[aq::kColTfp][r] = wfp;                       // clone f := witness fp
        cols[aq::kColM][r] = gf::Fp2::One();              // multiplicity 1 each
        cols[aq::kColPsi][r] = cols[aq::kColPhi][r];      // ψ = φ trivially balances
        cols[aq::kColS][r] = gf::Fp2::Zero();             // telescope stays at zero
    }

    // Algebra SEES the clone now: logup.tfp.bind is violated, remainder != 0.
    aq::AirProveOptions strict;
    const aq::AirQuotientProveResult<gf::Fp2> strict_pr =
        aq::AirQuotientProve<gf::Fp2>(b.cs, cols, seed, strict);
    BOOST_CHECK(!strict_pr.division_exact);

    aq::AirProveOptions opt;
    opt.force_commit_on_inexact = true;
    const aq::AirQuotientProveResult<gf::Fp2> pr =
        aq::AirQuotientProve<gf::Fp2>(b.cs, cols, seed, opt);
    BOOST_REQUIRE_MESSAGE(pr.ok, pr.note);
    BOOST_CHECK(!pr.division_exact);  // in-circuit fingerprint identity catches it

    std::string why;
    BOOST_CHECK(!aq::RcSamplerAirVerify<gf::Fp2>(pr.proof, seed, w.scale_e, tm, &why));
    BOOST_TEST_MESSAGE("clone rejected by online fingerprint: " << why);
}

// Differential parity + single-row grind tamper for the online fingerprint.
// Templated so BOTH field instantiations (Fp2, Fp3) are exercised.
namespace {
template <typename F>
void OnlineFingerprintParityAndTamper(uint8_t seed_tag)
{
    using T = aq::AirField<F>;
    const air::TableTM tm;
    const air::TileWitness& w = SharedWitness();
    const uint256 seed = MakeSeed(seed_tag);

    aq::RcSamplerBuild<F> b = aq::BuildRcSamplerInstance<F>(w, tm, seed);
    BOOST_REQUIRE_MESSAGE(b.ok, b.note);
    const uint32_t N = b.n_rows;
    const F g2 = T::Mul(b.gamma, b.gamma);

    // (1) Bit-identical parity: committed f == the legacy γ-baked closed form
    //     n + γ·acc[n] + γ²·mu[n] AND == the in-circuit tbl_a+γ·tbl_b+γ²·tbl_c.
    uint32_t mismatches = 0;
    for (uint32_t r = 0; r < N; ++r) {
        const uint32_t n = (r < 16) ? r : 0;
        const F legacy =
            T::Add(T::FromU64(n),
                   T::Add(T::Mul(b.gamma, T::FromU64(tm.acc[n])),
                          T::Mul(g2, T::FromSigned(tm.mu[n]))));
        const F bound =
            T::Add(b.columns[aq::kColTblA][r],
                   T::Add(T::Mul(b.gamma, b.columns[aq::kColTblB][r]),
                          T::Mul(g2, b.columns[aq::kColTblC][r])));
        if (!T::Eq(b.columns[aq::kColTfp][r], legacy)) ++mismatches;
        if (!T::Eq(b.columns[aq::kColTfp][r], bound)) ++mismatches;
    }
    BOOST_CHECK_EQUAL(mismatches, 0U);

    // Honest proof still verifies end-to-end (φ/ψ/S unchanged).
    const aq::AirQuotientProveResult<F> honest =
        aq::AirQuotientProve<F>(b.cs, b.columns, seed);
    BOOST_REQUIRE_MESSAGE(honest.ok, honest.note);
    BOOST_CHECK(honest.division_exact);
    std::string why;
    BOOST_CHECK_MESSAGE(
        aq::RcSamplerAirVerify<F>(honest.proof, seed, w.scale_e, tm, &why), why);

    // (2) Single-row grind: bump the committed fingerprint f on one row while
    //     the pinned table columns stay canonical. logup.tfp.bind rejects it by
    //     algebra — a grind the γ-baked preprocessed column could not catch
    //     at the relation level.
    auto tampered = b.columns;
    tampered[aq::kColTfp][1] = T::Add(tampered[aq::kColTfp][1], T::One());
    aq::AirProveOptions strict;
    const aq::AirQuotientProveResult<F> strict_pr =
        aq::AirQuotientProve<F>(b.cs, tampered, seed, strict);
    BOOST_CHECK(!strict_pr.division_exact);
    aq::AirProveOptions forced_opt;
    forced_opt.force_commit_on_inexact = true;
    const aq::AirQuotientProveResult<F> forced =
        aq::AirQuotientProve<F>(b.cs, tampered, seed, forced_opt);
    BOOST_REQUIRE_MESSAGE(forced.ok, forced.note);
    BOOST_CHECK(!forced.division_exact);
    BOOST_CHECK(!aq::RcSamplerAirVerify<F>(forced.proof, seed, w.scale_e, tm, &why));
}
}  // namespace

BOOST_AUTO_TEST_CASE(online_fingerprint_parity_and_tamper_fp2)
{
    OnlineFingerprintParityAndTamper<gf::Fp2>(9);
}

BOOST_AUTO_TEST_CASE(online_fingerprint_parity_and_tamper_fp3)
{
    OnlineFingerprintParityAndTamper<gf::Fp3>(10);
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

    aq::AirProveOptions hinted_options;
    const uint32_t n_coeffs = matmul::v4::rc::FriNextPow2(
        std::max(b.cs.n_rows, b.cs.QuotientLen()));
    hinted_options.checked_trace_root_hints.resize(
        b.cs.n_columns);
    for (uint32_t column = 0;
         column < b.cs.n_columns; ++column) {
        if ((column & 1U) == 0) {
            hinted_options.checked_trace_root_hints[column] =
                aq::AirCommittedValuesRoot<gf::Fp3>(
                    b.columns[column], n_coeffs);
        }
    }
    const auto hinted =
        aq::AirQuotientProve<gf::Fp3>(
            b.cs, b.columns, seed, hinted_options);
    BOOST_REQUIRE_MESSAGE(hinted.ok, hinted.note);
    std::vector<unsigned char> ordinary_bytes;
    std::vector<unsigned char> hinted_bytes;
    BOOST_REQUIRE(
        SerializeAirFp3ProofForTest(
            pr.proof, ordinary_bytes));
    BOOST_REQUIRE(
        SerializeAirFp3ProofForTest(
            hinted.proof, hinted_bytes));
    BOOST_CHECK_EQUAL_COLLECTIONS(
        ordinary_bytes.begin(), ordinary_bytes.end(),
        hinted_bytes.begin(), hinted_bytes.end());

    using StreamingBackend =
        aq::AirFriBackendFp3StreamingColumns;
    const auto streamed =
        aq::AirQuotientProve<gf::Fp3, StreamingBackend>(
            b.cs, b.columns, seed, hinted_options);
    BOOST_REQUIRE_MESSAGE(streamed.ok, streamed.note);
    std::vector<unsigned char> streamed_bytes;
    BOOST_REQUIRE(
        SerializeAirFp3ProofForTest(
            streamed.proof, streamed_bytes));
    BOOST_CHECK_EQUAL_COLLECTIONS(
        ordinary_bytes.begin(), ordinary_bytes.end(),
        streamed_bytes.begin(), streamed_bytes.end());
    BOOST_CHECK_MESSAGE(
        (aq::AirQuotientVerify<gf::Fp3, StreamingBackend>(
            b.cs, streamed.proof, seed, &why)),
        why);

    auto wrong_hint_options = hinted_options;
    wrong_hint_options.checked_trace_root_hints[0] =
        MakeSeed(0xfe);
    const auto wrong_hint =
        aq::AirQuotientProve<gf::Fp3>(
            b.cs, b.columns, seed, wrong_hint_options);
    BOOST_CHECK(!wrong_hint.ok);
    BOOST_CHECK_EQUAL(
        wrong_hint.note,
        "internal: trace root mismatch vs FriBatchColumnRoot");
    auto wrong_size_options = hinted_options;
    wrong_size_options.checked_trace_root_hints.pop_back();
    const auto wrong_size =
        aq::AirQuotientProve<gf::Fp3>(
            b.cs, b.columns, seed, wrong_size_options);
    BOOST_CHECK(!wrong_size.ok);
    BOOST_CHECK_EQUAL(
        wrong_size.note,
        "checked trace-root hint count mismatch");

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

// ---------------------------------------------------------------------------
// COMPOSITION-SITE (O(W x M) evaluation matrix) — footprint and bit-identity.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(composition_peak_bytes_models_the_measured_real_shape)
{
    // MEASURED shape of the real-role arity-4 aggregate-root self-prove
    // (AIRQ_SHAPE, BTX_AIRQ_REPORT_BYTES): W=384984 N=256 M=2048, Fp3 = 24 B.
    constexpr uint64_t kW = 384984;
    constexpr uint32_t kN = 256;
    constexpr uint32_t kM = 2048;
    constexpr uint64_t kElem = sizeof(gf::Fp3);
    static_assert(kElem == 24, "Fp3 is three Goldilocks limbs");

    // The dense composition matrix is exactly the reported ldeM_bytes.
    BOOST_CHECK_EQUAL(kW * kM * kElem, 18922733568ULL);
    // Coset blocking replaces the W x M slab by a W x N slab.
    BOOST_CHECK_EQUAL(kW * kN * kElem, 2365341696ULL);

    const uint64_t dense = aq::AirQuotientCompositionPeakBytes(
        kW, kN, kM, kElem, /*coset_blocked=*/false, /*threads=*/8);
    const uint64_t coset = aq::AirQuotientCompositionPeakBytes(
        kW, kN, kM, kElem, /*coset_blocked=*/true, /*threads=*/8);
    BOOST_CHECK_GT(dense, coset);
    // Only the slab term differs, and it differs by exactly stepM = M/N.
    BOOST_CHECK_EQUAL(dense - coset, kW * (kM - kN) * kElem);
    // Sanity on the absolute numbers this whole exercise is about. The dense
    // composition site alone projects 21,435,958,272 B = 19.96 GiB at 8
    // prover threads — on its own it does not quite fill the 24 GiB cgroup
    // that OOM-killed the real-width self-prove, but it leaves under 4 GiB for
    // the caller-held witness, `shifted`, and everything else, which is why
    // that run died. Coset blocking takes the same site to under 5 GiB.
    BOOST_CHECK_EQUAL(dense, 21435958272ULL);
    BOOST_CHECK_EQUAL(coset, 4878566400ULL);
    BOOST_CHECK_GT(dense, uint64_t{19} << 30);
    BOOST_CHECK_LT(coset, uint64_t{5} << 30);
}

BOOST_AUTO_TEST_CASE(composition_memory_guard_fails_closed_before_allocation)
{
    // A shape that passes every PRE-EXISTING guard and is still unallocatable
    // here: comfortably under the backend column cap, and the commit-site
    // guard does not look at the composition domain M at all. M grows with the
    // composed constraint degree, so a wide AIR with degree-256 composition
    // lands here while nothing else in the prover notices.
    constexpr uint64_t kW = 384984;
    constexpr uint32_t kN = 256;
    constexpr uint32_t kM = 65536; // stepM = 256
    BOOST_REQUIRE_LT(kW, uint64_t{rc::kRCFri3AlgBatchMaxColumns});
    // Dense here is ~605 GiB: above any plausible ceiling, so this assertion
    // does not depend on the exact default.
    BOOST_REQUIRE_GT(kW * kM * sizeof(gf::Fp3), uint64_t{512} << 30);

    uint64_t projected = 0;
    std::string why;
    // Ceiling below the projected peak -> refuse, with a diagnostic that says
    // which site and that it is not the column cap.
    BOOST_CHECK(!aq::AirQuotientCompositionFitsMemoryBudget(
        kW, kN, kM, sizeof(gf::Fp3), /*coset_blocked=*/false, /*threads=*/8,
        &projected, &why));
    BOOST_CHECK_GT(projected, 0U);
    BOOST_CHECK(why.find("COMPOSITION") != std::string::npos);
    BOOST_CHECK(why.find("not the column cap") != std::string::npos);

    // The coset-blocked schedule of the SAME shape is admitted.
    uint64_t coset_projected = 0;
    std::string coset_why;
    BOOST_CHECK(aq::AirQuotientCompositionFitsMemoryBudget(
        kW, kN, kM, sizeof(gf::Fp3), /*coset_blocked=*/true, /*threads=*/8,
        &coset_projected, &coset_why));
    BOOST_CHECK(coset_why.empty());
    BOOST_CHECK_LT(coset_projected, projected);
}

BOOST_AUTO_TEST_CASE(coset_blocked_composition_is_byte_identical_to_dense)
{
    const air::TableTM tm;
    const air::TileWitness& w = SharedWitness();
    const uint256 seed = MakeSeed(0x5c);

    aq::RcSamplerBuild<gf::Fp3> b = aq::BuildRcSamplerInstance<gf::Fp3>(w, tm, seed);
    BOOST_REQUIRE_MESSAGE(b.ok, b.note);

    // NON-VACUITY OF THE COMPARISON: the two schedules can only differ when
    // the composition domain is strictly larger than H, i.e. stepM > 1. If
    // this instance had M == N the coset route would BE the dense route and a
    // byte-equal result would prove nothing.
    const uint32_t M = std::max(
        b.cs.n_rows,
        matmul::v4::rc::FriNextPow2(
            static_cast<uint32_t>(b.cs.MaxComposedDegreeBound() + 1)));
    BOOST_REQUIRE_GT(M, b.cs.n_rows);
    BOOST_TEST_MESSAGE("COMPOSITION_ROUTE_SHAPE W=" << b.cs.n_columns
                       << " N=" << b.cs.n_rows << " M=" << M
                       << " stepM=" << (M / b.cs.n_rows));

    // Default route: coset-blocked.
    BOOST_REQUIRE(std::getenv("BTX_AIRQ_DENSE_COMPOSITION") == nullptr);
    const auto coset =
        aq::AirQuotientProve<gf::Fp3>(b.cs, b.columns, seed);
    BOOST_REQUIRE_MESSAGE(coset.ok, coset.note);
    BOOST_CHECK(coset.division_exact);

    // Dense control, same binary, same inputs.
    BOOST_REQUIRE_EQUAL(setenv("BTX_AIRQ_DENSE_COMPOSITION", "1", 1), 0);
    const auto dense =
        aq::AirQuotientProve<gf::Fp3>(b.cs, b.columns, seed);
    BOOST_REQUIRE_EQUAL(unsetenv("BTX_AIRQ_DENSE_COMPOSITION"), 0);
    BOOST_REQUIRE_MESSAGE(dense.ok, dense.note);
    BOOST_CHECK(dense.division_exact);

    std::vector<unsigned char> coset_bytes;
    std::vector<unsigned char> dense_bytes;
    BOOST_REQUIRE(SerializeAirFp3ProofForTest(coset.proof, coset_bytes));
    BOOST_REQUIRE(SerializeAirFp3ProofForTest(dense.proof, dense_bytes));
    BOOST_REQUIRE(!coset_bytes.empty());
    BOOST_CHECK_EQUAL_COLLECTIONS(
        coset_bytes.begin(), coset_bytes.end(),
        dense_bytes.begin(), dense_bytes.end());

    // Both remainders are the same object too (the quotient, not just the
    // committed bytes).
    BOOST_REQUIRE_EQUAL(coset.remainder.size(), dense.remainder.size());
    for (size_t i = 0; i < coset.remainder.size(); ++i) {
        BOOST_CHECK(gf::Eq(coset.remainder[i], dense.remainder[i]));
    }

    std::string why;
    BOOST_CHECK_MESSAGE(
        aq::RcSamplerAirVerify<gf::Fp3>(coset.proof, seed, w.scale_e, tm, &why),
        why);
}

BOOST_AUTO_TEST_CASE(
    selector_sparse_row_tiles_and_streamed_fri_are_transcript_identical)
{
    constexpr uint32_t N = 8;
    constexpr uint32_t W = 3;
    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = N;
    cs.n_columns = W;
    cs.preprocessed_pin_ood = true;
    std::vector<std::vector<gf::Fp3>> columns(
        W, std::vector<gf::Fp3>(
               N, gf::Fp3::Zero()));
    for (uint32_t row = 0; row < N; ++row) {
        columns[0][row] =
            gf::Fp3::FromFp(gf::FromU64(1));
        columns[1][row] =
            gf::Fp3::FromFp(gf::FromU64(1));
        if (row < 4) {
            columns[2][row] = gf::Fp3::One();
        }
    }
    cs.preprocessed.emplace_back(2, columns[2]);

    aq::AirConstraint<gf::Fp3> sparse;
    sparse.name = "streaming.audit.sparse";
    sparse.kind = aq::AirKind::kEverywhere;
    sparse.alg_degree = 2;
    sparse.eval =
        [](const std::vector<gf::Fp3>& cur,
           const std::vector<gf::Fp3>&) {
            return gf::Mul(
                cur[2], gf::Sub(cur[0], cur[1]));
        };
    cs.constraints.push_back(std::move(sparse));
    aq::AirConstraint<gf::Fp3> transition;
    transition.name = "streaming.audit.transition";
    transition.kind = aq::AirKind::kTransition;
    transition.alg_degree = 1;
    transition.eval =
        [](const std::vector<gf::Fp3>& cur,
           const std::vector<gf::Fp3>& next) {
            return gf::Sub(next[0], cur[0]);
        };
    cs.constraints.push_back(std::move(transition));
    aq::AirConstraint<gf::Fp3> first;
    first.name = "streaming.audit.first";
    first.kind = aq::AirKind::kFirstRow;
    first.alg_degree = 1;
    first.eval =
        [](const std::vector<gf::Fp3>& cur,
           const std::vector<gf::Fp3>&) {
            return gf::Sub(cur[0], gf::Fp3::One());
        };
    cs.constraints.push_back(std::move(first));

    const uint256 seed = MakeSeed(0x7a);
    const auto tiled =
        aq::AuditAirQuotientRowTilesFp3(
            cs, columns, seed, 3);
    BOOST_REQUIRE_MESSAGE(tiled.valid, tiled.note);
    BOOST_CHECK(tiled.callback_schedule_executed);
    BOOST_CHECK(tiled.composition_values_identical);
    BOOST_CHECK(tiled.quotient_coefficients_identical);
    BOOST_CHECK_GT(tiled.tiles_visited, 1U);
    const auto memory_spill =
        aq::AuditAirQuotientSpillFp3(
            cs, columns, seed, 3,
            aq::AirExternalStoreBackend::kMemory);
    BOOST_REQUIRE_MESSAGE(
        memory_spill.valid, memory_spill.note);
    BOOST_CHECK(memory_spill.all_lde_columns_spilled);
    BOOST_CHECK(memory_spill.all_tiles_reloaded);
    BOOST_CHECK(memory_spill.byte_canonical_roundtrip);
    BOOST_CHECK_GT(
        memory_spill.store_resident_cells, 0U);
    BOOST_CHECK_EQUAL(
        memory_spill.store_resident_cells, 48U);
    BOOST_CHECK_EQUAL(
        memory_spill.store_peak_live_cells, 16U);
    const auto file_spill =
        aq::AuditAirQuotientSpillFp3(
            cs, columns, seed, 3,
            aq::AirExternalStoreBackend::
                kAnonymousTempFile);
    BOOST_REQUIRE_MESSAGE(
        file_spill.valid, file_spill.note);
    BOOST_CHECK(file_spill.all_lde_columns_spilled);
    BOOST_CHECK(file_spill.all_tiles_reloaded);
    BOOST_CHECK(file_spill.byte_canonical_roundtrip);
    BOOST_CHECK_EQUAL(
        file_spill.store_resident_cells, 0U);
    BOOST_CHECK_EQUAL(
        memory_spill.quotient.composition_rows,
        file_spill.quotient.composition_rows);
    BOOST_CHECK_EQUAL(
        memory_spill.quotient.tiles_visited,
        file_spill.quotient.tiles_visited);
    BOOST_CHECK_EQUAL(
        memory_spill.store_peak_live_cells,
        file_spill.store_peak_live_cells);

    using Dense =
        aq::AirFriBackendAlgDual<gf::Fp3>;
    using StreamAudit =
        aq::AirFriBackendAlgDualStreamingAudit;
    const auto dense =
        aq::AirQuotientProve<gf::Fp3, Dense>(
            cs, columns, seed);
    BOOST_REQUIRE_MESSAGE(dense.ok, dense.note);
    const auto streamed =
        aq::AirQuotientProve<
            gf::Fp3, StreamAudit>(
            cs, columns, seed);
    BOOST_REQUIRE_MESSAGE(streamed.ok, streamed.note);

    std::vector<unsigned char> dense_bytes;
    std::vector<unsigned char> streamed_bytes;
    const size_t dense_size =
        matmul::v4::rc::SerializeFri3AlgDualBatchProof(
        dense.proof.batch.repeated, dense_bytes);
    const size_t streamed_size =
        matmul::v4::rc::SerializeFri3AlgDualBatchProof(
        streamed.proof.batch.repeated,
        streamed_bytes);
    BOOST_REQUIRE_GT(dense_size, 0U);
    BOOST_CHECK_EQUAL(dense_size, streamed_size);
    BOOST_CHECK(dense_bytes == streamed_bytes);
    BOOST_CHECK_EQUAL(
        dense.proof.next_openings.size(),
        streamed.proof.next_openings.size());
    for (size_t query = 0;
         query < dense.proof.next_openings.size();
         ++query) {
        BOOST_REQUIRE_EQUAL(
            dense.proof.next_openings[query].size(),
            streamed.proof.next_openings[query].size());
        for (size_t opening = 0;
             opening <
                 dense.proof.next_openings[query].size();
             ++opening) {
            const auto& a =
                dense.proof.next_openings[query][opening];
            const auto& b =
                streamed.proof.next_openings[query][opening];
            BOOST_CHECK_EQUAL(a.index, b.index);
            BOOST_REQUIRE_EQUAL(
                a.values.size(), b.values.size());
            for (size_t value = 0;
                 value < a.values.size(); ++value) {
                BOOST_CHECK(
                    gf::Eq(
                        a.values[value],
                        b.values[value]));
            }
            BOOST_CHECK(a.siblings == b.siblings);
        }
    }
    std::string why;
    const bool verified =
        aq::AirQuotientVerify<
            gf::Fp3, StreamAudit>(
            cs, streamed.proof, seed, &why);
    BOOST_CHECK_MESSAGE(
        verified,
        why);
}

BOOST_AUTO_TEST_CASE(
    sampled_two_epoch_cross_opening_is_explicitly_rejected)
{
    constexpr uint32_t N = 8;
    const uint256 seed = MakeSeed(93);
    std::vector<std::vector<gf::Fp3>> columns(
        3, std::vector<gf::Fp3>(
               N, gf::Fp3::Zero()));
    for (uint32_t row = 0; row < N; ++row) {
        columns[0][row] =
            gf::Fp3::FromFp(gf::FromU64(
                3 + 5 * row + row * row));
        columns[1][row] =
            gf::Fp3::FromFp(gf::FromU64(
                11 + 7 * row));
    }
    const auto make_cs = [](const gf::Fp3& challenge) {
        aq::AirConstraintSystem<gf::Fp3> cs;
        cs.n_rows = N;
        cs.n_columns = 3;
        aq::AirConstraint<gf::Fp3> relation;
        relation.name =
            "test.two_epoch.challenge_relation";
        relation.kind = aq::AirKind::kEverywhere;
        relation.alg_degree = 1;
        relation.eval = [challenge](
            const std::vector<gf::Fp3>& cur,
            const std::vector<gf::Fp3>&) {
            return gf::Sub(
                cur[2],
                gf::Add(
                    cur[0],
                    gf::Mul(challenge, cur[1])));
        };
        cs.constraints.push_back(
            std::move(relation));
        return cs;
    };
    const std::vector<uint32_t> base_indices{0, 1};
    const auto shape_cs =
        make_cs(gf::Fp3::Zero());
    std::string why;
    const auto r0_session =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            shape_cs, columns, base_indices);
    BOOST_REQUIRE_MESSAGE(
        r0_session.valid, r0_session.note);
    const uint256 r0 =
        r0_session.base_row_commitment;
    BOOST_REQUIRE_MESSAGE(!r0.IsNull(), why);
    const uint256 challenge_digest =
        aq::AirChallengeDigest(
            seed, "test_two_epoch_challenge",
            {r0}, {N, 2});
    const gf::Fp3 challenge =
        gf::FromChallengeBytes3(
            challenge_digest.data());
    const auto cs = make_cs(challenge);
    for (uint32_t row = 0; row < N; ++row) {
        columns[2][row] =
            gf::Add(
                columns[0][row],
                gf::Mul(
                    challenge, columns[1][row]));
    }

    const auto proved =
        aq::AirQuotientProveRowsTwoEpoch(
            cs, columns, base_indices, seed, {},
            &r0_session);
    BOOST_CHECK(!proved.ok);
    const auto& receipt = proved.receipt;
    BOOST_CHECK_EQUAL(receipt.trace_rows, N);
    BOOST_CHECK(receipt.base_row_commitment == r0);
    BOOST_CHECK(
        receipt.base_commitment_bound_in_fs);
    BOOST_CHECK(receipt.same_query_cross_openings);
    BOOST_CHECK(
        !receipt.low_degree_proximity_accounted);
    BOOST_CHECK(!receipt.valid);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsTwoEpoch(
            cs, receipt, seed, &why));
    BOOST_CHECK_NE(
        why.find("global_oracle_equality_unproved"),
        std::string::npos);

    auto root_attack = receipt;
    root_attack.base_row_commitment = MakeSeed(94);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsTwoEpoch(
            cs, root_attack, seed, &why));

    auto value_attack = receipt;
    BOOST_REQUIRE(
        !value_attack.base_openings.empty());
    BOOST_REQUIRE(
        !value_attack.base_openings[0]
             .values.empty());
    value_attack.base_openings[0].values[0] =
        gf::Add(
            value_attack.base_openings[0]
                .values[0],
            gf::Fp3::One());
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsTwoEpoch(
            cs, value_attack, seed, &why));

    auto index_attack = receipt;
    std::swap(
        index_attack.base_column_indices[0],
        index_attack.base_column_indices[1]);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsTwoEpoch(
            cs, index_attack, seed, &why));

    const auto wrong_cs =
        make_cs(
            gf::Add(
                challenge, gf::Fp3::One()));
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsTwoEpoch(
            wrong_cs, receipt, seed, &why));

    auto accounting_attack = receipt;
    accounting_attack.low_degree_proximity_accounted =
        true;
    accounting_attack.valid = true;
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsTwoEpoch(
            cs, accounting_attack, seed, &why));
}

BOOST_AUTO_TEST_CASE(
    split_rap_multi_row_closes_current_next_and_air_lambda)
{
    constexpr uint32_t N = 8;
    const uint256 seed = MakeSeed(96);
    std::vector<std::vector<gf::Fp3>> columns(
        4, std::vector<gf::Fp3>(
               N, gf::Fp3::Zero()));
    for (uint32_t row = 0; row < N; ++row) {
        columns[0][row] =
            gf::Fp3::FromFp(
                gf::FromU64(
                    3 + 2 * row + row * row));
        columns[1][row] =
            gf::Fp3::FromFp(
                gf::FromU64(
                    7 + 5 * row));
    }
    const auto make_cs =
        [](const gf::Fp3& relation_challenge) {
            aq::AirConstraintSystem<gf::Fp3> cs;
            cs.n_rows = N;
            cs.n_columns = 4;
            aq::AirConstraint<gf::Fp3> relation;
            relation.name =
                "test.split_rap.challenge_relation";
            relation.kind =
                aq::AirKind::kEverywhere;
            relation.alg_degree = 1;
            relation.eval =
                [relation_challenge](
                    const std::vector<gf::Fp3>& cur,
                    const std::vector<gf::Fp3>&) {
                    return gf::Sub(
                        cur[2],
                        gf::Add(
                            cur[0],
                            gf::Mul(
                                relation_challenge,
                                cur[1])));
                };
            cs.constraints.push_back(
                std::move(relation));
            aq::AirConstraint<gf::Fp3> transition;
            transition.name =
                "test.split_rap.next_relation";
            transition.kind =
                aq::AirKind::kTransition;
            transition.alg_degree = 1;
            transition.eval =
                [](const std::vector<gf::Fp3>& cur,
                   const std::vector<gf::Fp3>& next) {
                    return gf::Sub(
                        next[3],
                        gf::Add(cur[3], cur[2]));
                };
            cs.constraints.push_back(
                std::move(transition));
            return cs;
        };
    const std::vector<uint32_t> base_indices{
        0, 1};
    const auto shape_cs =
        make_cs(gf::Fp3::Zero());
    const auto r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            shape_cs, columns, base_indices);
    BOOST_REQUIRE_MESSAGE(r0.valid, r0.note);
    const uint256 relation_digest =
        aq::AirChallengeDigest(
            seed,
            "test_split_rap_relation_challenge",
            {r0.base_row_commitment},
            {N, 4});
    const gf::Fp3 relation_challenge =
        gf::FromChallengeBytes3(
            relation_digest.data());
    auto cs = make_cs(relation_challenge);
    for (uint32_t row = 0; row < N; ++row) {
        columns[2][row] =
            gf::Add(
                columns[0][row],
                gf::Mul(
                    relation_challenge,
                    columns[1][row]));
        if (row + 1 < N) {
            columns[3][row + 1] =
                gf::Add(
                    columns[3][row],
                    columns[2][row]);
        }
    }
    cs.preprocessed.emplace_back(
        1, columns[1]);
    cs.preprocessed_pin_ood = true;
    cs.preprocessed_row_group_roots.push_back({
        .version = 1,
        .role =
            aq::AirPreprocessedRowGroupRole::kR0,
        .ordered_columns = base_indices,
        .root = r0.base_row_commitment,
    });

    const auto proved =
        aq::AirQuotientProveRowsSplitRap(
            cs, columns, base_indices,
            seed, {}, &r0);
    BOOST_REQUIRE_MESSAGE(
        proved.ok, proved.note);
    BOOST_CHECK(proved.division_exact);
    BOOST_CHECK_EQUAL(
        proved.proof.batch.version,
        matmul::v4::rc::
            kRCFri3AlgMultiRowBatchProofVersion);
    BOOST_CHECK_EQUAL(
        proved.proof.batch.groups.size(), 3U);
    BOOST_CHECK_EQUAL(
        proved.proof.batch.groups[0]
            .column_count,
        2U);
    BOOST_CHECK_EQUAL(
        proved.proof.batch.groups[1]
            .column_count,
        2U);
    BOOST_CHECK_EQUAL(
        proved.proof.batch.groups[2]
            .column_count,
        1U);
    BOOST_CHECK_EQUAL(
        proved.proof.next_trace_group_rows
            .size(),
        matmul::v4::rc::
            kRCFri3AlgNumQueries);
    BOOST_REQUIRE_EQUAL(
        proved.group_row_tree_caches.size(),
        3U);

    std::string why;
    BOOST_CHECK_MESSAGE(
        aq::AirQuotientVerifyRowsSplitRap(
            cs, proved.proof, base_indices,
            seed, &why),
        why);
    auto wrong_group_root_cs = cs;
    wrong_group_root_cs
        .preprocessed_row_group_roots[0]
        .root.begin()[0] ^= 1U;
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            wrong_group_root_cs, proved.proof,
            base_indices, seed, &why));
    auto wrong_group_order_cs = cs;
    std::swap(
        wrong_group_order_cs
            .preprocessed_row_group_roots[0]
            .ordered_columns[0],
        wrong_group_order_cs
            .preprocessed_row_group_roots[0]
            .ordered_columns[1]);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            wrong_group_order_cs, proved.proof,
            base_indices, seed, &why));
    auto wrong_group_role_cs = cs;
    wrong_group_role_cs
        .preprocessed_row_group_roots[0]
        .role =
        aq::AirPreprocessedRowGroupRole::kRdep;
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            wrong_group_role_cs, proved.proof,
            base_indices, seed, &why));

    std::vector<unsigned char> encoded;
    BOOST_REQUIRE_GT(
        aq::SerializeAirQuotientSplitRapRowsProof(
            proved.proof, encoded),
        0U);
    BOOST_CHECK_LE(
        encoded.size(),
        aq::kAirQuotientSplitRapRowsMaxProofBytesHard);
    const auto decoded =
        aq::DeserializeAirQuotientSplitRapRowsProof(
            encoded);
    BOOST_REQUIRE(decoded.has_value());
    std::vector<unsigned char> encoded_again;
    BOOST_CHECK_EQUAL(
        aq::SerializeAirQuotientSplitRapRowsProof(
            *decoded, encoded_again),
        encoded.size());
    BOOST_CHECK(encoded_again == encoded);
    BOOST_CHECK_MESSAGE(
        aq::AirQuotientVerifyRowsSplitRap(
            cs, *decoded, base_indices,
            seed, &why),
        why);

    auto malformed_codec = proved.proof;
    std::swap(
        malformed_codec.base_column_indices[0],
        malformed_codec.base_column_indices[1]);
    BOOST_CHECK_EQUAL(
        aq::SerializeAirQuotientSplitRapRowsProof(
            malformed_codec, encoded_again),
        0U);
    malformed_codec = proved.proof;
    malformed_codec.next_trace_group_rows
        .pop_back();
    BOOST_CHECK_EQUAL(
        aq::SerializeAirQuotientSplitRapRowsProof(
            malformed_codec, encoded_again),
        0U);
    malformed_codec = proved.proof;
    malformed_codec
        .next_trace_group_rows[0][0]
        .siblings.pop_back();
    BOOST_CHECK_EQUAL(
        aq::SerializeAirQuotientSplitRapRowsProof(
            malformed_codec, encoded_again),
        0U);

    const size_t air_lambda_offset =
        16 + base_indices.size() * 4;
    const size_t batch_size_offset =
        air_lambda_offset + 24;
    const size_t next_count_offset =
        batch_size_offset + 4 +
        ([&] {
            std::vector<unsigned char> nested;
            return rc::
                SerializeFri3AlgMultiRowBatchProof(
                    proved.proof.batch,
                    nested);
        })();
    auto bad_codec_wire = encoded;
    std::fill(
        bad_codec_wire.begin() +
            air_lambda_offset,
        bad_codec_wire.begin() +
            air_lambda_offset + 8,
        0xff);
    BOOST_CHECK(
        !aq::DeserializeAirQuotientSplitRapRowsProof(
             bad_codec_wire)
             .has_value());
    bad_codec_wire = encoded;
    PutLE32(
        bad_codec_wire, batch_size_offset,
        static_cast<uint32_t>(
            rc::
                kRCFri3AlgMultiRowMaxProofBytesHard +
            1));
    BOOST_CHECK(
        !aq::DeserializeAirQuotientSplitRapRowsProof(
             bad_codec_wire)
             .has_value());
    bad_codec_wire = encoded;
    PutLE32(
        bad_codec_wire, next_count_offset,
        rc::kRCFri3AlgNumQueries - 1);
    BOOST_CHECK(
        !aq::DeserializeAirQuotientSplitRapRowsProof(
             bad_codec_wire)
             .has_value());
    bad_codec_wire = encoded;
    bad_codec_wire.push_back(0);
    BOOST_CHECK(
        !aq::DeserializeAirQuotientSplitRapRowsProof(
             bad_codec_wire)
             .has_value());
    BOOST_CHECK(
        !aq::DeserializeAirQuotientSplitRapRowsProof(
             std::vector<unsigned char>(
                 aq::
                     kAirQuotientSplitRapRowsMaxProofBytesHard +
                     1,
                 0))
             .has_value());

    auto air_fri_lambda_swap = proved.proof;
    air_fri_lambda_swap.air_constraint_lambda =
        air_fri_lambda_swap.batch.lambda;
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            cs, air_fri_lambda_swap,
            base_indices, seed, &why));

    auto wrong_group_width = proved.proof;
    ++wrong_group_width.batch.groups[0]
          .column_count;
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            cs, wrong_group_width,
            base_indices, seed, &why));

    auto wrong_rdep_root = proved.proof;
    wrong_rdep_root.batch.groups[1]
        .row_commit.root[0] =
        gf::Add(
            wrong_rdep_root.batch.groups[1]
                .row_commit.root[0],
            1);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            cs, wrong_rdep_root,
            base_indices, seed, &why));

    auto wrong_next = proved.proof;
    wrong_next.next_trace_group_rows[0][1]
        .values[0] =
        gf::Add(
            wrong_next
                .next_trace_group_rows[0][1]
                .values[0],
            gf::Fp3::One());
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            cs, wrong_next,
            base_indices, seed, &why));

    auto wrong_indices = proved.proof;
    std::swap(
        wrong_indices.base_column_indices[0],
        wrong_indices.base_column_indices[1]);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            cs, wrong_indices,
            base_indices, seed, &why));

    const auto wrong_cs =
        make_cs(
            gf::Add(
                relation_challenge,
                gf::Fp3::One()));
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            wrong_cs, proved.proof,
            base_indices, seed, &why));

    // A changed Rdep can recompute every later root/transcript and still
    // emit a proximity proof, but cannot satisfy the immutable relation.
    auto changed_columns = columns;
    changed_columns[2][0] =
        gf::Add(
            changed_columns[2][0],
            gf::Fp3::One());
    aq::AirProveOptions forced;
    forced.force_commit_on_inexact = true;
    const auto self_consistent_changed_rdep =
        aq::AirQuotientProveRowsSplitRap(
            cs, changed_columns,
            base_indices, seed, forced,
            &r0);
    BOOST_REQUIRE_MESSAGE(
        self_consistent_changed_rdep.ok,
        self_consistent_changed_rdep.note);
    BOOST_CHECK(
        !self_consistent_changed_rdep
             .division_exact);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            cs,
            self_consistent_changed_rdep.proof,
            base_indices, seed, &why));
}

// ===========================================================================
// PR-89: Poseidon2 route for the AIR challenge digest (NOT ACTIVATED).
// ===========================================================================

namespace {

/** p = 2^64 - 2^32 + 1. */
constexpr uint64_t kGoldilocksP = 0xFFFFFFFF00000001ULL;

uint256 U256FromLimbs(const std::array<uint64_t, 4>& limbs)
{
    std::array<unsigned char, 32> b{};
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 8; ++j) {
            b[8 * i + j] = static_cast<unsigned char>((limbs[i] >> (8 * j)) & 0xFF);
        }
    }
    return uint256{Span<const unsigned char>{b.data(), b.size()}};
}

/** The encoding this lane REJECTED: one u64 limb -> one lane, via FromU64.
 *  Present only so the aliasing collision can be exhibited as a live failure
 *  rather than asserted in prose. */
std::vector<gf::Fp> NaiveU64LimbLanes(const uint256& v)
{
    std::vector<gf::Fp> lanes;
    const unsigned char* b = v.data();
    for (int i = 0; i < 4; ++i) {
        uint64_t w = 0;
        for (int j = 0; j < 8; ++j) w |= static_cast<uint64_t>(b[8 * i + j]) << (8 * j);
        lanes.push_back(gf::FromU64(w));
    }
    return lanes;
}

} // namespace

// The SHA256d route is UNCHANGED by this lane. Pinned against a value computed
// INDEPENDENTLY (Python hashlib over the hand-assembled 113-byte preimage), not
// captured from this binary, so the check cannot agree with itself.
BOOST_AUTO_TEST_CASE(airq_legacy_sha_challenge_digest_is_byte_identical_kat)
{
    const uint256 seed = MakePrf(3);
    const uint256 root = MakePrf(9);
    const uint256 d = aq::AirChallengeDigest(seed, "airq_lambda", {root}, {64, 8, 3});
    BOOST_CHECK_EQUAL(
        d.ToString(),
        "c277093fb3628769031f319a7d48e9ab90466b78292fe549d63b26cadacace44");
}

// The documented 113-byte / 3-compression preimage shape, recomputed here so a
// silent layout drift in the legacy route is caught by the cost model too.
BOOST_AUTO_TEST_CASE(airq_p2_preimage_lane_and_permutation_count)
{
    const uint256 seed = MakePrf(3);
    const uint256 root = MakePrf(9);
    const auto lanes = aq::AirChallengeP2Lanes(seed, "airq_lambda", {root}, {64, 8, 3});

    // 6 tag + 1 version + 8 seed + 4 label + 1 nroots + 8 root + 1 nextra + 3 extra.
    BOOST_CHECK_EQUAL(lanes.size(), 32u);
    // 32 lanes + the mandatory 10* "1" lane -> 40 -> 5 rate blocks.
    BOOST_CHECK_EQUAL(aq::AirChallengeP2Permutations(lanes.size()), 5u);

    // Every absorbed lane is < 2^32, which is the whole reason the encoding is
    // injective: reduction mod p is the identity on this range.
    for (const gf::Fp x : lanes) {
        BOOST_CHECK_LT(static_cast<uint64_t>(x), (uint64_t{1} << 32));
    }

    // At one row per permutation the in-AIR replay is 5 rows, against the
    // 1024 * next_pow2(3) = 4096 rows the SHA256d vertical chip charges.
    BOOST_CHECK_LT(aq::AirChallengeP2Permutations(lanes.size()), 4096u);
}

// THE GOLDILOCKS ALIASING CLASS, driven rather than described.
// B = x + p is a DIFFERENT u64 that FromU64 maps to the SAME field element.
// The test first shows the rejected encoding genuinely collides (so the guard
// is not vacuous), then shows the shipped encoding separates the two roots.
BOOST_AUTO_TEST_CASE(airq_p2_rejects_goldilocks_x_plus_p_aliased_root)
{
    const uint64_t x = 5;
    const uint64_t x_plus_p = x + kGoldilocksP; // 0xFFFFFFFF00000006, no wrap
    BOOST_REQUIRE_GT(x_plus_p, x);
    BOOST_REQUIRE_EQUAL(gf::FromU64(x), gf::FromU64(x_plus_p)); // the alias

    const uint256 root_a = U256FromLimbs({x, 11, 22, 33});
    const uint256 root_b = U256FromLimbs({x_plus_p, 11, 22, 33});
    BOOST_REQUIRE(root_a != root_b); // genuinely two different commitments

    // (a) NON-VACUITY: the rejected u64-limb encoding really does collide.
    BOOST_CHECK(NaiveU64LimbLanes(root_a) == NaiveU64LimbLanes(root_b));

    // (b) The shipped 32-bit-lane encoding does NOT.
    const uint256 seed = MakePrf(3);
    const auto lanes_a = aq::AirChallengeP2Lanes(seed, "airq_lambda", {root_a}, {64, 8, 3});
    const auto lanes_b = aq::AirChallengeP2Lanes(seed, "airq_lambda", {root_b}, {64, 8, 3});
    BOOST_CHECK(lanes_a != lanes_b);
    BOOST_CHECK(aq::AirChallengeDigestP2(seed, "airq_lambda", {root_a}, {64, 8, 3}) !=
                aq::AirChallengeDigestP2(seed, "airq_lambda", {root_b}, {64, 8, 3}));

    // The same alias in the SEED position, which binds the recursion node/slot.
    const uint256 seed_a = U256FromLimbs({x, 1, 2, 3});
    const uint256 seed_b = U256FromLimbs({x_plus_p, 1, 2, 3});
    BOOST_REQUIRE(seed_a != seed_b);
    BOOST_CHECK(NaiveU64LimbLanes(seed_a) == NaiveU64LimbLanes(seed_b));
    BOOST_CHECK(aq::AirChallengeDigestP2(seed_a, "airq_lambda", {root_a}, {64, 8, 3}) !=
                aq::AirChallengeDigestP2(seed_b, "airq_lambda", {root_a}, {64, 8, 3}));
}

// Length-prefixing makes the concatenation prefix-free: moving a byte between
// two adjacent variable-length sections must not preserve the digest.
BOOST_AUTO_TEST_CASE(airq_p2_preimage_is_injective_across_sections)
{
    const uint256 seed = MakePrf(3);
    const uint256 r1 = MakePrf(9);
    const uint256 r2 = MakePrf(10);

    // Label boundary: "ab" + no-root vs "a" + "b"-ish shifts are impossible to
    // build directly, so exercise the count fields, which are what pins them.
    BOOST_CHECK(aq::AirChallengeDigestP2(seed, "airq_lambda", {r1, r2}, {64, 8, 3}) !=
                aq::AirChallengeDigestP2(seed, "airq_lambda", {r1}, {64, 8, 3}));
    BOOST_CHECK(aq::AirChallengeDigestP2(seed, "airq_lambda", {r1}, {64, 8, 3, 0}) !=
                aq::AirChallengeDigestP2(seed, "airq_lambda", {r1}, {64, 8, 3}));
    // Label separation (same length, and different length).
    BOOST_CHECK(aq::AirChallengeDigestP2(seed, "airq_gammaX", {r1}, {64, 8, 3}) !=
                aq::AirChallengeDigestP2(seed, "airq_lambda", {r1}, {64, 8, 3}));
    BOOST_CHECK(aq::AirChallengeDigestP2(seed, "airq_gamma", {r1}, {64, 8, 3}) !=
                aq::AirChallengeDigestP2(seed, "airq_lambda", {r1}, {64, 8, 3}));
    // Root ORDER is bound.
    BOOST_CHECK(aq::AirChallengeDigestP2(seed, "airq_lambda", {r2, r1}, {64, 8, 3}) !=
                aq::AirChallengeDigestP2(seed, "airq_lambda", {r1, r2}, {64, 8, 3}));
    // Extra ORDER is bound.
    BOOST_CHECK(aq::AirChallengeDigestP2(seed, "airq_lambda", {r1}, {8, 64, 3}) !=
                aq::AirChallengeDigestP2(seed, "airq_lambda", {r1}, {64, 8, 3}));
    // Determinism.
    BOOST_CHECK(aq::AirChallengeDigestP2(seed, "airq_lambda", {r1}, {64, 8, 3}) ==
                aq::AirChallengeDigestP2(seed, "airq_lambda", {r1}, {64, 8, 3}));
}

// The two routes are separate: same logical preimage, different digest, and the
// Poseidon2 output is four CANONICAL Goldilocks lanes (never a limb >= p).
BOOST_AUTO_TEST_CASE(airq_p2_route_is_domain_separated_and_canonical)
{
    const uint256 seed = MakePrf(3);
    const uint256 root = MakePrf(9);
    const uint256 sha = aq::AirChallengeDigest(seed, "airq_lambda", {root}, {64, 8, 3});
    const uint256 p2 = aq::AirChallengeDigestP2(seed, "airq_lambda", {root}, {64, 8, 3});
    BOOST_CHECK(sha != p2);

    const unsigned char* b = p2.data();
    for (int i = 0; i < 4; ++i) {
        uint64_t limb = 0;
        for (int j = 0; j < 8; ++j) limb |= static_cast<uint64_t>(b[8 * i + j]) << (8 * j);
        BOOST_CHECK_LT(limb, kGoldilocksP);
    }

    // The route is NOT activated: nothing selects it yet.
    BOOST_CHECK(!aq::kAirChallengeP2Activated);
    BOOST_CHECK(!aq::AirBackendUsesP2Challenge<aq::AirFriBackend<gf::Fp3>>);
    // Row-wise trait is true for the alg backend, but the activation gate
    // keeps the selected digest on the SHA route until the flag flips.
    BOOST_CHECK(aq::AirBackendIsRowWise<aq::AirFriBackendAlg<gf::Fp3>>);
    BOOST_CHECK(!aq::AirBackendUsesP2Challenge<aq::AirFriBackendAlg<gf::Fp3>>);
    BOOST_CHECK(aq::AirChallengeDigestSelected(
                    /*use_p2=*/false, seed, "airq_lambda", {root}, {64, 8, 3}) ==
                sha);
    BOOST_CHECK(aq::AirChallengeDigestSelected(
                    /*use_p2=*/true, seed, "airq_lambda", {root}, {64, 8, 3}) ==
                p2);
    BOOST_CHECK(aq::AirChallengeDigestForBackend<aq::AirFriBackendAlg<gf::Fp3>>(
                    seed, "airq_lambda", {root}, {64, 8, 3}) == sha);
    BOOST_CHECK(aq::AirChallengeDigestForBackend<aq::AirFriBackend<gf::Fp3>>(
                    seed, "airq_lambda", {root}, {64, 8, 3}) == sha);
}

// ---------------------------------------------------------------------------
// COST OF THE REPLACEMENT COMPANION.
//
// The MEASURED g4 producer-endpoint floor (commit 5faa019) is 58.571 s:
//   build SHA companion CS   16.166 s
//   Split-RAP PROVE          41.149 s   over 591 columns x 4096 rows
// The 4096 rows are 1024 (hash_air's pinned lane_rows) x next_pow2(3
// compressions). Under the Poseidon2 route the same logical preimage is 5
// permutations, and the in-AIR Poseidon2 chip charges ONE row per permutation,
// so the replacement table is 8 rows (next power of two >= 5).
//
// THIS TEST MEASURES THE REPLACEMENT SHAPE'S Split-RAP PROVE, so the "after"
// number is a measurement rather than a model. It is honest about two gaps:
//   * it proves the Poseidon2 OPERATION TABLE (484 columns, 4*118 quadratic
//     identities). It does NOT include the sponge-chaining/padding constraints
//     or the LogUp bus lane the real companion also needs. Those add columns
//     (~+53 at the SHA companion's ratio) at the SAME row count, so they move
//     width by ~11%, not the 512x row factor that dominates.
//   * the Split-RAP split used is the chip's own 130 base / 354 auxiliary
//     partition, which is a structural property of the table, not a tuning
//     choice made to flatter the number.
// Env-gated because it proves; the default gate must stay fast.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(airq_p2_companion_replacement_prove_cost)
{
    if (std::getenv("BTX_RUN_AIRQ_P2_COMPANION_COST") == nullptr) {
        BOOST_TEST_MESSAGE(
            "AIRQ_P2_COST skipped (set BTX_RUN_AIRQ_P2_COMPANION_COST=1)");
        return;
    }
    using Clock = std::chrono::steady_clock;
    namespace pa = matmul::v4::rc::stage3_poseidon_air;
    namespace ah = matmul::v4::rc::alg_hash;

    const uint256 seed = MakePrf(3);
    const uint256 root = MakePrf(9);
    const auto lanes = aq::AirChallengeP2Lanes(seed, "airq_lambda", {root}, {64, 8, 3});
    const uint32_t perms = aq::AirChallengeP2Permutations(lanes.size());
    uint32_t min_rows = 2;
    while (min_rows < perms) min_rows <<= 1;

    // TWO row counts, deliberately.
    //   min_rows (8) is the TRUE replay size, but n_lde = 8*16 = 128 is BELOW
    //     the 192-query budget, so a STANDALONE proof at that size is
    //     query-degenerate and its timing must not be quoted as the honest
    //     "after" number. It is reported only to isolate the row effect.
    //   1024 rows gives n_lde = 16384 > 192 queries, the same regime the
    //     MEASURED 591x4096 SHA number was taken in, so it is the defensible
    //     apples-to-apples figure -- and it is still 4x FEWER rows than 4096
    //     while carrying 205x more Poseidon2 permutations than this preimage
    //     actually needs.
    for (const uint32_t n_rows : {min_rows, 1024u}) {
    std::string why;
    aq::AirConstraintSystem<gf::Fp3> cs;
    BOOST_REQUIRE_MESSAGE(pa::BuildFixedSystem(n_rows, cs, &why), why);
    const auto layout = pa::CanonicalLayout(0);

    // Replicate SpongeHashFp's absorb schedule exactly: 10* padding, then
    // add-absorb into the 8 rate lanes and permute, one permutation per row.
    std::vector<gf::Fp> padded = lanes;
    padded.push_back(1);
    while (padded.size() % ah::kAlgHashRate != 0) padded.push_back(0);
    BOOST_REQUIRE_EQUAL(padded.size() / ah::kAlgHashRate, perms);

    std::vector<std::vector<gf::Fp3>> columns(
        cs.n_columns, std::vector<gf::Fp3>(n_rows, gf::Fp3::Zero()));
    ah::State s{};
    ah::State sponge_out{};
    for (uint32_t i = 0; i < n_rows; ++i) {
        if (i < perms) {
            for (uint32_t j = 0; j < ah::kAlgHashRate; ++j) {
                s[j] = gf::Add(s[j], padded[i * ah::kAlgHashRate + j]);
            }
        } else {
            s = ah::State{}; // filler rows are still honest permutation rows
        }
        const pa::Witness w = pa::BuildWitness(layout, s);
        BOOST_REQUIRE_EQUAL(w.row.size(), layout.End());
        for (uint32_t c = 0; c < layout.End() && c < cs.n_columns; ++c) {
            columns[c][i] = w.row[c];
        }
        s = w.output;
        // Capture BEFORE the filler rows overwrite the chain.
        if (i + 1 == perms) sponge_out = w.output;
    }

    // The sponge the AIR rows just replayed must be the native digest, or the
    // measurement is of an unrelated table.
    const ah::Digest native = ah::SpongeHashFp(lanes);
    for (int i = 0; i < 4; ++i) BOOST_REQUIRE_EQUAL(sponge_out[i], native[i]);

    // Split-RAP needs a genuine two-epoch split. Use the chip's OWN partition:
    // the 130 flattened permutation cells are the base commitment, the 3*118
    // S-box auxiliary cells are the dependent epoch.
    const auto m = pa::Measure(n_rows);
    BOOST_REQUIRE_EQUAL(m.base_columns + m.auxiliary_columns, cs.n_columns);
    std::vector<uint32_t> base_indices(m.base_columns);
    for (uint32_t c = 0; c < m.base_columns; ++c) base_indices[c] = c;

    const uint32_t n_lde = cs.n_rows * matmul::v4::rc::kRCFriBlowup;
    BOOST_TEST_MESSAGE("AIRQ_P2_SHAPE rows=" << cs.n_rows
                       << " cols=" << cs.n_columns
                       << " constraints=" << cs.constraints.size()
                       << " permutations=" << perms
                       << " lanes=" << lanes.size()
                       << " n_lde=" << n_lde
                       << " query_sound=" << (n_lde > 192u ? "yes" : "NO"));

    auto t = Clock::now();
    const auto sp = aq::AirQuotientProveRowsSplitRap(cs, columns, base_indices, seed, {});
    const double t_prove =
        std::chrono::duration<double>(Clock::now() - t).count();
    BOOST_REQUIRE_MESSAGE(sp.ok, sp.note);

    t = Clock::now();
    const bool vok =
        aq::AirQuotientVerifyRowsSplitRap(cs, sp.proof, base_indices, seed, &why);
    const double t_verify =
        std::chrono::duration<double>(Clock::now() - t).count();
    BOOST_CHECK_MESSAGE(vok, why);

    BOOST_TEST_MESSAGE("AIRQ_P2_PROVE rows=" << cs.n_rows << " " << t_prove << " s"
                       << " | AIRQ_P2_VERIFY " << t_verify << " s"
                       << " | SHA_MEASURED_PROVE 41.149 s @591x4096"
                       << " | ratio=" << (41.149 / std::max(1e-9, t_prove)));
    } // end row-count sweep
}

BOOST_AUTO_TEST_SUITE_END()

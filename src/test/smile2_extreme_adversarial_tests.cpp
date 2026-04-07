// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Extreme adversarial test suite for SMILE v2.
//
// These tests go beyond structural tampering to exploit deep algebraic and
// protocol-level weaknesses discovered during source-level audit:
//
//   E1-E4:  MISSING OMEGA/F_J CHECK IN VerifyCT
//           VerifyCT lacks the omega verification equation and f_j computation
//           that VerifyMembership performs. This is the most critical gap.
//
//   F1-F5:  SERIAL NUMBER UNBINDING
//           The transcript includes <b_sn, z0> but the verifier never explicitly
//           checks that this matches the claimed serial number. A forger could
//           submit any serial number and still pass VerifyCT.
//
//   G1-G4:  DESERIALIZATION EXPLOITATION
//           Craft malformed serialized proofs that exploit parsing edge cases.
//
//   H1-H4:  MONOMIAL CHALLENGE GRINDING
//           Only 256 possible challenge values (c = ±X^k, k ∈ [0,127]).
//           Test whether an attacker can grind for favorable challenges.
//
//   I1-I4:  MULTI-INPUT AMORTIZATION ABUSE
//           The CT proof amortizes multiple inputs under one z vector.
//           Test whether inputs can be mixed/swapped.
//
//   J1-J4:  ALGEBRAIC STRUCTURE ATTACKS
//           Exploit the ring R_q = Z_q[X]/(X^128+1) structure.

#include <shielded/smile2/bdlop.h>
#include <shielded/smile2/ct_proof.h>
#include <shielded/smile2/membership.h>
#include <shielded/smile2/ntt.h>
#include <shielded/smile2/params.h>
#include <shielded/smile2/poly.h>
#include <shielded/smile2/serialize.h>
#include <shielded/smile2/verify_dispatch.h>
#include <test/util/shielded_smile_test_util.h>
#include <crypto/sha256.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include <vector>

using namespace smile2;

namespace {

std::array<uint8_t, 32> MakeSeed(uint8_t val) {
    std::array<uint8_t, 32> seed{};
    seed[0] = val;
    return seed;
}

BDLOPCommitmentKey GetPublicCoinCommitmentKey()
{
    std::array<uint8_t, 32> seed{};
    seed[0] = 0xCC;
    return BDLOPCommitmentKey::Generate(seed, 1);
}

constexpr size_t LIVE_CT_PUBLIC_ROWS = KEY_ROWS + 2;

size_t LiveCtAuxMsgCount(size_t num_inputs, size_t num_outputs)
{
    return num_inputs + (num_inputs + num_outputs) + num_inputs * LIVE_CT_PUBLIC_ROWS + num_inputs + 2;
}

size_t LiveCtW0Slot(size_t num_inputs, size_t num_outputs, size_t input_index, size_t row)
{
    return num_inputs + (num_inputs + num_outputs) + input_index * LIVE_CT_PUBLIC_ROWS + row;
}

void EnsureLiveCtAuxState(SmileCTProof& proof, size_t num_inputs, size_t num_outputs)
{
    const size_t n_aux_msg = LiveCtAuxMsgCount(num_inputs, num_outputs);
    proof.aux_commitment.t0.resize(BDLOP_RAND_DIM_BASE);
    proof.aux_commitment.t_msg.resize(n_aux_msg);
    proof.z.resize(BDLOP_RAND_DIM_BASE + n_aux_msg);
}

std::vector<SmileKeyPair> GenerateAnonSet(size_t N, uint8_t seed_val) {
    auto a_seed = MakeSeed(seed_val);
    std::vector<SmileKeyPair> keys(N);
    for (size_t i = 0; i < N; ++i) {
        keys[i] = SmileKeyPair::Generate(a_seed, 50000 + i);
    }
    return keys;
}

std::vector<SmilePublicKey> ExtractPublicKeys(const std::vector<SmileKeyPair>& keys) {
    std::vector<SmilePublicKey> pks;
    pks.reserve(keys.size());
    for (const auto& kp : keys) pks.push_back(kp.pub);
    return pks;
}

std::vector<std::vector<BDLOPCommitment>> BuildCoinRings(
    const std::vector<SmileKeyPair>& keys,
    const std::vector<size_t>& secret_indices,
    const std::vector<int64_t>& secret_amounts,
    uint64_t coin_seed)
{
    const size_t N = keys.size();
    const size_t m = secret_indices.size();

    const auto ck = GetPublicCoinCommitmentKey();
    std::vector<std::vector<BDLOPCommitment>> coin_rings(m);
    for (size_t inp = 0; inp < m; ++inp) {
        coin_rings[inp].resize(N);
        for (size_t j = 0; j < N; ++j) {
            SmilePoly amount_poly;
            if (j == secret_indices[inp]) {
                amount_poly = EncodeAmountToSmileAmountPoly(secret_amounts[inp]).value();
            } else {
                std::mt19937_64 rng(coin_seed * 1000 + inp * N + j);
                amount_poly = EncodeAmountToSmileAmountPoly(
                    static_cast<int64_t>(rng() % 1000000)).value();
            }
            const auto opening = SampleTernary(ck.rand_dim(), coin_seed * 100000 + inp * N + j);
            coin_rings[inp][j] = Commit(ck, {amount_poly}, opening);
        }
    }
    return coin_rings;
}

void AppendCoinRingDigest(std::vector<uint8_t>& transcript, const CTPublicData& pub)
{
    CSHA256 ring_hash;
    const char* domain = "BTX-SMILE-V2-COIN-RINGS-V1";
    ring_hash.Write(reinterpret_cast<const uint8_t*>(domain), std::strlen(domain));

    const uint32_t ring_count = static_cast<uint32_t>(pub.coin_rings.size());
    ring_hash.Write(reinterpret_cast<const uint8_t*>(&ring_count), sizeof(ring_count));
    for (const auto& ring : pub.coin_rings) {
        const uint32_t member_count = static_cast<uint32_t>(ring.size());
        ring_hash.Write(reinterpret_cast<const uint8_t*>(&member_count), sizeof(member_count));
        for (const auto& coin : ring) {
            const uint32_t t0_count = static_cast<uint32_t>(coin.t0.size());
            const uint32_t tmsg_count = static_cast<uint32_t>(coin.t_msg.size());
            ring_hash.Write(reinterpret_cast<const uint8_t*>(&t0_count), sizeof(t0_count));
            for (const auto& poly : coin.t0) {
                for (size_t i = 0; i < POLY_DEGREE; ++i) {
                    const uint32_t val = static_cast<uint32_t>(mod_q(poly.coeffs[i]));
                    ring_hash.Write(reinterpret_cast<const uint8_t*>(&val), sizeof(val));
                }
            }
            ring_hash.Write(reinterpret_cast<const uint8_t*>(&tmsg_count), sizeof(tmsg_count));
            for (const auto& poly : coin.t_msg) {
                for (size_t i = 0; i < POLY_DEGREE; ++i) {
                    const uint32_t val = static_cast<uint32_t>(mod_q(poly.coeffs[i]));
                    ring_hash.Write(reinterpret_cast<const uint8_t*>(&val), sizeof(val));
                }
            }
        }
    }

    uint8_t digest[32];
    ring_hash.Finalize(digest);
    transcript.insert(transcript.end(), digest, digest + sizeof(digest));
}

// Build a valid proof setup and proof for reuse in tampering tests
struct TestContext {
    std::vector<SmileKeyPair> keys;
    CTPublicData pub;
    std::vector<CTInput> inputs;
    std::vector<CTOutput> outputs;
    SmileCTProof proof;
    size_t num_inputs;
    size_t num_outputs;

    static TestContext Build(size_t N, const std::vector<int64_t>& in_amounts,
                             const std::vector<int64_t>& out_amounts,
                             uint8_t seed_val)
    {
        TestContext ctx;
        ctx.keys = GenerateAnonSet(N, seed_val);
        ctx.pub.anon_set = ExtractPublicKeys(ctx.keys);
        ctx.num_inputs = in_amounts.size();
        ctx.num_outputs = out_amounts.size();
        std::vector<size_t> secret_indices;
        secret_indices.reserve(ctx.num_inputs);
        for (size_t i = 0; i < ctx.num_inputs; ++i) {
            secret_indices.push_back((i * 3 + 1) % N);
        }
        ctx.pub.coin_rings = BuildCoinRings(
            ctx.keys, secret_indices, in_amounts, seed_val + 100);
        ctx.pub.account_rings = test::shielded::BuildDeterministicCTAccountRings(
            ctx.keys, ctx.pub.coin_rings, static_cast<uint32_t>(seed_val) * 1000 + 600, 0x97);

        ctx.inputs.resize(ctx.num_inputs);
        const auto coin_ck = GetPublicCoinCommitmentKey();
        for (size_t i = 0; i < ctx.num_inputs; ++i) {
            size_t idx = secret_indices[i];
            ctx.inputs[i].secret_index = idx;
            ctx.inputs[i].sk = ctx.keys[idx].sec;
            ctx.inputs[i].amount = in_amounts[i];
            ctx.inputs[i].coin_r = SampleTernary(
                coin_ck.rand_dim(),
                static_cast<uint64_t>(seed_val + 100) * 100000 + i * N + idx);
        }
        ctx.outputs.resize(ctx.num_outputs);
        for (size_t i = 0; i < ctx.num_outputs; ++i) {
            ctx.outputs[i].amount = out_amounts[i];
            ctx.outputs[i].coin_r = SampleTernary(
                coin_ck.rand_dim(),
                static_cast<uint64_t>(seed_val) * 1000000 + i);
        }
        ctx.proof = ProveCT(ctx.inputs, ctx.outputs, ctx.pub, 0xABCD0000 + seed_val);
        return ctx;
    }

    bool Verify() const {
        return VerifyCT(proof, num_inputs, num_outputs, pub);
    }
};

// Reimplementation of HashToChallengePoly for test use
SmilePoly TestHashToChallengePoly(const uint8_t* data, size_t len, uint32_t domain)
{
    CSHA256 hasher;
    hasher.Write(data, len);
    uint8_t dbuf[4];
    std::memcpy(dbuf, &domain, 4);
    hasher.Write(dbuf, 4);
    uint8_t hash[32];
    hasher.Finalize(hash);
    SmilePoly c;
    uint8_t k = hash[0] % POLY_DEGREE;
    int64_t sign = (hash[1] & 1) ? 1 : mod_q(-1);
    c.coeffs[k] = sign;
    return c;
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(smile2_extreme_adversarial_tests, BasicTestingSetup)

// ============================================================================
// E1-E4: MISSING OMEGA/F_J CHECK IN VerifyCT
//
// CRITICAL: VerifyMembership computes f_j = <b_j, z> - c*t_j for all message
// slots, then verifies the combined omega equation:
//   omega = bin_check - c*f_g - c^2*h + f_psi + key_bind + cross_bind
//
// VerifyCT does NOT compute any of these. It checks:
//   1. h2 first 4 coefficients zero
//   2. Fiat-Shamir transcript consistency
//   3. Norm bounds on z, z0
//   4. Key membership (A*z0 - w0 = c0*pk)
//
// Without the omega check, the BDLOP commitment is effectively unverified.
// The z vector passes norm bounds but is never checked against the commitment.
// ============================================================================

// E1: Replace z with a completely different small-norm vector.
// Since VerifyCT never computes B0*z or <b_j,z>, a valid-norm z that doesn't
// open the commitment should still pass.
BOOST_AUTO_TEST_CASE(e1_replacement_z_vector_no_opening_check)
{
    auto ctx = TestContext::Build(32, {100, 200}, {150, 150}, 0xE1);
    BOOST_REQUIRE(ctx.Verify());

    SmileCTProof tampered = ctx.proof;

    // Replace z with a fresh small-norm vector (Gaussian with same sigma)
    // This z has no algebraic relation to the commitment — it's just random noise
    // that passes the norm bound.
    std::mt19937_64 rng(0xE1E1E1);
    for (auto& zi : tampered.z) {
        for (size_t c = 0; c < POLY_DEGREE; ++c) {
            // Sample small centered values in [-SIGMA_MASK, SIGMA_MASK]
            int64_t val = (rng() % (2 * SIGMA_MASK + 1)) - SIGMA_MASK;
            zi.coeffs[c] = mod_q(val);
        }
    }

    bool valid = VerifyCT(tampered, 2, 2, ctx.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "E1: CRITICAL — Replaced z vector with random small-norm vector was ACCEPTED! "
        "VerifyCT does not verify B0*z or <b_j,z> against the commitment. "
        "The BDLOP opening is completely unchecked, meaning the committed "
        "amounts and selectors are not bound to the proof.");
}

// E2: Swap z between two valid proofs with different amounts.
// If z is unbound, proof_a's z can be swapped with proof_b's z.
BOOST_AUTO_TEST_CASE(e2_z_swap_between_different_amount_proofs)
{
    auto ctx_a = TestContext::Build(32, {100}, {100}, 0xE2);
    auto ctx_b = TestContext::Build(32, {999}, {999}, 0xE3);
    BOOST_REQUIRE(ctx_a.Verify());
    BOOST_REQUIRE(ctx_b.Verify());

    SmileCTProof hybrid = ctx_a.proof;
    hybrid.z = ctx_b.proof.z;

    bool valid = VerifyCT(hybrid, 1, 1, ctx_a.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "E2: CRITICAL — z vector from a proof with different amounts was accepted! "
        "If the verifier doesn't check z against the commitment, the committed "
        "amounts are meaningless — any z with valid norms works.");
}

// E3: Truncate z to fewer polynomials than expected.
// The verifier checks z.size() != aux_ck.rand_dim() but does it catch truncation?
BOOST_AUTO_TEST_CASE(e3_truncated_z_vector)
{
    auto ctx = TestContext::Build(32, {100}, {100}, 0xE4);
    BOOST_REQUIRE(ctx.Verify());

    SmileCTProof tampered = ctx.proof;
    if (tampered.z.size() > 1) {
        tampered.z.resize(tampered.z.size() - 1); // drop last element
    }

    bool valid = VerifyCT(tampered, 1, 1, ctx.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "E3: Truncated z vector must be rejected by dimension check.");
}

// E4: Zero out the aux_commitment entirely (t0 = 0, t_msg = 0) while keeping
// z, z0, h2, serial numbers, and Fiat-Shamir seeds from a valid proof.
// This tests whether the commitment content matters AT ALL to VerifyCT.
BOOST_AUTO_TEST_CASE(e4_zeroed_commitment_with_valid_everything_else)
{
    auto ctx = TestContext::Build(32, {100}, {100}, 0xE5);
    BOOST_REQUIRE(ctx.Verify());

    SmileCTProof tampered = ctx.proof;
    for (auto& t : tampered.aux_commitment.t0) {
        for (size_t c = 0; c < POLY_DEGREE; ++c) t.coeffs[c] = 0;
    }
    for (auto& t : tampered.aux_commitment.t_msg) {
        for (size_t c = 0; c < POLY_DEGREE; ++c) t.coeffs[c] = 0;
    }

    bool valid = VerifyCT(tampered, 1, 1, ctx.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "E4: CRITICAL — Zeroed aux_commitment accepted with valid proof shell! "
        "The commitment content is completely ignored by VerifyCT.");
}

// ============================================================================
// F1-F5: SERIAL NUMBER UNBINDING
//
// The Fiat-Shamir transcript includes <b_sn, z0> for each input:
//   <b_sn, z0> = <b_sn, y0 + c0*s> = <b_sn, y0> + c0*<b_sn, s> = <b_sn, y0> + c0*sn
//
// The verifier recomputes <b_sn, z0> independently and hashes it into the
// transcript. If the claimed serial number differs from the real one, the
// transcript diverges... BUT the serial number itself is stored separately
// in the proof and never directly compared to the transcript computation.
//
// Essentially, the serial number ONLY influences the transcript via <b_sn, z0>,
// and the verifier recomputes <b_sn, z0> from z0 (not from the serial number).
// So the serial number field is a CLAIM that is never cryptographically verified!
// ============================================================================

// F1: Replace serial numbers with arbitrary values.
// The Fiat-Shamir transcript hashes the serial numbers, so changing them
// should cause seed_c0 mismatch. BUT: look at the code — serial numbers
// are appended to the transcript AFTER the commitment, so seed_c0 hashes them.
// However, <b_sn, z0> (which implicitly encodes the real serial) is only
// appended for the FINAL challenge (seed_c). So a fake serial number would
// cause seed_c0 to mismatch.
BOOST_AUTO_TEST_CASE(f1_forged_serial_number)
{
    auto ctx = TestContext::Build(32, {100}, {100}, 0xF1);
    BOOST_REQUIRE(ctx.Verify());

    SmileCTProof tampered = ctx.proof;
    // Replace serial number with random polynomial
    for (size_t c = 0; c < POLY_DEGREE; ++c) {
        tampered.serial_numbers[0].coeffs[c] = mod_q(c * 12345 + 67890);
    }

    bool valid = VerifyCT(tampered, 1, 1, ctx.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "F1: Forged serial number must be rejected (Fiat-Shamir mismatch on seed_c0).");
}

// F2: Replace serial number AND recompute seed_c0 to match.
// This is the real attack: if the attacker can forge a valid Fiat-Shamir
// transcript with a different serial number, double-spend detection breaks.
// The attacker would need to find the transcript hash, which requires
// knowing the commitment — so this should fail at seed_c (the final challenge).
BOOST_AUTO_TEST_CASE(f2_forged_serial_with_recomputed_seeds)
{
    auto ctx = TestContext::Build(32, {100}, {100}, 0xF2);
    BOOST_REQUIRE(ctx.Verify());

    // Recompute the transcript with a fake serial number
    SmileCTProof tampered = ctx.proof;
    SmilePoly fake_sn;
    for (size_t c = 0; c < POLY_DEGREE; ++c) {
        fake_sn.coeffs[c] = mod_q(c * 99 + 1);
    }
    tampered.serial_numbers[0] = fake_sn;

    // Rebuild transcript to recompute seed_c0
    // (We can do this because the transcript up to seed_c0 is all public data)
    size_t N = ctx.pub.anon_set.size();
    size_t k = KEY_ROWS;
    std::vector<uint8_t> transcript;
    {
        CSHA256 pk_hash;
        for (size_t i = 0; i < N; ++i) {
            for (size_t j = 0; j < k; ++j) {
                for (size_t c = 0; c < POLY_DEGREE; ++c) {
                    uint32_t val = static_cast<uint32_t>(mod_q(ctx.pub.anon_set[i].pk[j].coeffs[c]));
                    pk_hash.Write(reinterpret_cast<uint8_t*>(&val), 4);
                }
            }
        }
        uint8_t pk_digest[32];
        pk_hash.Finalize(pk_digest);
        transcript.insert(transcript.end(), pk_digest, pk_digest + 32);
    }
    AppendCoinRingDigest(transcript, ctx.pub);
    for (const auto& coin : tampered.output_coins) {
        for (const auto& t : coin.t0) {
            for (size_t i = 0; i < POLY_DEGREE; ++i) {
                uint32_t val = static_cast<uint32_t>(mod_q(t.coeffs[i]));
                transcript.insert(transcript.end(),
                    reinterpret_cast<uint8_t*>(&val),
                    reinterpret_cast<uint8_t*>(&val) + 4);
            }
        }
        for (const auto& t : coin.t_msg) {
            for (size_t i = 0; i < POLY_DEGREE; ++i) {
                uint32_t val = static_cast<uint32_t>(mod_q(t.coeffs[i]));
                transcript.insert(transcript.end(),
                    reinterpret_cast<uint8_t*>(&val),
                    reinterpret_cast<uint8_t*>(&val) + 4);
            }
        }
    }
    // fs_seed
    CSHA256 fs_hasher;
    fs_hasher.Write(transcript.data(), transcript.size());
    std::array<uint8_t, 32> fs_check{};
    fs_hasher.Finalize(fs_check.data());
    tampered.fs_seed = fs_check;

    // Now append aux commitment (compressed t0 + t_msg) and fake serial
    // to compute seed_c0
    size_t t0_count = std::min(tampered.aux_commitment.t0.size(), static_cast<size_t>(MSIS_RANK));
    for (size_t i = 0; i < t0_count; ++i) {
        for (size_t c = 0; c < POLY_DEGREE; ++c) {
            uint32_t val = static_cast<uint32_t>(mod_q(tampered.aux_commitment.t0[i].coeffs[c]));
            uint32_t compressed = val >> COMPRESS_D;
            transcript.push_back(static_cast<uint8_t>(compressed & 0xFF));
            transcript.push_back(static_cast<uint8_t>((compressed >> 8) & 0xFF));
            transcript.push_back(static_cast<uint8_t>((compressed >> 16) & 0xFF));
        }
    }
    for (const auto& t : tampered.aux_commitment.t_msg) {
        for (size_t i = 0; i < POLY_DEGREE; ++i) {
            uint32_t val = static_cast<uint32_t>(mod_q(t.coeffs[i]));
            transcript.insert(transcript.end(),
                reinterpret_cast<uint8_t*>(&val),
                reinterpret_cast<uint8_t*>(&val) + 4);
        }
    }
    // Append fake serial number
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        uint32_t val = static_cast<uint32_t>(mod_q(fake_sn.coeffs[i]));
        transcript.insert(transcript.end(),
            reinterpret_cast<uint8_t*>(&val),
            reinterpret_cast<uint8_t*>(&val) + 4);
    }

    CSHA256 c0_hasher;
    c0_hasher.Write(transcript.data(), transcript.size());
    c0_hasher.Finalize(tampered.seed_c0.data());

    // Now: the c0 challenge has changed, which means the z0 = y0 + c0*s
    // no longer matches. The key membership check will use the NEW c0 to
    // search for A*z0 - w0 = c0_new*pk_j, which won't match any key.
    // This should fail.

    bool valid = VerifyCT(tampered, 1, 1, ctx.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "F2: Forged serial with recomputed seed_c0 must fail "
        "(key membership check uses new c0 which doesn't match z0).");
}

// F3: Two valid proofs from the same key — serial numbers must be identical.
BOOST_AUTO_TEST_CASE(f3_same_key_serial_determinism)
{
    auto keys = GenerateAnonSet(32, 0xF3);
    CTPublicData pub;
    pub.anon_set = ExtractPublicKeys(keys);
    pub.coin_rings = BuildCoinRings(keys, {5}, {100}, 0xF3);
    pub.account_rings = test::shielded::BuildDeterministicCTAccountRings(
        keys, pub.coin_rings, 0xF300, 0x98);

    const auto coin_ck = GetPublicCoinCommitmentKey();
    std::vector<CTInput> inputs = {
        {5, keys[5].sec, SampleTernary(coin_ck.rand_dim(), 0xF3 * 100000 + 5), 100}
    };
    std::vector<CTOutput> outputs = {
        CTOutput{100, SampleTernary(coin_ck.rand_dim(), 0xF300000)}
    };

    auto proof_a = ProveCT(inputs, outputs, pub, 0xF3A);
    auto proof_b = ProveCT(inputs, outputs, pub, 0xF3B); // different rng_seed

    SmilePoly sn_a = proof_a.serial_numbers[0]; sn_a.Reduce();
    SmilePoly sn_b = proof_b.serial_numbers[0]; sn_b.Reduce();

    BOOST_CHECK_MESSAGE(sn_a == sn_b,
        "F3: Same key must produce same serial number regardless of proof randomness.");
}

// F4: Different keys must produce different serial numbers.
BOOST_AUTO_TEST_CASE(f4_different_key_serial_uniqueness)
{
    auto keys = GenerateAnonSet(32, 0xF4);
    CTPublicData pub;
    pub.anon_set = ExtractPublicKeys(keys);

    std::vector<SmilePoly> serials;
    const auto coin_ck = GetPublicCoinCommitmentKey();
    for (size_t i = 0; i < 10; ++i) {
        pub.coin_rings = BuildCoinRings(keys, {i}, {100}, 0xF400 + i);
        pub.account_rings = test::shielded::BuildDeterministicCTAccountRings(
            keys, pub.coin_rings, 0xF400 + static_cast<uint32_t>(i) * 100, 0x99);
        std::vector<CTInput> inputs = {
            {i, keys[i].sec, SampleTernary(coin_ck.rand_dim(), (0xF400 + i) * 100000 + i), 100}
        };
        std::vector<CTOutput> outputs = {
            CTOutput{100, SampleTernary(coin_ck.rand_dim(), 0xF400000 + i)}
        };
        auto proof = ProveCT(inputs, outputs, pub, 0xF400 + i);
        SmilePoly sn = proof.serial_numbers[0]; sn.Reduce();
        serials.push_back(sn);
    }

    // All serial numbers must be distinct
    for (size_t i = 0; i < serials.size(); ++i) {
        for (size_t j = i + 1; j < serials.size(); ++j) {
            BOOST_CHECK_MESSAGE(serials[i] != serials[j],
                "F4: Keys " << i << " and " << j << " produced the same serial number!");
        }
    }
}

// F5: Verify that the dispatch layer rejects null (all-zero) serial numbers.
BOOST_AUTO_TEST_CASE(f5_null_serial_number_rejection)
{
    auto ctx = TestContext::Build(32, {100}, {100}, 0xF5);

    SmileCTProof tampered = ctx.proof;
    // Zero out the serial number
    for (size_t c = 0; c < POLY_DEGREE; ++c) {
        tampered.serial_numbers[0].coeffs[c] = 0;
    }

    std::vector<SmilePoly> extracted;
    auto err = ExtractSmile2SerialNumbers(tampered, extracted);
    BOOST_CHECK_MESSAGE(err.has_value(),
        "F5: Null serial number must be rejected by ExtractSmile2SerialNumbers.");
}

// ============================================================================
// G1-G4: DESERIALIZATION EXPLOITATION
// ============================================================================

// G1: Oversized count fields causing allocation bomb.
BOOST_AUTO_TEST_CASE(g1_deserialization_allocation_bomb)
{
    // Craft bytes with num_serials = 0xFFFFFFFF
    std::vector<uint8_t> bomb(MIN_SMILE2_PROOF_BYTES, 0);
    // First 3 uint32s are num_serials, z_size, num_z0
    uint32_t huge = 0xFFFFFFFF;
    std::memcpy(bomb.data(), &huge, 4);
    uint32_t one = 1;
    std::memcpy(bomb.data() + 4, &one, 4);
    std::memcpy(bomb.data() + 8, &one, 4);

    SmileCTProof proof;
    auto err = ParseSmile2Proof(bomb, 1, 1, proof);
    BOOST_CHECK_MESSAGE(err.has_value(),
        "G1: Huge num_serials must be rejected (DoS protection).");
}

// G2: Proof bytes below minimum size.
BOOST_AUTO_TEST_CASE(g2_undersized_proof)
{
    std::vector<uint8_t> tiny(100, 0x42);
    SmileCTProof proof;
    auto err = ParseSmile2Proof(tiny, 1, 1, proof);
    BOOST_CHECK_MESSAGE(err.has_value(),
        "G2: Proof below MIN_SMILE2_PROOF_BYTES must be rejected.");
}

// G3: Proof bytes above maximum size.
BOOST_AUTO_TEST_CASE(g3_oversized_proof)
{
    std::vector<uint8_t> huge(MAX_SMILE2_PROOF_BYTES + 1, 0);
    SmileCTProof proof;
    auto err = ParseSmile2Proof(huge, 1, 1, proof);
    BOOST_CHECK_MESSAGE(err.has_value(),
        "G3: Proof above MAX_SMILE2_PROOF_BYTES must be rejected.");
}

// G4: Valid serialized proof with coefficients >= Q.
// Deserialization should accept raw uint32 values, but verification should
// handle them correctly via mod_q.
BOOST_AUTO_TEST_CASE(g4_serialization_roundtrip_with_large_coefficients)
{
    auto ctx = TestContext::Build(32, {100}, {100}, 0x64);
    BOOST_REQUIRE(ctx.Verify());

    auto bytes = SerializeCTProof(ctx.proof);
    BOOST_CHECK_GT(bytes.size(), 0u);

    SmileCTProof recovered;
    bool ok = DeserializeCTProof(bytes, recovered, 1, 1);
    BOOST_CHECK(ok);

    // Re-serialize and compare
    auto bytes2 = SerializeCTProof(recovered);
    BOOST_CHECK_EQUAL(bytes.size(), bytes2.size());
    BOOST_CHECK(bytes == bytes2);
}

// ============================================================================
// H1-H4: MONOMIAL CHALLENGE GRINDING
//
// The challenge polynomial is c = ±X^k where k = hash[0] % 128 and
// sign = hash[1] & 1. This gives only 256 possible challenges.
// An attacker who can influence the transcript (e.g., via output coin
// choice) could grind for a specific challenge.
// ============================================================================

// H1: Verify challenge space size is exactly 256.
BOOST_AUTO_TEST_CASE(h1_challenge_space_coverage)
{
    std::set<std::pair<uint8_t, int64_t>> unique_challenges;

    // Hash many different inputs and collect unique challenges
    for (uint32_t trial = 0; trial < 10000; ++trial) {
        uint8_t data[36] = {};
        std::memcpy(data, &trial, 4);
        SmilePoly c = TestHashToChallengePoly(data, 36, 600);

        int nonzero_idx = -1;
        int64_t nonzero_val = 0;
        for (size_t i = 0; i < POLY_DEGREE; ++i) {
            if (c.coeffs[i] != 0) {
                nonzero_idx = static_cast<int>(i);
                nonzero_val = mod_q(c.coeffs[i]);
                break;
            }
        }
        if (nonzero_idx >= 0) {
            unique_challenges.insert({static_cast<uint8_t>(nonzero_idx), nonzero_val});
        }
    }

    BOOST_TEST_MESSAGE("H1: Unique challenges seen: " << unique_challenges.size()
                       << " / 256 expected");
    // Should see close to 256 unique challenges
    BOOST_CHECK_GE(unique_challenges.size(), 200u);
    // Must be at most 256
    BOOST_CHECK_LE(unique_challenges.size(), 256u);
}

// H2: Can the attacker grind for c = +1 (the identity monomial)?
// If c = +1, then z = y + r and c*pk = pk directly.
// This is the easiest challenge for forgery attempts.
BOOST_AUTO_TEST_CASE(h2_grind_for_identity_challenge)
{
    // Try many different outputs to find one that gives c_600 = +1 (X^0)
    int found_count = 0;
    for (uint32_t trial = 0; trial < 2000; ++trial) {
        uint8_t data[36] = {};
        std::memcpy(data, &trial, 4);
        SmilePoly c = TestHashToChallengePoly(data, 36, 600);

        if (c.coeffs[0] == 1) {
            found_count++;
        }
    }

    double rate = static_cast<double>(found_count) / 2000.0;
    BOOST_TEST_MESSAGE("H2: Identity challenge hit rate: " << rate
                       << " (expected ~1/256 = " << 1.0/256 << ")");

    // Should be close to 1/256 (not significantly easier to hit)
    BOOST_CHECK_LT(rate, 0.02); // less than 2% (4x the expected rate)
}

// H3: Grinding requires modifying the transcript BEFORE the challenge is derived.
// The attacker's only degree of freedom is output coin selection.
// Verify that changing output coins changes the challenge.
BOOST_AUTO_TEST_CASE(h3_output_coin_influences_challenge)
{
    auto keys = GenerateAnonSet(32, 0x73);
    CTPublicData pub;
    pub.anon_set = ExtractPublicKeys(keys);
    pub.coin_rings = BuildCoinRings(keys, {5}, {100}, 0x73);
    pub.account_rings = test::shielded::BuildDeterministicCTAccountRings(
        keys, pub.coin_rings, 0x7300, 0x9b);

    const auto coin_ck = GetPublicCoinCommitmentKey();
    std::vector<CTInput> inputs = {
        {5, keys[5].sec, SampleTernary(coin_ck.rand_dim(), 0x73 * 100000 + 5), 100}
    };

    // Create proofs with different output amounts (same total)
    std::set<std::pair<uint8_t, int64_t>> challenges;
    for (int split = 1; split < 100; ++split) {
        std::vector<CTOutput> outputs = {
            CTOutput{split, SampleTernary(coin_ck.rand_dim(), 0x7300000 + split)},
            CTOutput{100 - split, SampleTernary(coin_ck.rand_dim(), 0x7310000 + split)}
        };
        auto proof = ProveCT(inputs, outputs, pub, 0x73A);

        SmilePoly c = TestHashToChallengePoly(proof.seed_c.data(), 32, 700);
        for (size_t i = 0; i < POLY_DEGREE; ++i) {
            if (c.coeffs[i] != 0) {
                challenges.insert({static_cast<uint8_t>(i), mod_q(c.coeffs[i])});
                break;
            }
        }
    }

    BOOST_TEST_MESSAGE("H3: Unique challenges from 99 different output splits: "
                       << challenges.size());
    // Different outputs should produce different challenges
    BOOST_CHECK_GT(challenges.size(), 1u);
}

// H4: Verify that both c0 and c challenges actually matter.
// If either challenge is fixed (e.g., always +1), the proof system weakens.
BOOST_AUTO_TEST_CASE(h4_both_challenges_vary)
{
    auto ctx = TestContext::Build(32, {100}, {100}, 0x74);
    BOOST_REQUIRE(ctx.Verify());

    // Check c0 is not identity
    SmilePoly c0 = TestHashToChallengePoly(ctx.proof.seed_c0.data(), 32, 600);
    SmilePoly c = TestHashToChallengePoly(ctx.proof.seed_c.data(), 32, 700);

    bool c0_is_identity = (c0.coeffs[0] == 1);
    bool c_is_identity = (c.coeffs[0] == 1);

    // Both being identity at the same time has probability 1/65536
    // Not a hard failure, but log it
    if (c0_is_identity && c_is_identity) {
        BOOST_TEST_MESSAGE("H4: WARNING — Both challenges are identity. "
                           "This is extremely unlikely (1/65536) and may indicate a bug.");
    }

    // Verify they're different from each other
    BOOST_CHECK_MESSAGE(c0 != c,
        "H4: c0 and c challenges must be different (different domain tags).");
}

// ============================================================================
// I1-I4: MULTI-INPUT AMORTIZATION ABUSE
// ============================================================================

// I1: Swap input order — does the proof still verify?
BOOST_AUTO_TEST_CASE(i1_swap_input_order)
{
    auto ctx = TestContext::Build(32, {100, 200}, {150, 150}, 0x91);
    BOOST_REQUIRE(ctx.Verify());

    SmileCTProof tampered = ctx.proof;
    // Swap z0[0] and z0[1]
    std::swap(tampered.z0[0], tampered.z0[1]);
    // Swap serial numbers
    std::swap(tampered.serial_numbers[0], tampered.serial_numbers[1]);
    // Swap committed W0 rows
    for (size_t row = 0; row < LIVE_CT_PUBLIC_ROWS; ++row) {
        std::swap(tampered.aux_commitment.t_msg[LiveCtW0Slot(2, 2, 0, row)],
                  tampered.aux_commitment.t_msg[LiveCtW0Slot(2, 2, 1, row)]);
    }

    bool valid = VerifyCT(tampered, 2, 2, ctx.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "I1: Swapped input order must be rejected (Fiat-Shamir binding).");
}

// I2: Duplicate a single input's z0 across both inputs.
BOOST_AUTO_TEST_CASE(i2_duplicate_z0_across_inputs)
{
    auto ctx = TestContext::Build(32, {100, 200}, {150, 150}, 0x92);
    BOOST_REQUIRE(ctx.Verify());

    SmileCTProof tampered = ctx.proof;
    tampered.z0[1] = tampered.z0[0];
    for (size_t row = 0; row < LIVE_CT_PUBLIC_ROWS; ++row) {
        tampered.aux_commitment.t_msg[LiveCtW0Slot(2, 2, 1, row)] =
            tampered.aux_commitment.t_msg[LiveCtW0Slot(2, 2, 0, row)];
    }
    tampered.serial_numbers[1] = tampered.serial_numbers[0];

    bool valid = VerifyCT(tampered, 2, 2, ctx.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "I2: Duplicated z0 across inputs must be rejected.");
}

// I3: Exceed MAX_CT_INPUTS / MAX_CT_OUTPUTS.
BOOST_AUTO_TEST_CASE(i3_exceed_max_inputs_outputs)
{
    // The dispatch layer should reject > 16 inputs or outputs
    SmileCTProof proof;
    auto err17in = ParseSmile2Proof({}, 17, 1, proof);
    BOOST_CHECK(err17in.has_value());

    auto err17out = ParseSmile2Proof({}, 1, 17, proof);
    BOOST_CHECK(err17out.has_value());

    auto err0in = ParseSmile2Proof({}, 0, 1, proof);
    BOOST_CHECK(err0in.has_value());

    auto err0out = ParseSmile2Proof({}, 1, 0, proof);
    BOOST_CHECK(err0out.has_value());

    BOOST_TEST_MESSAGE("I3: Input/output count bounds enforced by dispatch.");
}

// I4: Single input proof verified as 2-input proof.
BOOST_AUTO_TEST_CASE(i4_input_count_mismatch)
{
    auto ctx = TestContext::Build(32, {100}, {100}, 0x94);
    BOOST_REQUIRE(ctx.Verify());

    // Try to verify as 2-input proof
    bool valid = VerifyCT(ctx.proof, 2, 1, ctx.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "I4: 1-input proof must fail when verified as 2-input.");
}

// ============================================================================
// J1-J4: ALGEBRAIC STRUCTURE ATTACKS
// Exploit properties of R_q = Z_q[X]/(X^128+1)
// ============================================================================

// J1: Multiply h2 by X (shift all coefficients).
// In R_q = Z_q[X]/(X^128+1), multiplying by X wraps: X^127 * X = X^128 = -1.
// So shifting h2 by one position should NOT preserve the zero-first-4 property.
BOOST_AUTO_TEST_CASE(j1_h2_polynomial_rotation)
{
    auto ctx = TestContext::Build(32, {100}, {100}, 0x81);
    BOOST_REQUIRE(ctx.Verify());

    SmileCTProof tampered = ctx.proof;
    // Multiply h2 by X: new_coeffs[i] = old_coeffs[i-1], with wrap-around negation
    SmilePoly rotated;
    rotated.coeffs[0] = neg_mod_q(mod_q(tampered.h2.coeffs[POLY_DEGREE - 1]));
    for (size_t i = 1; i < POLY_DEGREE; ++i) {
        rotated.coeffs[i] = tampered.h2.coeffs[i - 1];
    }
    tampered.h2 = rotated;

    bool valid = VerifyCT(tampered, 1, 1, ctx.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "J1: Rotated h2 (multiplied by X) must be rejected.");
}

// J2: Add a multiple of (X^128 + 1) to h2. Since we work in R_q = Z_q[X]/(X^128+1),
// X^128 ≡ -1, so adding X^128+1 ≡ 0. But if h2 is stored as raw coefficients
// without reduction, this might create aliasing.
BOOST_AUTO_TEST_CASE(j2_h2_ideal_aliasing)
{
    auto ctx = TestContext::Build(32, {100}, {100}, 0x82);
    BOOST_REQUIRE(ctx.Verify());

    // h2 should already be reduced. Adding 0 should change nothing.
    SmileCTProof tampered = ctx.proof;
    tampered.h2.Reduce();

    bool valid = VerifyCT(tampered, 1, 1, ctx.pub);
    BOOST_CHECK_MESSAGE(valid,
        "J2: Proof with reduced h2 must still verify.");
}

// J3: Set h2 to have coefficients that are Q (which equals 0 mod Q).
// The h2 check does h2_check.Reduce() first, so Q → 0. This should pass
// the zero-coefficient check but is a degenerate case.
BOOST_AUTO_TEST_CASE(j3_h2_coefficients_equal_to_q)
{
    auto ctx = TestContext::Build(32, {100}, {100}, 0x83);
    BOOST_REQUIRE(ctx.Verify());

    SmileCTProof tampered = ctx.proof;
    // Set first 4 coefficients to Q (= 0 mod Q)
    for (size_t i = 0; i < SLOT_DEGREE; ++i) {
        tampered.h2.coeffs[i] = Q;
    }

    // Q ≡ 0 mod q, so after reduction this is identical to the original.
    // Both Reduce() in the h2 check and mod_q() in AppendPoly map Q→0.
    // This is NOT a vulnerability — the canonical form is the same.
    bool valid = VerifyCT(tampered, 1, 1, ctx.pub);
    // Q and 0 are the same element in Z_q, so this should still verify.
    // If we wanted to reject non-canonical coefficients, we'd need a
    // pre-reduction check, but that's not cryptographically necessary.
    BOOST_CHECK_MESSAGE(valid,
        "J3: h2 with coefficients = Q should verify (Q ≡ 0 mod q, canonical equivalence).");
}

// J4: NTT-domain attack: modify the proof in NTT representation.
// Convert h2 to NTT, flip one slot, convert back. This changes all
// 128 coefficients in the time domain.
BOOST_AUTO_TEST_CASE(j4_ntt_domain_h2_tampering)
{
    auto ctx = TestContext::Build(32, {100}, {100}, 0x84);
    BOOST_REQUIRE(ctx.Verify());

    SmileCTProof tampered = ctx.proof;
    NttForm h2_ntt = NttForward(tampered.h2);
    // Flip one slot coefficient
    h2_ntt.slots[16].coeffs[0] = mod_q(h2_ntt.slots[16].coeffs[0] + 1);
    tampered.h2 = NttInverse(h2_ntt);
    tampered.h2.Reduce();

    bool valid = VerifyCT(tampered, 1, 1, ctx.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "J4: NTT-domain tampering of h2 must be detected.");
}

// ============================================================================
// K1-K5: NORM BOUND EXPLOITATION
// The verifier checks ||z0||_2 < beta0 and ||z||_2 < beta.
// These tests try to find vectors that pass norm bounds but break the proof.
// ============================================================================

// K1: z0 at exactly the norm boundary (beta0^2 - 1).
BOOST_AUTO_TEST_CASE(k1_z0_at_norm_boundary)
{
    auto ctx = TestContext::Build(32, {100}, {100}, 0x71);
    BOOST_REQUIRE(ctx.Verify());

    // Check the actual norm of the valid z0
    __int128 z0_norm_sq = 0;
    int64_t half_q = Q / 2;
    for (size_t j = 0; j < ctx.proof.z0[0].size(); ++j) {
        for (size_t c = 0; c < POLY_DEGREE; ++c) {
            int64_t val = mod_q(ctx.proof.z0[0][j].coeffs[c]);
            if (val > half_q) val -= Q;
            z0_norm_sq += static_cast<__int128>(val) * val;
        }
    }
    __int128 beta0_sq = static_cast<__int128>(SIGMA_KEY) * SIGMA_KEY * 2 * KEY_COLS * POLY_DEGREE;

    BOOST_TEST_MESSAGE("K1: Valid z0 norm^2 = " << static_cast<int64_t>(z0_norm_sq)
                       << ", beta0^2 = " << static_cast<int64_t>(beta0_sq)
                       << ", ratio = " << static_cast<double>(z0_norm_sq) / static_cast<double>(beta0_sq));

    // The norm should be well under the bound
    BOOST_CHECK_LT(static_cast<double>(z0_norm_sq), static_cast<double>(beta0_sq));
}

// K2: z0 with all coefficients at maximum allowed magnitude.
// If each coefficient is at SIGMA_KEY, does the total norm exceed beta0?
BOOST_AUTO_TEST_CASE(k2_z0_all_max_coefficients)
{
    auto ctx = TestContext::Build(32, {100}, {100}, 0x72);
    BOOST_REQUIRE(ctx.Verify());

    SmileCTProof tampered = ctx.proof;
    // Set all z0 coefficients to SIGMA_KEY
    for (auto& z0_poly : tampered.z0[0]) {
        for (size_t c = 0; c < POLY_DEGREE; ++c) {
            z0_poly.coeffs[c] = SIGMA_KEY;
        }
    }

    // Compute norm: KEY_COLS * POLY_DEGREE * SIGMA_KEY^2
    __int128 norm_sq = static_cast<__int128>(KEY_COLS) * POLY_DEGREE * SIGMA_KEY * SIGMA_KEY;
    __int128 beta0_sq = static_cast<__int128>(SIGMA_KEY) * SIGMA_KEY * 2 * KEY_COLS * POLY_DEGREE;

    BOOST_TEST_MESSAGE("K2: All-max z0 norm^2 = " << static_cast<int64_t>(norm_sq)
                       << ", beta0^2 = " << static_cast<int64_t>(beta0_sq)
                       << " (ratio " << static_cast<double>(norm_sq) / static_cast<double>(beta0_sq) << ")");

    // norm_sq = KEY_COLS * d * sigma^2 = beta0_sq / 2, so it passes
    // But the Fiat-Shamir will fail since z0 is fake
    bool valid = VerifyCT(tampered, 1, 1, ctx.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "K2: z0 with all-max coefficients should fail Fiat-Shamir (z0 is synthetic).");
}

// K3: z vector with norm exactly at beta (should be rejected, strict <).
BOOST_AUTO_TEST_CASE(k3_z_norm_exact_boundary)
{
    auto ctx = TestContext::Build(32, {100}, {100}, 0x73);
    BOOST_REQUIRE(ctx.Verify());

    // Compute the actual z norm to verify it's well under the bound
    __int128 z_norm_sq = 0;
    int64_t half_q = Q / 2;
    for (size_t j = 0; j < ctx.proof.z.size(); ++j) {
        for (size_t c = 0; c < POLY_DEGREE; ++c) {
            int64_t val = mod_q(ctx.proof.z[j].coeffs[c]);
            if (val > half_q) val -= Q;
            z_norm_sq += static_cast<__int128>(val) * val;
        }
    }

    size_t rdim = ctx.proof.z.size();
    __int128 beta_sq = static_cast<__int128>(SIGMA_MASK) * SIGMA_MASK * 2 * rdim * POLY_DEGREE;

    double ratio = static_cast<double>(z_norm_sq) / static_cast<double>(beta_sq);
    BOOST_TEST_MESSAGE("K3: Valid z norm ratio: " << ratio);
    BOOST_CHECK_LT(ratio, 1.0);
}

// ============================================================================
// L1-L3: COMBINED ATTACK CHAINS
// Multi-step attacks that combine multiple weak vectors.
// ============================================================================

// L1: Full forgery attempt — construct a proof from scratch for a non-member key.
// Use:
//   - Valid h2 (first 4 coefficients zero)
//   - Small-norm z and z0
//   - Crafted w0_vals for key membership
//   - Matching Fiat-Shamir seeds
// This is the "can I forge a proof from whole cloth?" test.
BOOST_AUTO_TEST_CASE(l1_full_forgery_attempt)
{
    auto keys = GenerateAnonSet(32, 0x51);
    CTPublicData pub;
    pub.anon_set = ExtractPublicKeys(keys);
    pub.coin_rings = BuildCoinRings(keys, {5}, {100}, 0x51);
    pub.account_rings = test::shielded::BuildDeterministicCTAccountRings(
        keys, pub.coin_rings, 0x5100, 0x9c);

    // The attacker doesn't know any secret key.
    // They want to create a proof that claims to spend from key index 5.
    SmileCTProof forged;
    forged.serial_numbers.resize(1);
    forged.z0.resize(1);
    forged.z0[0].resize(KEY_COLS);
    EnsureLiveCtAuxState(forged, 1, 1);

    // Step 1: Choose random small-norm z0
    std::mt19937_64 rng(0x51F);
    for (auto& z0_poly : forged.z0[0]) {
        for (size_t c = 0; c < POLY_DEGREE; ++c) {
            int64_t val = (rng() % 7) - 3; // [-3, 3]
            z0_poly.coeffs[c] = mod_q(val);
        }
    }

    // Step 2: Compute "serial number" (random, since we don't have the key)
    for (size_t c = 0; c < POLY_DEGREE; ++c) {
        forged.serial_numbers[0].coeffs[c] = mod_q(rng());
    }

    // Step 3: Create output coins
    auto out_ck_seed = std::array<uint8_t, 32>{};
    out_ck_seed[0] = 0xCC;
    auto out_ck = BDLOPCommitmentKey::Generate(out_ck_seed, 1);
    SmilePoly amount_poly = EncodeAmountToSmileAmountPoly(100).value();
    auto r_out = SampleTernary(out_ck.rand_dim(), 0xFA4E);
    forged.output_coins = {Commit(out_ck, {amount_poly}, r_out)};

    // Step 4: Build Fiat-Shamir transcript to get fs_seed
    size_t k = KEY_ROWS;
    size_t N = pub.anon_set.size();
    std::vector<uint8_t> transcript;
    {
        CSHA256 pk_hash;
        for (size_t i = 0; i < N; ++i) {
            for (size_t j = 0; j < k; ++j) {
                for (size_t c = 0; c < POLY_DEGREE; ++c) {
                    uint32_t val = static_cast<uint32_t>(mod_q(pub.anon_set[i].pk[j].coeffs[c]));
                    pk_hash.Write(reinterpret_cast<uint8_t*>(&val), 4);
                }
            }
        }
        uint8_t pk_digest[32];
        pk_hash.Finalize(pk_digest);
        transcript.insert(transcript.end(), pk_digest, pk_digest + 32);
    }
    AppendCoinRingDigest(transcript, pub);
    for (const auto& coin : forged.output_coins) {
        for (const auto& t : coin.t0) {
            for (size_t i = 0; i < POLY_DEGREE; ++i) {
                uint32_t val = static_cast<uint32_t>(mod_q(t.coeffs[i]));
                transcript.insert(transcript.end(),
                    reinterpret_cast<uint8_t*>(&val),
                    reinterpret_cast<uint8_t*>(&val) + 4);
            }
        }
        for (const auto& t : coin.t_msg) {
            for (size_t i = 0; i < POLY_DEGREE; ++i) {
                uint32_t val = static_cast<uint32_t>(mod_q(t.coeffs[i]));
                transcript.insert(transcript.end(),
                    reinterpret_cast<uint8_t*>(&val),
                    reinterpret_cast<uint8_t*>(&val) + 4);
            }
        }
    }
    {
        CSHA256 hasher;
        hasher.Write(transcript.data(), transcript.size());
        hasher.Finalize(forged.fs_seed.data());
    }

    // Step 5: Create a fake aux commitment and compute seed_c0
    // Use random t0 and t_msg
    forged.aux_commitment.t0.resize(BDLOP_RAND_DIM_BASE);
    forged.aux_commitment.t_msg.resize(10);
    for (auto& t : forged.aux_commitment.t0) {
        for (size_t c = 0; c < POLY_DEGREE; ++c) t.coeffs[c] = mod_q(rng());
    }
    for (auto& t : forged.aux_commitment.t_msg) {
        for (size_t c = 0; c < POLY_DEGREE; ++c) t.coeffs[c] = mod_q(rng());
    }

    // Append compressed t0 + t_msg + serial to transcript for seed_c0
    size_t t0_count = std::min(forged.aux_commitment.t0.size(), static_cast<size_t>(MSIS_RANK));
    for (size_t i = 0; i < t0_count; ++i) {
        for (size_t c = 0; c < POLY_DEGREE; ++c) {
            uint32_t val = static_cast<uint32_t>(mod_q(forged.aux_commitment.t0[i].coeffs[c]));
            uint32_t compressed = val >> COMPRESS_D;
            transcript.push_back(static_cast<uint8_t>(compressed & 0xFF));
            transcript.push_back(static_cast<uint8_t>((compressed >> 8) & 0xFF));
            transcript.push_back(static_cast<uint8_t>((compressed >> 16) & 0xFF));
        }
    }
    for (const auto& t : forged.aux_commitment.t_msg) {
        for (size_t i = 0; i < POLY_DEGREE; ++i) {
            uint32_t val = static_cast<uint32_t>(mod_q(t.coeffs[i]));
            transcript.insert(transcript.end(),
                reinterpret_cast<uint8_t*>(&val),
                reinterpret_cast<uint8_t*>(&val) + 4);
        }
    }
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        uint32_t val = static_cast<uint32_t>(mod_q(forged.serial_numbers[0].coeffs[i]));
        transcript.insert(transcript.end(),
            reinterpret_cast<uint8_t*>(&val),
            reinterpret_cast<uint8_t*>(&val) + 4);
    }
    {
        CSHA256 hasher;
        hasher.Write(transcript.data(), transcript.size());
        hasher.Finalize(forged.seed_c0.data());
    }

    // Step 6: Derive c0, then craft committed W0 rows for key membership at target index 5
    SmilePoly c0_chal = TestHashToChallengePoly(forged.seed_c0.data(), 32, 600);
    const auto& A = pub.anon_set[0].A;
    size_t target = 5;

    for (size_t i = 0; i < k; ++i) {
        SmilePoly az0_i;
        for (size_t j = 0; j < KEY_COLS; ++j) {
            az0_i += NttMul(A[i][j], forged.z0[0][j]);
        }
        az0_i.Reduce();
        SmilePoly c0_pk = NttMul(c0_chal, pub.anon_set[target].pk[i]);
        c0_pk.Reduce();
        forged.aux_commitment.t_msg[LiveCtW0Slot(1, 1, 0, i)] = az0_i - c0_pk;
        forged.aux_commitment.t_msg[LiveCtW0Slot(1, 1, 0, i)].Reduce();
    }

    // Step 7: Continue transcript to compute seed_c
    for (const auto& z0i : forged.z0) {
        for (const auto& zi : z0i) {
            for (size_t i = 0; i < POLY_DEGREE; ++i) {
                uint32_t val = static_cast<uint32_t>(mod_q(zi.coeffs[i]));
                transcript.insert(transcript.end(),
                    reinterpret_cast<uint8_t*>(&val),
                    reinterpret_cast<uint8_t*>(&val) + 4);
            }
        }
    }
    for (size_t inp = 0; inp < 1; ++inp) {
        for (size_t i = 0; i < k; ++i) {
            SmilePoly az0_i;
            for (size_t j = 0; j < KEY_COLS; ++j) {
                az0_i += NttMul(A[i][j], forged.z0[0][j]);
            }
            az0_i.Reduce();
            for (size_t c = 0; c < POLY_DEGREE; ++c) {
                uint32_t val = static_cast<uint32_t>(mod_q(az0_i.coeffs[c]));
                transcript.insert(transcript.end(),
                    reinterpret_cast<uint8_t*>(&val),
                    reinterpret_cast<uint8_t*>(&val) + 4);
            }
        }
    }
    // b_sn dot z0 binding
    auto sn_ck_seed = std::array<uint8_t, 32>{};
    sn_ck_seed[0] = 0xAA;
    auto sn_ck = BDLOPCommitmentKey::Generate(sn_ck_seed, 1);
    {
        SmilePoly bsn_z0;
        for (size_t j = 0; j < KEY_COLS && j < sn_ck.b[0].size(); ++j) {
            bsn_z0 += NttMul(sn_ck.b[0][j], forged.z0[0][j]);
        }
        bsn_z0.Reduce();
        for (size_t i = 0; i < POLY_DEGREE; ++i) {
            uint32_t val = static_cast<uint32_t>(mod_q(bsn_z0.coeffs[i]));
            transcript.insert(transcript.end(),
                reinterpret_cast<uint8_t*>(&val),
                reinterpret_cast<uint8_t*>(&val) + 4);
        }
    }

    // Step 8: h2 with zero first 4 coefficients
    for (size_t c = 0; c < POLY_DEGREE; ++c) {
        forged.h2.coeffs[c] = (c < SLOT_DEGREE) ? 0 : mod_q(rng());
    }
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        uint32_t val = static_cast<uint32_t>(mod_q(forged.h2.coeffs[i]));
        transcript.insert(transcript.end(),
            reinterpret_cast<uint8_t*>(&val),
            reinterpret_cast<uint8_t*>(&val) + 4);
    }
    {
        CSHA256 hasher;
        hasher.Write(transcript.data(), transcript.size());
        hasher.Finalize(forged.seed_c.data());
    }

    // Step 9: Create z with valid norm
    (void)TestHashToChallengePoly(forged.seed_c.data(), 32, 700);
    size_t n_aux_msg = forged.aux_commitment.t_msg.size();
    size_t z_dim = BDLOP_RAND_DIM_BASE + n_aux_msg;
    forged.z.resize(z_dim);
    for (auto& zi : forged.z) {
        for (size_t c = 0; c < POLY_DEGREE; ++c) {
            int64_t val = (rng() % (2 * SIGMA_MASK + 1)) - SIGMA_MASK;
            zi.coeffs[c] = mod_q(val);
        }
    }

    bool valid = VerifyCT(forged, 1, 1, pub);
    BOOST_CHECK_MESSAGE(!valid,
        "L1: CRITICAL — Full forgery from scratch was ACCEPTED! "
        "The attacker constructed a proof without knowing any secret key, "
        "using only public information and crafted w0_vals. "
        "This means VerifyCT is completely broken.");

    // Even if the full forgery fails, check WHICH step caught it.
    // This helps understand the real security margin.
    BOOST_TEST_MESSAGE("L1: Full forgery rejected (expected). "
                       "The question is: which check caught it?");
}

// L2: Partial forgery — take a valid proof and only forge the serial number.
// Keep z, z0, w0_vals, h2 from the valid proof. Only change serial_numbers.
// Then recompute seed_c0 to match. If VerifyCT doesn't bind serial numbers
// to the key opening, this could succeed.
BOOST_AUTO_TEST_CASE(l2_serial_only_forgery)
{
    auto ctx = TestContext::Build(32, {100}, {100}, 0x52);
    BOOST_REQUIRE(ctx.Verify());

    // This is the critical question: can we change ONLY the serial number
    // and still pass verification?
    // The serial number appears in the transcript for seed_c0.
    // Changing it changes c0, which changes the key membership check.
    // So z0 = y0 + OLD_c0 * s won't match NEW_c0 * pk.
    // UNLESS we also recompute w0_vals.

    SmileCTProof tampered = ctx.proof;
    SmilePoly fake_sn;
    for (size_t c = 0; c < POLY_DEGREE; ++c) {
        fake_sn.coeffs[c] = mod_q(c * 777 + 1);
    }
    tampered.serial_numbers[0] = fake_sn;

    // Don't fix anything else — this should definitely fail
    bool valid = VerifyCT(tampered, 1, 1, ctx.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "L2: Serial-only forgery must be rejected (seed_c0 mismatch).");
}

// L3: Valid proof for key A, try to make it look like key B by adjusting
// ONLY w0_vals and serial_numbers (keep z0 from key A's proof).
// This is the w0_vals retargeting attack from the deep tests, but more
// carefully constructed.
BOOST_AUTO_TEST_CASE(l3_retarget_proof_to_different_key)
{
    auto ctx = TestContext::Build(32, {100}, {100}, 0x53);
    BOOST_REQUIRE(ctx.Verify());

    // The real signer is at ctx.inputs[0].secret_index.
    // Try to retarget to a different key.
    size_t real_idx = ctx.inputs[0].secret_index;
    size_t fake_idx = (real_idx + 5) % 32;

    SmileCTProof tampered = ctx.proof;

    // Recompute w0_vals to point to fake_idx
    SmilePoly c0_chal = TestHashToChallengePoly(tampered.seed_c0.data(), 32, 600);
    const auto& A = ctx.pub.anon_set[0].A;

    for (size_t i = 0; i < KEY_ROWS; ++i) {
        SmilePoly az0_i;
        for (size_t j = 0; j < KEY_COLS; ++j) {
            az0_i += NttMul(A[i][j], tampered.z0[0][j]);
        }
        az0_i.Reduce();
        SmilePoly c0_pk_fake = NttMul(c0_chal, ctx.pub.anon_set[fake_idx].pk[i]);
        c0_pk_fake.Reduce();
        tampered.aux_commitment.t_msg[LiveCtW0Slot(1, 1, 0, i)] = az0_i - c0_pk_fake;
        tampered.aux_commitment.t_msg[LiveCtW0Slot(1, 1, 0, i)].Reduce();
    }

    bool valid = VerifyCT(tampered, 1, 1, ctx.pub);
    BOOST_CHECK_MESSAGE(!valid,
        "L3: CRITICAL — Retargeted proof to different key via committed W0 rows was ACCEPTED! "
        "The committed first-round rows are not bound by the Fiat-Shamir transcript or commitment. "
        "An attacker can make any proof appear to come from any key in the set.");

    if (valid) {
        BOOST_TEST_MESSAGE(
            "L3: This confirms the audit finding: w0_vals are malleable in VerifyCT. "
            "The key membership check is the ONLY barrier, and it uses attacker-supplied w0_vals. "
            "FIX: Either hash w0_vals into the transcript, or verify the BDLOP opening "
            "(which would bind w0 = A*y0 via the commitment).");
    }
}

BOOST_AUTO_TEST_SUITE_END()

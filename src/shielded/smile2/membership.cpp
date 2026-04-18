// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/smile2/membership.h>
#include <shielded/smile2/domain_separation.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <random.h>

#include <cassert>
#include <cmath>
#include <cstring>
#include <limits>
#include <numbers>
#include <optional>

namespace smile2 {

namespace {

// Expand a pseudorandom polynomial from hash
SmilePoly HashToPoly(const uint8_t* data, size_t len, uint32_t domain, uint32_t index)
{
    SmilePoly p;
    for (size_t block = 0; block < POLY_DEGREE; block += 8) {
        CSHA256 hasher;
        hasher.Write(data, len);
        uint8_t buf[12];
        WriteLE32(buf, domain);
        WriteLE32(buf + 4, index);
        uint32_t blk = static_cast<uint32_t>(block);
        WriteLE32(buf + 8, blk);
        hasher.Write(buf, 12);
        uint8_t hash[32];
        hasher.Finalize(hash);
        for (size_t i = 0; i < 8 && (block + i) < POLY_DEGREE; ++i) {
            const uint32_t val = ReadLE32(hash + 4 * i);
            p.coeffs[block + i] = static_cast<int64_t>(val) % Q;
        }
    }
    return p;
}

using SlotChallenge = std::array<NttSlot, NUM_NTT_SLOTS>;
constexpr size_t MAX_MEMBERSHIP_REJECTION_RETRIES{256};
constexpr size_t MAX_MEMBERSHIP_TIMING_PADDING_ATTEMPTS{MAX_MEMBERSHIP_REJECTION_RETRIES};
volatile uint64_t g_membership_padding_sink{0};

// Hash to get l=32 slot challenges in M_q.
SlotChallenge HashToSlotChallenge(
    const uint8_t* data, size_t len, uint32_t domain)
{
    SlotChallenge result{};
    for (size_t i = 0; i < NUM_NTT_SLOTS; ++i) {
        CSHA256 hasher;
        hasher.Write(data, len);
        uint8_t buf[8];
        WriteLE32(buf, domain);
        uint32_t idx = static_cast<uint32_t>(i);
        WriteLE32(buf + 4, idx);
        hasher.Write(buf, 8);
        uint8_t hash[32];
        hasher.Finalize(hash);
        for (size_t c = 0; c < SLOT_DEGREE; ++c) {
            const uint32_t val = ReadLE32(hash + (4 * c));
            result[i].coeffs[c] = static_cast<int64_t>(val) % Q;
        }
    }
    return result;
}

// Challenge polynomial: coefficients independently distributed as
// P(0)=1/2 and P(1)=P(-1)=1/4, matching the paper's challenge
// distribution C.
SmilePoly HashToTernaryChallenge(const uint8_t* data, size_t len, uint32_t domain)
{
    SmilePoly c;
    for (size_t block = 0; block < POLY_DEGREE; block += 64) {
        CSHA256 hasher;
        hasher.Write(data, len);
        uint8_t buf[8];
        WriteLE32(buf, domain);
        uint32_t blk = static_cast<uint32_t>(block);
        WriteLE32(buf + 4, blk);
        hasher.Write(buf, 8);
        uint8_t hash[32];
        hasher.Finalize(hash);

        for (size_t byte_idx = 0; byte_idx < 32 && (block + 2 * byte_idx) < POLY_DEGREE; ++byte_idx) {
            const uint8_t byte = hash[byte_idx];
            for (size_t nibble = 0; nibble < 2; ++nibble) {
                const size_t coeff_idx = block + (2 * byte_idx) + nibble;
                if (coeff_idx >= POLY_DEGREE) {
                    break;
                }
                const uint8_t two_bits = (byte >> (2 * nibble)) & 0x3;
                if (two_bits == 0 || two_bits == 1) {
                    c.coeffs[coeff_idx] = 0;
                } else if (two_bits == 2) {
                    c.coeffs[coeff_idx] = 1;
                } else {
                    c.coeffs[coeff_idx] = mod_q(-1);
                }
            }
        }
    }
    return c;
}

// Deterministic PRNG
class DetRng {
    FastRandomContext m_ctx;
public:
    static uint256 SeedToHash(uint64_t seed)
    {
        uint8_t seed_bytes[8];
        WriteLE64(seed_bytes, seed);
        uint256 seed_hash;
        CSHA256().Write(seed_bytes, sizeof(seed_bytes)).Finalize(seed_hash.begin());
        return seed_hash;
    }

    explicit DetRng(uint64_t seed) : m_ctx(SeedToHash(seed)) {}

    uint64_t Next() { return m_ctx.rand64(); }

    int64_t UniformModQ() {
        uint64_t hi = Next();
        uint64_t lo = Next();
        __int128 combined = (static_cast<__int128>(hi) << 32) | (lo & 0xFFFFFFFF);
        return static_cast<int64_t>(static_cast<uint64_t>(combined % Q));
    }

    // Discrete Gaussian approximation: rounded continuous Gaussian
    int64_t GaussianSample(int64_t sigma) {
        // Box-Muller from deterministic bits
        double u1 = static_cast<double>(Next() & 0xFFFFFFFF) / 4294967296.0;
        double u2 = static_cast<double>(Next() & 0xFFFFFFFF) / 4294967296.0;
        if (u1 < 1e-10) u1 = 1e-10;
        double z = std::sqrt(-2.0 * std::log(u1)) * std::cos(2.0 * std::numbers::pi_v<double> * u2);
        int64_t val = static_cast<int64_t>(std::round(z * static_cast<double>(sigma)));
        return mod_q(val);
    }

    SmilePoly GaussianPoly(int64_t sigma) {
        SmilePoly p;
        for (size_t i = 0; i < POLY_DEGREE; ++i) {
            p.coeffs[i] = GaussianSample(sigma);
        }
        return p;
    }
};

std::array<uint8_t, 32> DrawStrongTernarySeed(DetRng& rng)
{
    std::array<uint8_t, 32> seed{};
    for (size_t offset = 0; offset < seed.size(); offset += sizeof(uint64_t)) {
        WriteLE64(seed.data() + offset, rng.Next());
    }
    return seed;
}

enum class RejectionMode {
    Rej0,
    Rej1,
};

// Rejection sampling (SMILE paper Figure 10).
//
// The in-tree prototype originally used a monomial-specific shortcut bound of
// 14 for ||c·v||^2. That shortcut breaks once the challenge distribution is
// widened to the dense ternary set C from the paper. Here we instead use the
// paper-shaped constant-M acceptance rule and switch the main z path onto Rej1.
bool RejectionSample(const SmilePolyVec& z, const SmilePolyVec& cv,
                     int64_t sigma, DetRng& rng, RejectionMode mode)
{
    // Compute ⟨z, cv⟩ = Σ_i Σ_j z[i].coeffs[j] * cv[i].coeffs[j]
    // (centered coefficients)
    double inner = 0.0;
    double cv_norm_sq = 0.0;
    int64_t half_q = Q / 2;
    for (size_t i = 0; i < z.size() && i < cv.size(); ++i) {
        for (size_t j = 0; j < POLY_DEGREE; ++j) {
            int64_t zval = mod_q(z[i].coeffs[j]);
            if (zval > half_q) zval -= Q;
            int64_t cval = mod_q(cv[i].coeffs[j]);
            if (cval > half_q) cval -= Q;
            inner += static_cast<double>(zval) * static_cast<double>(cval);
            cv_norm_sq += static_cast<double>(cval) * static_cast<double>(cval);
        }
    }

    if (mode == RejectionMode::Rej1 && inner < 0.0) {
        return false;
    }

    double sigma_sq = static_cast<double>(sigma) * static_cast<double>(sigma);
    static constexpr double REJECTION_M = 3.0;
    double log_accept =
        (-2.0 * inner + cv_norm_sq) / (2.0 * sigma_sq) - std::log(REJECTION_M);

    if (log_accept >= 0.0) return true; // always accept

    // Accept with probability exp(log_accept). Use the full 64-bit draw so the
    // membership path matches the CT prover's rejection-coin entropy.
    double u = static_cast<double>(rng.Next()) / 18446744073709551616.0;
    return std::log(u) < log_accept;
}

uint64_t DeriveMembershipPaddingSeed(const SmileMembershipProof& proof,
                                     uint64_t rng_seed,
                                     bool bind_anonset_context)
{
    CSHA256 hasher;
    static constexpr char kDomain[] = "BTX_SMILE2_MEMBERSHIP_PADDING_V1";
    hasher.Write(reinterpret_cast<const uint8_t*>(kDomain), sizeof(kDomain) - 1);
    hasher.Write(proof.seed_c0.data(), proof.seed_c0.size());
    hasher.Write(proof.seed_c.data(), proof.seed_c.size());
    uint8_t seed_buf[8];
    WriteLE64(seed_buf, rng_seed);
    hasher.Write(seed_buf, sizeof(seed_buf));
    seed_buf[0] = bind_anonset_context ? 1 : 0;
    hasher.Write(seed_buf, 1);
    uint8_t hash[32];
    hasher.Finalize(hash);
    return ReadLE64(hash);
}

size_t ComputeRecursionLevels(size_t N);
size_t ComputeNumMsg(size_t m);
void HashAnonSet(std::vector<uint8_t>& transcript,
                 const std::vector<SmilePublicKey>& anon_set,
                 bool bind_anonset_context);
SmilePolyVec ComputeB0Response(const BDLOPCommitmentKey& ck,
                               const SmilePolyVec& witness);

// Fiat-Shamir transcript hash
std::array<uint8_t, 32> TranscriptHash(const std::vector<uint8_t>& transcript)
{
    CSHA256 hasher;
    hasher.Write(transcript.data(), transcript.size());
    std::array<uint8_t, 32> hash{};
    hasher.Finalize(hash.data());
    return hash;
}

void AppendUint32(std::vector<uint8_t>& transcript, uint32_t value)
{
    uint8_t buf[4];
    WriteLE32(buf, value);
    transcript.insert(transcript.end(), buf, buf + sizeof(buf));
}

void AppendPoly(std::vector<uint8_t>& transcript, const SmilePoly& p)
{
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        uint32_t val = static_cast<uint32_t>(mod_q(p.coeffs[i]));
        uint8_t buf[4];
        WriteLE32(buf, val);
        transcript.insert(transcript.end(), buf, buf + sizeof(buf));
    }
}

void RunMembershipPaddingIterations(const std::vector<SmilePublicKey>& anon_set,
                                    const SmileSecretKey& sk,
                                    uint64_t rng_seed,
                                    size_t accepted_attempt,
                                    bool bind_anonset_context,
                                    const SmileMembershipProof& proof)
{
    const size_t padding_attempt_limit =
        std::min(MAX_MEMBERSHIP_REJECTION_RETRIES, MAX_MEMBERSHIP_TIMING_PADDING_ATTEMPTS);
    if (anon_set.empty() || accepted_attempt + 1 >= padding_attempt_limit) {
        return;
    }

    const size_t m = ComputeRecursionLevels(anon_set.size());
    if (m == 0) return;

    std::vector<uint8_t> transcript;
    HashAnonSet(transcript, anon_set, bind_anonset_context);
    const auto ck_seed = TranscriptHash(transcript);
    const auto ck = BDLOPCommitmentKey::Generate(ck_seed, ComputeNumMsg(m));
    const auto& A = anon_set[0].A;
    const uint64_t padding_seed = DeriveMembershipPaddingSeed(
        proof, rng_seed, bind_anonset_context);

    for (size_t pad = accepted_attempt + 1; pad < padding_attempt_limit; ++pad) {
        DetRng rng(padding_seed + static_cast<uint64_t>(pad));
        const auto r_com = SampleTernaryStrong(ck.rand_dim(), DrawStrongTernarySeed(rng));

        SmilePolyVec y_mask(ck.rand_dim());
        for (auto& yi : y_mask) {
            yi = rng.GaussianPoly(MEMBERSHIP_SIGMA_MASK);
        }
        SmilePolyVec y0_mask(KEY_COLS);
        for (auto& yi : y0_mask) {
            yi = rng.GaussianPoly(MEMBERSHIP_SIGMA_KEY);
        }

        auto w_mask = ComputeB0Response(ck, y_mask);
        std::vector<uint8_t> pad_transcript = transcript;
        for (const auto& wi : w_mask) {
            AppendPoly(pad_transcript, wi);
        }
        AppendUint32(pad_transcript, static_cast<uint32_t>(m));

        const auto seed_c0 = TranscriptHash(pad_transcript);
        const SmilePoly c0_chal =
            HashToTernaryChallenge(seed_c0.data(), seed_c0.size(), domainsep::MEMBERSHIP_C0);

        SmilePolyVec z0(KEY_COLS);
        SmilePolyVec c0s(KEY_COLS);
        for (size_t j = 0; j < KEY_COLS; ++j) {
            c0s[j] = NttMul(c0_chal, sk.s[j]);
            c0s[j].Reduce();
            z0[j] = y0_mask[j] + c0s[j];
            z0[j].Reduce();
            AppendPoly(pad_transcript, z0[j]);
        }
        for (size_t row = 0; row < KEY_ROWS; ++row) {
            SmilePoly az0_row;
            for (size_t col = 0; col < KEY_COLS; ++col) {
                az0_row += NttMul(A[row][col], z0[col]);
            }
            az0_row.Reduce();
            AppendPoly(pad_transcript, az0_row);
        }

        const bool z0_accept =
            RejectionSample(z0, c0s, MEMBERSHIP_SIGMA_KEY, rng, RejectionMode::Rej0);
        const auto seed_c = TranscriptHash(pad_transcript);
        const SmilePoly c_chal =
            HashToTernaryChallenge(seed_c.data(), seed_c.size(), domainsep::MEMBERSHIP_C);

        SmilePolyVec z(ck.rand_dim());
        SmilePolyVec cr(ck.rand_dim());
        for (size_t j = 0; j < ck.rand_dim(); ++j) {
            cr[j] = NttMul(c_chal, r_com[j]);
            cr[j].Reduce();
            z[j] = y_mask[j] + cr[j];
            z[j].Reduce();
        }
        const bool z_accept =
            RejectionSample(z, cr, MEMBERSHIP_SIGMA_MASK, rng, RejectionMode::Rej1);

        g_membership_padding_sink ^=
            ReadLE64(seed_c0.data()) ^
            ReadLE64(seed_c.data()) ^
            static_cast<uint64_t>(mod_q(z0.front().coeffs[0])) ^
            static_cast<uint64_t>(mod_q(z.front().coeffs[0])) ^
            (static_cast<uint64_t>(z0_accept) << 1) ^
            (static_cast<uint64_t>(z_accept) << 2);
    }
}

size_t ComputeRecursionLevels(size_t N) {
    if (N == 0) return 0;
    if (N <= NUM_NTT_SLOTS) return 1;
    size_t m = 0;
    size_t power = 1;
    while (power < N) {
        if (power > std::numeric_limits<size_t>::max() / NUM_NTT_SLOTS) {
            return 0;
        }
        power *= NUM_NTT_SLOTS;
        m++;
    }
    return m;
}

size_t PadToLPower(size_t N) {
    size_t m = ComputeRecursionLevels(N);
    if (m == 0) return 0;
    size_t padded = 1;
    for (size_t i = 0; i < m; ++i) {
        if (padded > std::numeric_limits<size_t>::max() / NUM_NTT_SLOTS) {
            return 0;
        }
        padded *= NUM_NTT_SLOTS;
    }
    return padded;
}

size_t ComputeIntermediateXSlotCount(size_t m)
{
    // The legacy prototype omitted x_2 entirely on the m=1 path, which forced
    // verification back onto the public effective-row lookup. The rewritten
    // layout always carries the first compressed x state so m=1 uses one
    // explicit x_2 slot and m>1 carries x_2..x_m as before.
    return (m == 1) ? 1 : (m - 1);
}

size_t ComputeFirstXSlot(size_t m)
{
    return m + KEY_ROWS;
}

size_t ComputeGSlot(size_t m)
{
    return ComputeFirstXSlot(m) + ComputeIntermediateXSlotCount(m);
}

size_t ComputePsiSlot(size_t m)
{
    return ComputeGSlot(m) + 1;
}

// Number of BDLOP message slots for the membership proof
// Layout (Figure 7):
//   slots 0..m-1:     selectors v_1,...,v_m
//   slots m..m+k-1:   w_0 values (A·y_0)
//   slots m+k..:      x intermediates
//                      - m=1: x_2
//                      - m>1: x_2,...,x_m
//   next slot:        garbage g (zero first d/l coeffs)
//   next slot:        combined garbage ψ = ψ_bin + ρ_0·ψ_sm
size_t ComputeNumMsg(size_t m) {
    return ComputePsiSlot(m) + 1;
}

// Hash the anonymity set public keys into a compact digest
void HashAnonSet(std::vector<uint8_t>& transcript,
                 const std::vector<SmilePublicKey>& anon_set,
                 bool bind_anonset_context)
{
    CSHA256 pk_hash;
    if (bind_anonset_context) {
        static constexpr char ANON_SET_DOMAIN[] = "BTX_SMILE2_ANON_SET_CTX_V2";
        pk_hash.Write(reinterpret_cast<const uint8_t*>(ANON_SET_DOMAIN), sizeof(ANON_SET_DOMAIN) - 1);
        uint8_t count_buf[4];
        WriteLE32(count_buf, static_cast<uint32_t>(anon_set.size()));
        pk_hash.Write(count_buf, sizeof(count_buf));
        WriteLE32(count_buf, static_cast<uint32_t>(KEY_ROWS));
        pk_hash.Write(count_buf, sizeof(count_buf));
        WriteLE32(count_buf, static_cast<uint32_t>(KEY_COLS));
        pk_hash.Write(count_buf, sizeof(count_buf));
    }
    for (size_t i = 0; i < anon_set.size(); ++i) {
        for (size_t j = 0; j < KEY_ROWS; ++j) {
            for (size_t c = 0; c < POLY_DEGREE; ++c) {
                uint32_t val = static_cast<uint32_t>(mod_q(anon_set[i].pk[j].coeffs[c]));
                uint8_t buf[4];
                WriteLE32(buf, val);
                pk_hash.Write(buf, sizeof(buf));
            }
        }
        if (!bind_anonset_context) continue;
        for (size_t row = 0; row < anon_set[i].A.size(); ++row) {
            for (size_t col = 0; col < anon_set[i].A[row].size(); ++col) {
                for (size_t c = 0; c < POLY_DEGREE; ++c) {
                    uint32_t val = static_cast<uint32_t>(mod_q(anon_set[i].A[row][col].coeffs[c]));
                    uint8_t buf[4];
                    WriteLE32(buf, val);
                    pk_hash.Write(buf, sizeof(buf));
                }
            }
        }
    }
    uint8_t pk_digest[32];
    pk_hash.Finalize(pk_digest);
    transcript.insert(transcript.end(), pk_digest, pk_digest + 32);
}

// Derive ρ challenges for framework proof
std::vector<SmilePoly> DeriveRhoChallenges(
    const std::vector<uint8_t>& transcript, size_t count)
{
    std::vector<SmilePoly> rhos(count);
    for (size_t i = 0; i < count; ++i) {
        rhos[i] = HashToPoly(transcript.data(), transcript.size(),
                             domainsep::RHO, static_cast<uint32_t>(i));
    }
    return rhos;
}

std::vector<SlotChallenge> DeriveSlotChallenges(
    const std::vector<uint8_t>& transcript,
    uint32_t domain_base,
    size_t count)
{
    const auto seed = TranscriptHash(transcript);
    std::vector<SlotChallenge> out(count);
    for (size_t i = 0; i < count; ++i) {
        out[i] = HashToSlotChallenge(seed.data(), seed.size(), domain_base + static_cast<uint32_t>(i));
    }
    return out;
}

SlotChallenge DeriveRecursionChallenge(
    const std::vector<uint8_t>& transcript,
    uint32_t domain)
{
    auto seed = TranscriptHash(transcript);
    return HashToSlotChallenge(seed.data(), 32, domain);
}

SmilePoly ApplySlotChallenge(
    const SmilePoly& poly,
    const std::array<int64_t, NUM_NTT_SLOTS>& challenge)
{
    const NttForm ntt_poly = NttForward(poly);
    NttForm weighted;
    for (size_t s = 0; s < NUM_NTT_SLOTS; ++s) {
        weighted.slots[s] = ntt_poly.slots[s].ScalarMul(challenge[s]);
    }
    SmilePoly out = NttInverse(weighted);
    out.Reduce();
    return out;
}

SmilePoly ApplySlotChallenge(
    const SmilePoly& poly,
    const SlotChallenge& challenge)
{
    const NttForm ntt_poly = NttForward(poly);
    NttForm weighted;
    for (size_t s = 0; s < NUM_NTT_SLOTS; ++s) {
        weighted.slots[s] = ntt_poly.slots[s].Mul(challenge[s], SLOT_ROOTS[s]);
    }
    SmilePoly out = NttInverse(weighted);
    out.Reduce();
    return out;
}

SmilePoly SumWeightedRows(
    const std::vector<SmilePoly>& rows,
    const std::vector<SlotChallenge>& challenges)
{
    SmilePoly out;
    const size_t limit = std::min(rows.size(), challenges.size());
    for (size_t i = 0; i < limit; ++i) {
        out += ApplySlotChallenge(rows[i], challenges[i]);
    }
    out.Reduce();
    return out;
}

std::vector<SmilePoly> CompressFirstRoundMatrix(
    const std::vector<std::vector<SmilePoly>>& p_rows,
    const std::vector<SlotChallenge>& gamma1,
    size_t cols_next)
{
    const size_t k = p_rows.size();
    std::vector<SmilePoly> out(cols_next);
    for (size_t c = 0; c < cols_next; ++c) {
        NttForm acc;
        for (size_t block = 0; block < NUM_NTT_SLOTS; ++block) {
            const size_t src = c * NUM_NTT_SLOTS + block;
            for (size_t row = 0; row < k && row < gamma1.size(); ++row) {
                if (src >= p_rows[row].size()) {
                    continue;
                }
                const NttForm ntt_src = NttForward(p_rows[row][src]);
                for (size_t row_slot = 0; row_slot < NUM_NTT_SLOTS; ++row_slot) {
                    acc.slots[block] = acc.slots[block].Add(
                        ntt_src.slots[row_slot].Mul(gamma1[row][row_slot], SLOT_ROOTS[row_slot]));
                }
            }
        }
        out[c] = NttInverse(acc);
        out[c].Reduce();
    }
    return out;
}

std::vector<SmilePoly> CompressRecursionMatrix(
    const std::vector<SmilePoly>& p_cols,
    const SlotChallenge& gamma,
    size_t cols_next)
{
    std::vector<SmilePoly> out(cols_next);
    for (size_t c = 0; c < cols_next; ++c) {
        NttForm acc;
        for (size_t block = 0; block < NUM_NTT_SLOTS; ++block) {
            const size_t src = c * NUM_NTT_SLOTS + block;
            if (src >= p_cols.size()) {
                continue;
            }
            const NttForm ntt_src = NttForward(p_cols[src]);
            for (size_t row_slot = 0; row_slot < NUM_NTT_SLOTS; ++row_slot) {
                acc.slots[block] = acc.slots[block].Add(
                    ntt_src.slots[row_slot].Mul(gamma[row_slot], SLOT_ROOTS[row_slot]));
            }
        }
        out[c] = NttInverse(acc);
        out[c].Reduce();
    }
    return out;
}

SmilePoly ApplyTransposeChallenge(
    const std::vector<SmilePoly>& p_cols,
    const SlotChallenge& gamma)
{
    NttForm out_ntt;
    for (size_t col = 0; col < p_cols.size() && col < NUM_NTT_SLOTS; ++col) {
        const NttForm ntt_col = NttForward(p_cols[col]);
        NttSlot slot_sum;
        for (size_t row = 0; row < NUM_NTT_SLOTS; ++row) {
            slot_sum = slot_sum.Add(ntt_col.slots[row].Mul(gamma[row], SLOT_ROOTS[row]));
        }
        out_ntt.slots[col] = slot_sum;
    }
    SmilePoly out = NttInverse(out_ntt);
    out.Reduce();
    return out;
}

SmilePoly EvaluateCompressedMatrix(
    const std::vector<SmilePoly>& p_cols,
    const std::vector<int64_t>& tensor)
{
    SmilePoly out;
    for (size_t c = 0; c < p_cols.size() && c < tensor.size(); ++c) {
        out += p_cols[c] * tensor[c];
    }
    out.Reduce();
    return out;
}

SmilePoly BuildRepeatedSlotPoly(const NttSlot& slot)
{
    NttForm repeated;
    for (size_t s = 0; s < NUM_NTT_SLOTS; ++s) {
        repeated.slots[s] = slot;
    }
    SmilePoly out = NttInverse(repeated);
    out.Reduce();
    return out;
}

SmilePoly BuildE1Poly()
{
    NttForm basis;
    basis.slots[0].coeffs[0] = 1;
    SmilePoly out = NttInverse(basis);
    out.Reduce();
    return out;
}

std::vector<SmilePoly> ComputeFinalPublicXValues(
    const std::vector<SmilePoly>& p_m_cols,
    const std::vector<SlotChallenge>& gamma_final)
{
    assert(gamma_final.size() >= 2);
    const size_t m = gamma_final.size() - 1;
    std::vector<SmilePoly> out(m);
    for (size_t i = 0; i + 1 < m; ++i) {
        out[i] = BuildRepeatedSlotPoly(gamma_final[i + 1][0]);
    }
    SmilePoly final_from_pm;
    if (!p_m_cols.empty()) {
        final_from_pm = ApplyTransposeChallenge(p_m_cols, gamma_final[0]);
    }
    final_from_pm += BuildRepeatedSlotPoly(gamma_final.back()[0]);
    final_from_pm.Reduce();
    out.back() = final_from_pm;
    return out;
}

SmilePoly ComputeFinalMembershipDelta(
    const std::vector<SmilePoly>& x_public,
    const std::vector<std::array<int64_t, NUM_NTT_SLOTS>>& v_decomp,
    const SmilePoly& x_m,
    const std::vector<SlotChallenge>& gamma_final)
{
    SmilePoly out;
    const size_t m = std::min(x_public.size(), v_decomp.size());
    for (size_t i = 0; i < m; ++i) {
        out += ApplySlotChallenge(x_public[i], v_decomp[i]);
    }
    out -= ApplySlotChallenge(x_m, gamma_final.front());

    SlotChallenge gamma_tail_sum{};
    for (size_t i = 1; i < gamma_final.size(); ++i) {
        for (size_t s = 0; s < NUM_NTT_SLOTS; ++s) {
            gamma_tail_sum[s] = gamma_tail_sum[s].Add(gamma_final[i][s]);
        }
    }
    out -= ApplySlotChallenge(BuildE1Poly(), gamma_tail_sum);
    out.Reduce();
    return out;
}

SmilePoly BuildConstantPoly(int64_t constant)
{
    SmilePoly out;
    out.coeffs[0] = mod_q(constant);
    return out;
}

SmilePolyVec ComputeB0Response(
    const BDLOPCommitmentKey& ck,
    const SmilePolyVec& witness)
{
    SmilePolyVec out(BDLOP_RAND_DIM_BASE);
    for (size_t row = 0; row < BDLOP_RAND_DIM_BASE; ++row) {
        for (size_t col = 0; col < ck.rand_dim(); ++col) {
            out[row] += NttMul(ck.B0[row][col], witness[col]);
        }
        out[row].Reduce();
    }
    return out;
}

std::vector<SmilePoly> ComputeMaskResponses(
    const BDLOPCommitmentKey& ck,
    const SmilePolyVec& y_mask)
{
    std::vector<SmilePoly> out(ck.n_msg);
    for (size_t j = 0; j < ck.n_msg; ++j) {
        SmilePoly acc;
        for (size_t col = 0; col < ck.rand_dim(); ++col) {
            acc += NttMul(ck.b[j][col], y_mask[col]);
        }
        acc.Reduce();
        out[j] = acc;
    }
    return out;
}

} // anonymous namespace

// --- SmileKeyPair ---

SmileKeyPair SmileKeyPair::Generate(const std::array<uint8_t, 32>& seed, uint64_t key_seed)
{
    SmileKeyPair kp;

    kp.pub.A.resize(KEY_ROWS);
    for (size_t i = 0; i < KEY_ROWS; ++i) {
        kp.pub.A[i].resize(KEY_COLS);
        for (size_t j = 0; j < KEY_COLS; ++j) {
            kp.pub.A[i][j] = HashToPoly(seed.data(), 32,
                domainsep::PUBLIC_ACCOUNT_MATRIX, static_cast<uint32_t>(i * KEY_COLS + j));
        }
    }

    {
        CSHA256 sk_hasher;
        sk_hasher.Write(seed.data(), 32);
        uint8_t ks_buf[8];
        WriteLE64(ks_buf, key_seed);
        sk_hasher.Write(ks_buf, 8);
        uint8_t sk_hash[32];
        sk_hasher.Finalize(sk_hash);
        uint64_t derived_seed = ReadLE64(sk_hash);
        if (derived_seed == 0) derived_seed = 1;
        kp.sec.s = SampleTernaryStrong(KEY_COLS, derived_seed);
    }

    kp.pub.pk.resize(KEY_ROWS);
    for (size_t i = 0; i < KEY_ROWS; ++i) {
        SmilePoly acc;
        for (size_t j = 0; j < KEY_COLS; ++j) {
            acc += NttMul(kp.pub.A[i][j], kp.sec.s[j]);
        }
        acc.Reduce();
        kp.pub.pk[i] = acc;
    }

    return kp;
}

SmileKeyPair SmileKeyPair::Generate(const std::array<uint8_t, 32>& seed,
                                    const std::array<uint8_t, 32>& key_seed)
{
    SmileKeyPair kp;

    kp.pub.A.resize(KEY_ROWS);
    for (size_t i = 0; i < KEY_ROWS; ++i) {
        kp.pub.A[i].resize(KEY_COLS);
        for (size_t j = 0; j < KEY_COLS; ++j) {
            kp.pub.A[i][j] = HashToPoly(seed.data(), 32,
                domainsep::PUBLIC_ACCOUNT_MATRIX, static_cast<uint32_t>(i * KEY_COLS + j));
        }
    }

    {
        CSHA256 sk_hasher;
        sk_hasher.Write(seed.data(), 32);
        sk_hasher.Write(key_seed.data(), key_seed.size());
        std::array<uint8_t, 32> sk_hash{};
        sk_hasher.Finalize(sk_hash.data());
        kp.sec.s = SampleTernaryStrong(KEY_COLS, sk_hash);
        memory_cleanse(sk_hash.data(), sk_hash.size());
    }

    kp.pub.pk.resize(KEY_ROWS);
    for (size_t i = 0; i < KEY_ROWS; ++i) {
        SmilePoly acc;
        for (size_t j = 0; j < KEY_COLS; ++j) {
            acc += NttMul(kp.pub.A[i][j], kp.sec.s[j]);
        }
        acc.Reduce();
        kp.pub.pk[i] = acc;
    }

    return kp;
}

// --- Matrix operations ---

std::vector<std::vector<NttSlot>> ComputeNextP(
    const std::vector<std::vector<NttSlot>>& P_j,
    const std::array<int64_t, NUM_NTT_SLOTS>& alpha,
    size_t cols_next)
{
    size_t rows = P_j.size();
    std::vector<std::vector<NttSlot>> P_next(rows, std::vector<NttSlot>(cols_next));

    for (size_t r = 0; r < rows; ++r) {
        for (size_t c = 0; c < cols_next; ++c) {
            NttSlot acc;
            for (size_t d = 0; d < NUM_NTT_SLOTS; ++d) {
                size_t src_col = d * cols_next + c;
                if (src_col < P_j[r].size()) {
                    acc = acc.Add(P_j[r][src_col].ScalarMul(alpha[d]));
                }
            }
            P_next[r][c] = acc;
        }
    }

    return P_next;
}

std::vector<NttSlot> MatVecProduct(
    const std::vector<std::vector<NttSlot>>& P,
    const std::vector<int64_t>& v)
{
    size_t rows = P.size();
    std::vector<NttSlot> result(rows);

    for (size_t r = 0; r < rows; ++r) {
        NttSlot acc;
        for (size_t c = 0; c < v.size(); ++c) {
            if (c < P[r].size()) {
                acc = acc.Add(P[r][c].ScalarMul(v[c]));
            }
        }
        result[r] = acc;
    }

    return result;
}

// --- Serialization size ---

size_t SmileMembershipProof::SerializedSize() const
{
    size_t size = 0;

    // t_0 compressed: MSIS_RANK polys × d coefficients × (log(q)-D) bits
    size_t t0_bits = MSIS_RANK * POLY_DEGREE * (32 - COMPRESS_D);
    size += (t0_bits + 7) / 8;

    // t_msg: n_msg polynomials × d × log(q) bits
    size_t tmsg_bits = commitment.t_msg.size() * POLY_DEGREE * 32;
    size += (tmsg_bits + 7) / 8;

    // h: 1 polynomial (first 4 coefficients are zero, not transmitted)
    size_t h_bits = (POLY_DEGREE - SLOT_DEGREE) * 32;
    size += (h_bits + 7) / 8;

    // z: bitpacked centered coefficients for the dense-C membership rewrite.
    size_t z_coeffs = z.size() * POLY_DEGREE;
    size_t z_bits = z_coeffs * MEMBERSHIP_Z_COEFF_BITS;
    size += (z_bits + 7) / 8;

    // z0: bitpacked centered coefficients for the dense-C membership rewrite.
    size_t z0_bits = z0.size() * POLY_DEGREE * MEMBERSHIP_Z0_COEFF_BITS;
    size += (z0_bits + 7) / 8;

    // omega: 1 polynomial × log(q) bits
    size += POLY_DEGREE * 4;

    // w0_vals: k polynomials for key relation check
    size += w0_vals.size() * POLY_DEGREE * 4;

    // Seeds: 2 × 32 bytes
    size += 64;

    return size;
}

// --- Prove Membership ---
// Implements Figure 7 of the SMILE paper with TWO-ROUND BDLOP commitment
// and Fiat-Shamir transform.
//
// Two-round commitment structure:
//   Round 1 (before c_0):
//     - Commit v_i selectors and w_0 = A·y_0
//     - t_0 = B_0·r, t_msg[0..m+k-1] from selectors and w_0
//     - Derive c_0 from Round 1 transcript
//   Between rounds:
//     - z_0 = y_0 + c_0·s
//     - Build P_1 from c_0-scaled keys (Eq. 31)
//     - Run recursion on c_0-scaled keys to get y_j
//     - Compute g (cancellation) and h = g + y_sum
//   Round 2 (after c_0):
//     - Extend commitment with g, ψ, x intermediates using SAME r
//     - t_msg[m+k..n_msg-1] computed with same r
//   After Round 2:
//     - Derive ρ, final challenge c, compute z, f_j, ω

SmileMembershipProof ProveMembershipWithRetryBudget(
    const std::vector<SmilePublicKey>& anon_set,
    size_t secret_index,
    const SmileSecretKey& sk,
    uint64_t rng_seed,
    size_t retries_remaining,
    bool bind_anonset_context,
    size_t rejected_attempts_so_far,
    size_t* accepted_attempt_out)
{
    size_t N = anon_set.size();
    size_t m = ComputeRecursionLevels(N);
    size_t N_padded = PadToLPower(N);
    size_t k = KEY_ROWS;
    const size_t first_x_slot = ComputeFirstXSlot(m);
    const size_t g_slot = ComputeGSlot(m);
    const size_t psi_slot = ComputePsiSlot(m);

    size_t retries_left = retries_remaining;
    size_t rejected_attempts = rejected_attempts_so_far;
    uint64_t attempt_seed = rng_seed;

retry_attempt:
    {
    // Keep rejection retries iterative so a hostile seed cannot exhaust the
    // retry budget by exhausting the stack first.
    DetRng rng(attempt_seed);

    // ------------------------------------------------------------------
    // Step 1: Decompose index into m one-hot vectors
    // ------------------------------------------------------------------
    auto v_decomp = DecomposeIndex(secret_index, m);

    // Derive initial transcript from public data
    std::vector<uint8_t> transcript;
    HashAnonSet(transcript, anon_set, bind_anonset_context);

    const auto& A = anon_set[0].A;

    // ------------------------------------------------------------------
    // Step 2: Generate commitment key and sample randomness BEFORE Round 1
    // ------------------------------------------------------------------
    size_t n_msg = ComputeNumMsg(m);
    auto ck_seed = TranscriptHash(transcript);
    auto ck = BDLOPCommitmentKey::Generate(ck_seed, n_msg);

    // Sample commitment randomness r (used for BOTH rounds)
    auto r_com = SampleTernaryStrong(ck.rand_dim(), DrawStrongTernarySeed(rng));

    // Sample masking vectors
    SmilePolyVec y_mask(ck.rand_dim());
    for (auto& yi : y_mask) {
        yi = rng.GaussianPoly(MEMBERSHIP_SIGMA_MASK);
    }

    SmilePolyVec y0_mask(KEY_COLS);
    for (auto& yi : y0_mask) {
        yi = rng.GaussianPoly(MEMBERSHIP_SIGMA_KEY);
    }

    // Figure 7 / Eq. 39 binds w = B0 * y into the first Fiat-Shamir challenge.
    const SmilePolyVec w_mask = ComputeB0Response(ck, y_mask);

    // ------------------------------------------------------------------
    // Step 3: Compute w_0 = A·y_0
    // ------------------------------------------------------------------
    std::vector<SmilePoly> w0(k);
    for (size_t i = 0; i < k; ++i) {
        SmilePoly acc;
        for (size_t j = 0; j < KEY_COLS; ++j) {
            acc += NttMul(A[i][j], y0_mask[j]);
        }
        acc.Reduce();
        w0[i] = acc;
    }

    SmilePoly g;
    for (size_t i = SLOT_DEGREE; i < POLY_DEGREE; ++i) {
        g.coeffs[i] = rng.UniformModQ();
    }

    // ==================================================================
    // ROUND 1: Commit v_i selectors, w_0, and g
    // ==================================================================

    // Compute t_0 = B_0·r (computed once, does not change)
    BDLOPCommitment com;
    com.t0.resize(BDLOP_RAND_DIM_BASE);
    for (size_t i = 0; i < BDLOP_RAND_DIM_BASE; ++i) {
        SmilePoly acc;
        for (size_t j = 0; j < ck.rand_dim(); ++j) {
            acc += NttMul(ck.B0[i][j], r_com[j]);
        }
        acc.Reduce();
        com.t0[i] = acc;
    }

    // Prepare Round 1 messages and compute t_msg for the initial Figure 7
    // commitment surface.
    com.t_msg.resize(n_msg);

    std::vector<SmilePoly> messages(n_msg);

    // Selectors v_i (slots 0..m-1)
    for (size_t i = 0; i < m; ++i) {
        NttForm v_ntt;
        for (size_t j = 0; j < NUM_NTT_SLOTS; ++j) {
            v_ntt.slots[j].coeffs[0] = v_decomp[i][j];
        }
        messages[i] = NttInverse(v_ntt);
        messages[i].Reduce();
    }

    // w_0 values (slots m..m+k-1)
    for (size_t i = 0; i < k; ++i) {
        messages[m + i] = w0[i];
    }

    // g polynomial (slot k+2m-1): sampled before c0 with zero low coefficients.
    messages[g_slot] = g;

    // Compute t_msg for Round 1 slots: t_i = ⟨b_i, r⟩ + message_i
    for (size_t i = 0; i < m + k; ++i) {
        SmilePoly br;
        for (size_t col = 0; col < ck.rand_dim(); ++col) {
            br += NttMul(ck.b[i][col], r_com[col]);
        }
        br.Reduce();
        com.t_msg[i] = br + messages[i];
        com.t_msg[i].Reduce();
    }
    {
        SmilePoly br;
        for (size_t col = 0; col < ck.rand_dim(); ++col) {
            br += NttMul(ck.b[g_slot][col], r_com[col]);
        }
        br.Reduce();
        com.t_msg[g_slot] = br + messages[g_slot];
        com.t_msg[g_slot].Reduce();
    }

    // Add Round 1 commitment to Fiat-Shamir transcript
    for (const auto& t : com.t0) {
        AppendPoly(transcript, t);
    }
    for (size_t i = 0; i < m + k; ++i) {
        AppendPoly(transcript, com.t_msg[i]);
    }
    AppendPoly(transcript, com.t_msg[g_slot]);
    for (const auto& wi : w_mask) {
        AppendPoly(transcript, wi);
    }
    AppendUint32(transcript, static_cast<uint32_t>(m));

    // Derive c_0 from Round 1 transcript
    auto seed_c0 = TranscriptHash(transcript);
    SmilePoly c0_chal = HashToTernaryChallenge(seed_c0.data(), 32, domainsep::MEMBERSHIP_C0);

    // ==================================================================
    // BETWEEN ROUNDS: z_0, recursion on c_0-scaled keys, g, h
    // ==================================================================

    // z_0 = y_0 + c_0 · s  (with rejection sampling, Figure 10)
    SmilePolyVec z0(KEY_COLS);
    {
        SmilePolyVec c0s(KEY_COLS);
        for (size_t j = 0; j < KEY_COLS; ++j) {
            z0[j] = y0_mask[j] + NttMul(c0_chal, sk.s[j]);
            z0[j].Reduce();
            c0s[j] = NttMul(c0_chal, sk.s[j]);
            c0s[j].Reduce();
        }
        if (!RejectionSample(z0, c0s, MEMBERSHIP_SIGMA_KEY, rng, RejectionMode::Rej0)) {
            if (retries_left == 0) return {};
            --retries_left;
            ++rejected_attempts;
            ++attempt_seed;
            goto retry_attempt;
        }
    }

    // Figure 7 derives the recursive gamma challenges only after z_0 is sent.
    // Bind z_0 itself into the Fiat-Shamir state before any recursive
    // challenges are derived.
    for (const auto& zi : z0) {
        AppendPoly(transcript, zi);
    }

    {
        for (size_t i = 0; i < k; ++i) {
            SmilePoly az0_i;
            for (size_t j = 0; j < KEY_COLS; ++j) {
                az0_i += NttMul(A[i][j], z0[j]);
            }
            az0_i.Reduce();
            SmilePoly adjusted_commit = com.t_msg[m + i] - az0_i;
            adjusted_commit.Reduce();
            AppendPoly(transcript, adjusted_commit);
        }
    }

    // Build the Equation 31 public matrix/object for the large-ring path.
    // The paper uses the effective key object w~ = NTT(w0 - A*z0) = -c0*pk,
    // not +c0*pk. Keep the recursion sign-consistent with that object.
    std::vector<std::vector<SmilePoly>> p1_rows(k);
    std::vector<SmilePoly> x1_rows(k);
    for (size_t i = 0; i < k; ++i) {
        p1_rows[i].resize(N_padded);
        for (size_t j = 0; j < N; ++j) {
            p1_rows[i][j] = NttMul(c0_chal, anon_set[j].pk[i]);
            SmilePoly neg_pk;
            neg_pk -= p1_rows[i][j];
            neg_pk.Reduce();
            p1_rows[i][j] = neg_pk;
            p1_rows[i][j].Reduce();
        }
        SmilePoly az0_i;
        for (size_t j = 0; j < KEY_COLS; ++j) {
            az0_i += NttMul(A[i][j], z0[j]);
        }
        az0_i.Reduce();
        x1_rows[i] = w0[i] - az0_i;
        x1_rows[i].Reduce();
    }
    // Run the membership recursion on the post-round-one compressed x-state.
    std::vector<SmilePoly> y_polys;
    std::vector<SlotChallenge> gamma1_rows;
    std::vector<SlotChallenge> gamma_mid;
    std::vector<SlotChallenge> gamma_final;
    std::vector<SmilePoly> final_public_x;

    // ==================================================================
    // ROUND 2: Extend commitment with ψ and x intermediates
    // ==================================================================
    // All use the SAME r sampled before Round 1.

    if (m == 1) {
        gamma1_rows = DeriveSlotChallenges(transcript, smile2::domainsep::MEMBERSHIP_GAMMA1_ROWS, k);
        const size_t cols_curr = N_padded / NUM_NTT_SLOTS;
        std::vector<SmilePoly> p_curr = CompressFirstRoundMatrix(p1_rows, gamma1_rows, cols_curr);
        assert(cols_curr == 1);
        SmilePoly x_curr = p_curr.front();
        x_curr.Reduce();

        SmilePoly y1 = ApplySlotChallenge(x_curr, v_decomp[0]) - SumWeightedRows(x1_rows, gamma1_rows);
        y1.Reduce();
        y_polys.push_back(y1);

        messages[first_x_slot] = x_curr;
        SmilePoly br;
        for (size_t col = 0; col < ck.rand_dim(); ++col) {
            br += NttMul(ck.b[first_x_slot][col], r_com[col]);
        }
        br.Reduce();
        com.t_msg[first_x_slot] = br + messages[first_x_slot];
        com.t_msg[first_x_slot].Reduce();
        AppendPoly(transcript, com.t_msg[first_x_slot]);
    } else {
        gamma1_rows = DeriveSlotChallenges(transcript, smile2::domainsep::MEMBERSHIP_GAMMA1_ROWS, k);
        size_t cols_curr = N_padded / NUM_NTT_SLOTS;
        std::vector<SmilePoly> p_curr = CompressFirstRoundMatrix(p1_rows, gamma1_rows, cols_curr);

        std::vector<std::array<int64_t, NUM_NTT_SLOTS>> sub_vecs(
            v_decomp.begin() + 1,
            v_decomp.end());
        SmilePoly x_curr = EvaluateCompressedMatrix(p_curr, TensorProduct(sub_vecs));
        SmilePoly y1 = ApplySlotChallenge(x_curr, v_decomp[0]) - SumWeightedRows(x1_rows, gamma1_rows);
        y1.Reduce();
        y_polys.push_back(y1);

        // Commit the real post-compression x_2, then recurse on the compressed state.
        {
            const size_t slot = first_x_slot;
            messages[slot] = x_curr;
            SmilePoly br;
            for (size_t col = 0; col < ck.rand_dim(); ++col) {
                br += NttMul(ck.b[slot][col], r_com[col]);
            }
            br.Reduce();
            com.t_msg[slot] = br + messages[slot];
            com.t_msg[slot].Reduce();
            AppendPoly(transcript, com.t_msg[slot]);
        }

        for (size_t level = 2; level < m; ++level) {
            const auto gamma_j = DeriveRecursionChallenge(
                transcript, smile2::domainsep::MembershipRecursionGamma(level));
            gamma_mid.push_back(gamma_j);
            const size_t cols_next = cols_curr / NUM_NTT_SLOTS;
            std::vector<SmilePoly> p_next = CompressRecursionMatrix(p_curr, gamma_j, cols_next);

            std::vector<std::array<int64_t, NUM_NTT_SLOTS>> tail_vecs(
                v_decomp.begin() + level,
                v_decomp.end());
            SmilePoly x_next = EvaluateCompressedMatrix(p_next, TensorProduct(tail_vecs));
            SmilePoly y_j = ApplySlotChallenge(x_next, v_decomp[level - 1]) -
                            ApplySlotChallenge(x_curr, gamma_j);
            y_j.Reduce();
            y_polys.push_back(y_j);

            const size_t slot = first_x_slot + (level - 1);
            messages[slot] = x_next;
            SmilePoly br;
            for (size_t col = 0; col < ck.rand_dim(); ++col) {
                br += NttMul(ck.b[slot][col], r_com[col]);
            }
            br.Reduce();
            com.t_msg[slot] = br + messages[slot];
            com.t_msg[slot].Reduce();
            AppendPoly(transcript, com.t_msg[slot]);

            p_curr = std::move(p_next);
            x_curr = x_next;
            cols_curr = cols_next;
        }

        gamma_final = DeriveSlotChallenges(transcript, smile2::domainsep::MEMBERSHIP_FINAL_GAMMA, m + 1);
        final_public_x = ComputeFinalPublicXValues(p_curr, gamma_final);
        SmilePoly y_m = ComputeFinalMembershipDelta(final_public_x, v_decomp, x_curr, gamma_final);
        y_m.Reduce();
        y_polys.push_back(y_m);
    }

    // Compute y_sum and the final h = g + y_1 + ... + y_m.
    SmilePoly y_sum;
    for (const auto& yp : y_polys) {
        y_sum += yp;
    }
    y_sum.Reduce();

    // In the paper, g is committed before c0 and already has zero low
    // coefficients; h inherits that low-coefficient structure from the true
    // recursion identities rather than from adaptive cancellation.
    SmilePoly h = g + y_sum;
    h.Reduce();

    // ==================================================================
    // AFTER ROUND 2: derive α, build ψ and ω, then derive the final c
    // ==================================================================

    SmilePoly omega;
    {
        AppendPoly(transcript, h);
        const auto alpha_chals = DeriveRhoChallenges(transcript, m + 1);
        const auto by = ComputeMaskResponses(ck, y_mask);
        const SmilePoly one_poly = BuildConstantPoly(1);

        SmilePoly omega_sm;
        SmilePoly psi_sm;

        {
            SmilePoly omega1 = NttMul(by[0], by[first_x_slot]);
            omega1.Reduce();
            omega_sm += omega1;

            SmilePoly psi1 = SumWeightedRows(
                std::vector<SmilePoly>(by.begin() + m, by.begin() + m + k), gamma1_rows);
            psi1 -= NttMul(by[0], messages[first_x_slot]);
            psi1 -= NttMul(by[first_x_slot], messages[0]);
            psi1.Reduce();
            psi_sm += psi1;
        }

        for (size_t level = 2; level < m; ++level) {
            const size_t x_prev_slot = first_x_slot + (level - 2);
            const size_t x_slot = first_x_slot + (level - 1);

            SmilePoly omega_j = NttMul(by[level - 1], by[x_slot]);
            omega_j.Reduce();
            omega_sm += omega_j;

            SmilePoly psi_j = ApplySlotChallenge(by[x_prev_slot], gamma_mid[level - 2]);
            psi_j -= NttMul(by[level - 1], messages[x_slot]);
            psi_j -= NttMul(by[x_slot], messages[level - 1]);
            psi_j.Reduce();
            psi_sm += psi_j;
        }

        if (m > 1) {
            const size_t last_x_slot = first_x_slot + (m - 2);
            SmilePoly psi_m;
            for (size_t i = 0; i < m && i < final_public_x.size(); ++i) {
                psi_m -= NttMul(final_public_x[i], by[i]);
            }
            psi_m += ApplySlotChallenge(by[last_x_slot], gamma_final.front());

            SlotChallenge gamma_tail_sum{};
            for (size_t i = 1; i < gamma_final.size(); ++i) {
                for (size_t s = 0; s < NUM_NTT_SLOTS; ++s) {
                    gamma_tail_sum[s] = gamma_tail_sum[s].Add(gamma_final[i][s]);
                }
            }
            psi_m -= ApplySlotChallenge(BuildE1Poly(), gamma_tail_sum);
            psi_m.Reduce();
            psi_sm += psi_m;
        }

        psi_sm -= by[g_slot];
        psi_sm.Reduce();
        omega_sm.Reduce();

        SmilePoly omega_bin;
        SmilePoly psi_bin;
        for (size_t i = 0; i < m; ++i) {
            SmilePoly omega_i = NttMul(by[i], by[i]);
            omega_i = NttMul(alpha_chals[i + 1], omega_i);
            omega_i.Reduce();
            omega_bin += omega_i;

            SmilePoly selector_term = one_poly - (messages[i] * 2);
            selector_term.Reduce();
            SmilePoly psi_i = NttMul(by[i], selector_term);
            psi_i = NttMul(alpha_chals[i + 1], psi_i);
            psi_i.Reduce();
            psi_bin += psi_i;
        }
        omega_bin.Reduce();
        psi_bin.Reduce();

        messages[psi_slot] = NttMul(alpha_chals[0], psi_sm) + psi_bin;
        messages[psi_slot].Reduce();
        omega = by[psi_slot] + NttMul(alpha_chals[0], omega_sm) + omega_bin;
        omega.Reduce();

        SmilePoly br;
        for (size_t col = 0; col < ck.rand_dim(); ++col) {
            br += NttMul(ck.b[psi_slot][col], r_com[col]);
        }
        br.Reduce();
        com.t_msg[psi_slot] = br + messages[psi_slot];
        com.t_msg[psi_slot].Reduce();
        AppendPoly(transcript, com.t_msg[psi_slot]);
        AppendPoly(transcript, omega);
    }

    auto seed_c = TranscriptHash(transcript);
    SmilePoly c_chal = HashToTernaryChallenge(seed_c.data(), 32, domainsep::MEMBERSHIP_C);

    // Compute z = y + c·r  (with rejection sampling, Figure 10)
    SmilePolyVec z(ck.rand_dim());
    {
        SmilePolyVec cr(ck.rand_dim());
        for (size_t j = 0; j < ck.rand_dim(); ++j) {
            z[j] = y_mask[j] + NttMul(c_chal, r_com[j]);
            z[j].Reduce();
            cr[j] = NttMul(c_chal, r_com[j]);
            cr[j].Reduce();
        }
        if (!RejectionSample(z, cr, MEMBERSHIP_SIGMA_MASK, rng, RejectionMode::Rej1)) {
            if (retries_left == 0) return {};
            --retries_left;
            ++rejected_attempts;
            ++attempt_seed;
            goto retry_attempt;
        }
    }

    omega.Reduce();

    // Build proof
    SmileMembershipProof proof;
    proof.commitment = com;
    proof.h = h;
    proof.z = z;
    proof.z0 = z0;
    proof.omega = omega;
    proof.seed_c0 = seed_c0;
    proof.seed_c = seed_c;
    if (accepted_attempt_out != nullptr) {
        *accepted_attempt_out = rejected_attempts;
    }

    return proof;
    }
}

SmileMembershipProof ProveMembership(
    const std::vector<SmilePublicKey>& anon_set,
    size_t secret_index,
    const SmileSecretKey& sk,
    uint64_t rng_seed,
    bool bind_anonset_context)
{
    size_t accepted_attempt{MAX_MEMBERSHIP_REJECTION_RETRIES};
    auto proof = ProveMembershipWithRetryBudget(anon_set,
                                                secret_index,
                                                sk,
                                                rng_seed,
                                                MAX_MEMBERSHIP_REJECTION_RETRIES,
                                                bind_anonset_context,
                                                /*rejected_attempts_so_far=*/0,
                                                &accepted_attempt);
    if (!proof.commitment.t0.empty()) {
        RunMembershipPaddingIterations(
            anon_set, sk, rng_seed, accepted_attempt, bind_anonset_context, proof);
    }
    return proof;
}

size_t GetMembershipRejectionRetryBudget()
{
    return MAX_MEMBERSHIP_REJECTION_RETRIES;
}

size_t GetMembershipTimingPaddingAttemptLimit()
{
    return MAX_MEMBERSHIP_TIMING_PADDING_ATTEMPTS;
}

// --- Verify Membership ---
// Implements SMILE paper Figure 9 verification equations (all 15 checks).
//
// The verification is structured as:
//   Lines 01-02: Norm bounds on z_0, z
//   Line 03:     BDLOP opening check B_0·z = w + c·t_0
//   Line 04:     Adjusted key commitments t'_{m+i} = t_{m+i} - A·z_0
//   Line 05:     Compute f_j = ⟨b_j, z⟩ - c·t_j
//   Lines 06-09: Compute intermediates for F_j
//   Lines 10-12: Framework equations F_1, ..., F_m
//   Line 13:     Quadratic check: ρ_0·ΣF_j - c·f_{k+2m} - c²·h + Σρ_i(f_i²+c·f_i) + f_{k+2m+1} = ω
//   Lines 14-15: h first d/l coefficients zero

bool VerifyMembership(
    const std::vector<SmilePublicKey>& anon_set,
    const SmileMembershipProof& proof,
    bool bind_anonset_context)
{
    size_t N = anon_set.size();
    if (N == 0 || N > ANON_SET_SIZE) return false;
    size_t m = ComputeRecursionLevels(N);
    size_t N_padded = PadToLPower(N);
    if (m == 0 || N_padded == 0) return false;
    size_t k = KEY_ROWS;
    const size_t first_x_slot = ComputeFirstXSlot(m);
    const size_t g_slot = ComputeGSlot(m);
    const size_t psi_slot = ComputePsiSlot(m);

    // (Fig 9, lines 14-15): Check h has first d/l = 4 coefficients all zero
    SmilePoly h_check = proof.h;
    h_check.Reduce();
    for (size_t i = 0; i < SLOT_DEGREE; ++i) {
        if (h_check.coeffs[i] != 0) return false;
    }

    // Structural checks
    size_t n_msg = ComputeNumMsg(m);
    if (proof.z0.size() != KEY_COLS) return false;
    if (proof.commitment.t_msg.size() != n_msg) return false;

    // Reconstruct Fiat-Shamir transcript (must match prover exactly)
    std::vector<uint8_t> transcript;
    HashAnonSet(transcript, anon_set, bind_anonset_context);

    auto ck_seed = TranscriptHash(transcript);
    auto ck = BDLOPCommitmentKey::Generate(ck_seed, n_msg);

    if (proof.z.size() != ck.rand_dim()) return false;

    // (Fig 9, lines 01-02): Norm bound checks on z_0 and z
    // ||z_0||_2 < β_0 = s_0 * sqrt(2 * KEY_COLS * POLY_DEGREE)
    {
        int64_t half_q = Q / 2;
        // Check z_0 norm bound
        __int128 z0_norm_sq = 0;
        for (size_t j = 0; j < proof.z0.size(); ++j) {
            for (size_t c = 0; c < POLY_DEGREE; ++c) {
                int64_t val = mod_q(proof.z0[j].coeffs[c]);
                if (val > half_q) val -= Q;
                z0_norm_sq += static_cast<__int128>(val) * val;
            }
        }
        // β_0^2 = s_0^2 * 2 * KEY_COLS * POLY_DEGREE
        __int128 beta0_sq =
            static_cast<__int128>(MEMBERSHIP_SIGMA_KEY) * MEMBERSHIP_SIGMA_KEY *
            2 * KEY_COLS * POLY_DEGREE;
        if (z0_norm_sq >= beta0_sq) return false;

        // Check z norm bound
        // ||z||_2 < β = s * sqrt(2 * rand_dim * POLY_DEGREE)
        __int128 z_norm_sq = 0;
        for (size_t j = 0; j < proof.z.size(); ++j) {
            for (size_t c = 0; c < POLY_DEGREE; ++c) {
                int64_t val = mod_q(proof.z[j].coeffs[c]);
                if (val > half_q) val -= Q;
                z_norm_sq += static_cast<__int128>(val) * val;
            }
        }
        __int128 beta_sq =
            static_cast<__int128>(MEMBERSHIP_SIGMA_MASK) * MEMBERSHIP_SIGMA_MASK *
            2 * ck.rand_dim() * POLY_DEGREE;
        if (z_norm_sq >= beta_sq) return false;
    }

    // Add the first Fiat-Shamir surface to the transcript:
    // (~t0, t1..tm+k, tk+2m, w, m) from Figure 7 / Eq. 39.
    for (const auto& t : proof.commitment.t0) {
        AppendPoly(transcript, t);
    }
    for (size_t i = 0; i < m + k && i < proof.commitment.t_msg.size(); ++i) {
        AppendPoly(transcript, proof.commitment.t_msg[i]);
    }
    if (g_slot >= proof.commitment.t_msg.size()) return false;
    AppendPoly(transcript, proof.commitment.t_msg[g_slot]);

    // Recover w = B0 * y from Line 03: B0 * z = w + c * t0.
    const SmilePoly c_chal_from_seed =
        HashToTernaryChallenge(proof.seed_c.data(), 32, domainsep::MEMBERSHIP_C);
    const SmilePolyVec b0z = ComputeB0Response(ck, proof.z);
    for (size_t row = 0; row < BDLOP_RAND_DIM_BASE; ++row) {
        SmilePoly recovered_w = b0z[row] - NttMul(c_chal_from_seed, proof.commitment.t0[row]);
        recovered_w.Reduce();
        AppendPoly(transcript, recovered_w);
    }
    AppendUint32(transcript, static_cast<uint32_t>(m));

    // Verify seed_c0 matches Fiat-Shamir derivation
    auto seed_c0_check = TranscriptHash(transcript);
    if (seed_c0_check != proof.seed_c0) return false;

    // Derive c_0 challenge polynomial
    SmilePoly c0_chal = HashToTernaryChallenge(proof.seed_c0.data(), 32, domainsep::MEMBERSHIP_C0);

    for (const auto& zi : proof.z0) {
        AppendPoly(transcript, zi);
    }

    std::vector<SlotChallenge> gamma1_rows;
    std::vector<SlotChallenge> gamma_mid;
    std::vector<SlotChallenge> gamma_final;
    std::vector<SmilePoly> final_public_x;
    if (!proof.w0_vals.empty()) return false;

    const auto& A_early = anon_set[0].A;
    for (size_t i = 0; i < k; ++i) {
        SmilePoly az0_i;
        for (size_t j = 0; j < KEY_COLS; ++j) {
            az0_i += NttMul(A_early[i][j], proof.z0[j]);
        }
        az0_i.Reduce();
        SmilePoly adjusted_commit = proof.commitment.t_msg[m + i] - az0_i;
        adjusted_commit.Reduce();
        AppendPoly(transcript, adjusted_commit);
    }

    std::vector<std::vector<SmilePoly>> p1_rows(k);
    for (size_t i = 0; i < k; ++i) {
        p1_rows[i].resize(N_padded);
        for (size_t j = 0; j < N; ++j) {
            p1_rows[i][j] = NttMul(c0_chal, anon_set[j].pk[i]);
            SmilePoly neg_pk;
            neg_pk -= p1_rows[i][j];
            neg_pk.Reduce();
            p1_rows[i][j] = neg_pk;
            p1_rows[i][j].Reduce();
        }
    }

    gamma1_rows = DeriveSlotChallenges(transcript, smile2::domainsep::MEMBERSHIP_GAMMA1_ROWS, k);

    if (first_x_slot >= proof.commitment.t_msg.size()) return false;
    AppendPoly(transcript, proof.commitment.t_msg[first_x_slot]);

    size_t cols_curr = N_padded / NUM_NTT_SLOTS;
    std::vector<SmilePoly> p_curr = CompressFirstRoundMatrix(p1_rows, gamma1_rows, cols_curr);

    if (m > 1) {
        for (size_t level = 2; level < m; ++level) {
            const auto gamma_j = DeriveRecursionChallenge(
                transcript, smile2::domainsep::MembershipRecursionGamma(level));
            gamma_mid.push_back(gamma_j);

            const size_t cols_next = cols_curr / NUM_NTT_SLOTS;
            p_curr = CompressRecursionMatrix(p_curr, gamma_j, cols_next);
            cols_curr = cols_next;

            const size_t slot = first_x_slot + (level - 1);
            if (slot >= proof.commitment.t_msg.size()) return false;
            AppendPoly(transcript, proof.commitment.t_msg[slot]);
        }

        gamma_final = DeriveSlotChallenges(transcript, smile2::domainsep::MEMBERSHIP_FINAL_GAMMA, m + 1);
        final_public_x = ComputeFinalPublicXValues(p_curr, gamma_final);
        if (final_public_x.size() != m) return false;
    }

    if (g_slot >= proof.commitment.t_msg.size() || psi_slot >= proof.commitment.t_msg.size()) return false;

    AppendPoly(transcript, proof.h);
    std::vector<SmilePoly> alpha_chals = DeriveRhoChallenges(transcript, m + 1);
    AppendPoly(transcript, proof.commitment.t_msg[psi_slot]);
    AppendPoly(transcript, proof.omega);
    auto seed_c_check = TranscriptHash(transcript);
    if (seed_c_check != proof.seed_c) return false;

    SmilePoly c_chal = HashToTernaryChallenge(proof.seed_c.data(), 32, domainsep::MEMBERSHIP_C);
    const auto& A = anon_set[0].A;

    // (Fig 9, line 03): BDLOP opening check B_0·z = w + c·t_0
    // We compute w_i = B_0[i]·z - c·t_0[i]. These are the implicit w values.
    // The prover sent w = B_0·y in the commitment phase; here we verify
    // that z is consistent with the commitment by checking the structure.
    SmilePolyVec w_vals(BDLOP_RAND_DIM_BASE);
    for (size_t i = 0; i < BDLOP_RAND_DIM_BASE && i < proof.commitment.t0.size(); ++i) {
        SmilePoly b0z;
        for (size_t j = 0; j < ck.rand_dim(); ++j) {
            b0z += NttMul(ck.B0[i][j], proof.z[j]);
        }
        b0z.Reduce();
        // w_i = B_0[i]·z - c·t_0[i]
        SmilePoly ct0 = NttMul(c_chal, proof.commitment.t0[i]);
        ct0.Reduce();
        w_vals[i] = b0z - ct0;
        w_vals[i].Reduce();
    }

    // (Fig 9, line 05): Compute f_j = ⟨b_j, z⟩ - c·t_j for all message slots.
    std::vector<SmilePoly> f(n_msg);
    for (size_t j = 0; j < n_msg; ++j) {
        SmilePoly bz;
        for (size_t col = 0; col < ck.rand_dim(); ++col) {
            bz += NttMul(ck.b[j][col], proof.z[col]);
        }
        bz.Reduce();
        SmilePoly ct = NttMul(c_chal, proof.commitment.t_msg[j]);
        ct.Reduce();
        f[j] = bz - ct;
        f[j].Reduce();
    }

    // (Fig 9, line 04): Key relation — adjust the w_0 commitment slots.
    // t'_{m+i} = t_{m+i} - A[i]·z_0
    // f'_{m+i} = f_{m+i} + c·A[i]·z_0
    for (size_t i = 0; i < k; ++i) {
        SmilePoly az0_i;
        for (size_t j = 0; j < KEY_COLS; ++j) {
            az0_i += NttMul(A[i][j], proof.z0[j]);
        }
        az0_i.Reduce();
        // Adjust f for w_0 slots: f'_{m+i} = f_{m+i} + c·A[i]·z_0
        f[m + i] = f[m + i] + NttMul(c_chal, az0_i);
        f[m + i].Reduce();
    }

    // (Fig 9, line 13): Combined verification equation.

    // Binary constraint: Σ_{i=1}^{m} α_i · (f_i² + c·f_i)
    SmilePoly bin_check;
    for (size_t i = 0; i < m; ++i) {
        SmilePoly fi_sq = NttMul(f[i], f[i]);
        SmilePoly c_fi = NttMul(c_chal, f[i]);
        SmilePoly term = fi_sq + c_fi;
        bin_check += NttMul(alpha_chals[i + 1], term);
    }
    bin_check.Reduce();

    // c · f_{g_slot}
    SmilePoly c_fg;
    if (g_slot < n_msg) {
        c_fg = NttMul(c_chal, f[g_slot]);
        c_fg.Reduce();
    }

    // c² · h
    SmilePoly c_sq = NttMul(c_chal, c_chal);
    SmilePoly c2h = NttMul(c_sq, proof.h);
    c2h.Reduce();

    // f_{psi_slot}
    SmilePoly f_psi;
    if (psi_slot < n_msg) {
        f_psi = f[psi_slot];
        f_psi.Reduce();
    }

    SmilePoly framework_sum;

    framework_sum += NttMul(f[0], f[first_x_slot]);
    framework_sum += NttMul(c_chal, SumWeightedRows(
        std::vector<SmilePoly>(f.begin() + m, f.begin() + m + k), gamma1_rows));

    for (size_t level = 2; level < m; ++level) {
        const size_t x_prev_slot = first_x_slot + (level - 2);
        const size_t x_slot = first_x_slot + (level - 1);
        framework_sum += NttMul(f[level - 1], f[x_slot]);
        framework_sum += NttMul(c_chal, ApplySlotChallenge(f[x_prev_slot], gamma_mid[level - 2]));
    }

    if (m > 1) {
        SlotChallenge gamma_tail_sum{};
        for (size_t i = 1; i < gamma_final.size(); ++i) {
            for (size_t s = 0; s < NUM_NTT_SLOTS; ++s) {
                gamma_tail_sum[s] = gamma_tail_sum[s].Add(gamma_final[i][s]);
            }
        }

        SmilePoly final_framework;
        for (size_t i = 0; i < m && i < final_public_x.size(); ++i) {
            final_framework -= NttMul(final_public_x[i], f[i]);
        }
        const size_t last_x_slot = first_x_slot + (m - 2);
        final_framework += ApplySlotChallenge(f[last_x_slot], gamma_final.front());
        const SmilePoly e1_tail = ApplySlotChallenge(BuildE1Poly(), gamma_tail_sum);
        final_framework -= e1_tail;
        final_framework = NttMul(c_chal, final_framework) - NttMul(c_sq, e1_tail);
        final_framework.Reduce();
        framework_sum += final_framework;
    }
    framework_sum.Reduce();

    SmilePoly bracket = framework_sum - c_fg - c2h;
    bracket.Reduce();
    SmilePoly lhs = NttMul(alpha_chals[0], bracket) + bin_check + f_psi;
    lhs.Reduce();

    SmilePoly omega_check = proof.omega;
    omega_check.Reduce();

    if (lhs != omega_check) return false;

    return true;
}

} // namespace smile2

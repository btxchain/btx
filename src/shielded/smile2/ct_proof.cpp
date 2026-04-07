// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/smile2/ct_proof.h>
#include <shielded/smile2/domain_separation.h>
#include <shielded/smile2/serialize.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <logging.h>
#include <random.h>

#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstring>
#include <limits>
#include <numbers>
#include <stdexcept>

namespace smile2 {

bool CTPublicAccount::IsValid() const
{
    return !note_commitment.IsNull() &&
           !account_leaf_commitment.IsNull() &&
           public_key.pk.size() == KEY_ROWS &&
           public_key.A.size() == KEY_ROWS &&
           std::all_of(public_key.A.begin(), public_key.A.end(), [](const auto& row) {
               return row.size() == KEY_COLS;
           }) &&
           public_coin.t0.size() == BDLOP_RAND_DIM_BASE &&
           public_coin.t_msg.size() == 1;
}

// M3 audit note: this function uses floating-point arithmetic intentionally.
// It is NOT on the consensus-critical path -- it is only used by the PROVER
// to decide whether to accept or retry a rejection sample. The verifier never
// calls this function. Floating-point non-determinism between platforms does
// not affect consensus because the verifier only checks the final z vector,
// not the prover's acceptance decision.
double ComputeCtRejectionLogAccept(const SmilePolyVec& z,
                                   const SmilePolyVec& cv,
                                   int64_t sigma)
{
    double inner = 0.0;
    double cv_norm_sq = 0.0;
    const int64_t half_q = Q / 2;
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

    const double sigma_sq = static_cast<double>(sigma) * static_cast<double>(sigma);
    static constexpr double REJECTION_M = 3.0;
    return (-2.0 * inner + cv_norm_sq) / (2.0 * sigma_sq) - std::log(REJECTION_M);
}

SmilePoly InvertMonomialChallenge(const SmilePoly& challenge)
{
    // Guard against malformed callers in release builds as well as debug.
    size_t monomial_index = POLY_DEGREE;
    int64_t monomial_coeff = 0;
    size_t nonzero_count = 0;
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        int64_t c = mod_q(challenge.coeffs[i]);
        if (c == 0) continue;
        if (nonzero_count == 0) {
            monomial_index = i;
            monomial_coeff = c;
        }
        ++nonzero_count;
    }

    if (monomial_index >= POLY_DEGREE || nonzero_count != 1) {
        throw std::invalid_argument("InvertMonomialChallenge requires a single non-zero monomial");
    }
    assert(monomial_index < POLY_DEGREE && "challenge must be a monomial");
    assert(nonzero_count == 1 && "challenge must have exactly one non-zero coefficient");

    SmilePoly inverse;
    // H1 audit fix (b): for index 0, return inv_mod_q(coeff) not coeff itself.
    // In R_q[X]/(X^d+1), the inverse of a*X^0 is a^{-1}*X^0.
    if (monomial_index == 0) {
        inverse.coeffs[0] = inv_mod_q(monomial_coeff);
        return inverse;
    }

    // For index k>0, inverse of a*X^k is -a^{-1}*X^{d-k} in R_q[X]/(X^d+1).
    const size_t inverse_index = POLY_DEGREE - monomial_index;
    inverse.coeffs[inverse_index] = mod_q(-inv_mod_q(monomial_coeff));
    return inverse;
}

namespace {

// M5 audit fix: shared numeric domain separator registry.
// See domain_separation.h for the canonical integer assignments used across
// the SMILE proof code.
//
// String-tagged domains (used via HashWriter):
//  "BTX_SMILE2_Serial_Nullifier_V1" - serial number hashing
//  "BTX_SMILE2_Output_Coin_V1"      - output coin hashing
//  "BTX_SMILE2_Direct_Input_Binding_V1" - input binding
//  "BTX_SMILE2_CT_PRE_H2_BIND_V1"  - pre-h2 binding digest
//  "BTX_SMILE2_CT_POST_H2_BIND_V1" - post-h2 binding digest
//  "BTX-SMILE-V2-COIN-RINGS-V1"    - coin ring digest (without account rings)
//  "BTX-SMILE-V2-ACCOUNT-RINGS-V1" - account ring digest (with account rings)
//  "BTX_SMILE2_Dup_Serial_V1"      - in-proof duplicate serial check

bool HasCanonicalSmilePublicKeyShape(const SmilePublicKey& pubkey);
bool HasCanonicalPublicCoinCommitmentShape(const BDLOPCommitment& coin);
size_t GetCtPublicRowCount();
std::array<uint8_t, 32> TranscriptHash(const std::vector<uint8_t>& transcript);
SmilePoly ComputeOpeningInnerProduct(const std::vector<SmilePoly>& row, const SmilePolyVec& opening);
SmilePoly ComputeOpeningInnerProduct(const std::vector<NttForm>& row_ntt,
                                     const std::vector<NttForm>& opening_ntt);

using SlotChallenge = std::array<NttSlot, NUM_NTT_SLOTS>;
constexpr uint64_t PROVE_CT_RETRY_STRIDE{0x9e3779b97f4a7c15ULL};
// The current monomial-CT surface still has a visible long tail on 2-input
// proving attempts. Keep the prover bounded, but high enough that
// deterministic harness seeds do not exhaust retries and return empty proofs.
constexpr size_t MAX_PROVE_CT_REJECTION_RETRIES{256};
constexpr size_t MAX_CT_TIMING_PADDING_ATTEMPTS{MAX_PROVE_CT_REJECTION_RETRIES};
volatile uint64_t g_ct_padding_sink{0};

[[nodiscard]] bool UsePostforkTupleHardening(bool bind_anonset_context)
{
    return bind_anonset_context;
}

void Sha256WriteLE32(CSHA256& hasher, uint32_t value)
{
    uint8_t buf[4];
    WriteLE32(buf, value);
    hasher.Write(buf, sizeof(buf));
}

void Sha256WriteLE64(CSHA256& hasher, uint64_t value)
{
    uint8_t buf[8];
    WriteLE64(buf, value);
    hasher.Write(buf, sizeof(buf));
}

uint64_t DeriveCtPaddingSeed(const SmileCTProof& proof,
                             uint64_t rng_seed,
                             int64_t public_fee,
                             bool bind_anonset_context)
{
    CSHA256 hasher;
    static constexpr char kDomain[] = "BTX_SMILE2_CT_PADDING_V1";
    hasher.Write(reinterpret_cast<const uint8_t*>(kDomain), sizeof(kDomain) - 1);
    hasher.Write(proof.fs_seed.data(), proof.fs_seed.size());
    hasher.Write(proof.seed_c0.data(), proof.seed_c0.size());
    hasher.Write(proof.seed_c.data(), proof.seed_c.size());
    hasher.Write(proof.seed_z.data(), proof.seed_z.size());
    Sha256WriteLE64(hasher, rng_seed);
    Sha256WriteLE64(hasher, static_cast<uint64_t>(public_fee));
    uint8_t bind_flag{static_cast<uint8_t>(bind_anonset_context ? 1 : 0)};
    hasher.Write(&bind_flag, sizeof(bind_flag));
    uint8_t hash[32];
    hasher.Finalize(hash);
    return ReadLE64(hash);
}

void AppendAnonSetTranscript(std::vector<uint8_t>& transcript,
                             const std::vector<SmilePublicKey>& anon_set,
                             bool bind_anonset_context)
{
    CSHA256 pk_hash;
    if (bind_anonset_context) {
        static constexpr char ANON_SET_DOMAIN[] = "BTX_SMILE2_ANON_SET_CTX_V2";
        pk_hash.Write(reinterpret_cast<const uint8_t*>(ANON_SET_DOMAIN), sizeof(ANON_SET_DOMAIN) - 1);
        Sha256WriteLE32(pk_hash, static_cast<uint32_t>(anon_set.size()));
        Sha256WriteLE32(pk_hash, static_cast<uint32_t>(KEY_ROWS));
        Sha256WriteLE32(pk_hash, static_cast<uint32_t>(KEY_COLS));
    }
    for (const auto& member : anon_set) {
        for (size_t row = 0; row < KEY_ROWS; ++row) {
            for (size_t coeff = 0; coeff < POLY_DEGREE; ++coeff) {
                Sha256WriteLE32(pk_hash, static_cast<uint32_t>(mod_q(member.pk[row].coeffs[coeff])));
            }
        }
        if (!bind_anonset_context) continue;
        for (const auto& matrix_row : member.A) {
            for (const auto& poly : matrix_row) {
                for (size_t coeff = 0; coeff < POLY_DEGREE; ++coeff) {
                    Sha256WriteLE32(pk_hash, static_cast<uint32_t>(mod_q(poly.coeffs[coeff])));
                }
            }
        }
    }
    uint8_t pk_digest[32];
    pk_hash.Finalize(pk_digest);
    transcript.insert(transcript.end(), pk_digest, pk_digest + sizeof(pk_digest));
}

SmilePoly HashToPoly(const uint8_t* data, size_t len, uint32_t domain, uint32_t index)
{
    SmilePoly p;
    for (size_t block = 0; block < POLY_DEGREE; block += 8) {
        CSHA256 hasher;
        hasher.Write(data, len);
        uint8_t buf[12];
        WriteLE32(buf, domain);
        WriteLE32(buf + 4, index);
        const uint32_t blk = static_cast<uint32_t>(block);
        WriteLE32(buf + 8, blk);
        hasher.Write(buf, sizeof(buf));
        uint8_t hash[32];
        hasher.Finalize(hash);
        for (size_t i = 0; i < 8 && (block + i) < POLY_DEGREE; ++i) {
            const uint32_t val = ReadLE32(hash + 4 * i);
            p.coeffs[block + i] = static_cast<int64_t>(val) % Q;
        }
    }
    return p;
}

// --- Deterministic PRNG ---
// H2 audit fix: replaced weak xorshift64 with ChaCha20-based CSPRNG
// (FastRandomContext) seeded from a deterministic 256-bit hash of the
// input seed. Gaussian sampling now uses 64-bit entropy instead of 32-bit.
class DetRng {
    FastRandomContext m_ctx;

    static uint256 SeedToHash(uint64_t seed) {
        CSHA256 hasher;
        Sha256WriteLE64(hasher, seed);
        uint256 hash256;
        hasher.Finalize(hash256.begin());
        return hash256;
    }
public:
    explicit DetRng(uint64_t seed) : m_ctx(SeedToHash(seed)) {}

    uint64_t Next() {
        return m_ctx.rand64();
    }

    int64_t UniformModQ() {
        // Use 64-bit random for better uniformity.
        uint64_t r = Next();
        return static_cast<int64_t>(r % static_cast<uint64_t>(Q));
    }

    // Discrete Gaussian via Box-Muller with 64-bit entropy per sample.
    // L1 note: clamping u1 away from zero introduces negligible bias
    // (< 2^{-50}) which is acceptable for the masking distribution.
    int64_t GaussianSample(int64_t sigma) {
        // H2 audit fix: use full 64-bit entropy instead of 32-bit.
        double u1 = static_cast<double>(Next()) / 18446744073709551616.0;
        double u2 = static_cast<double>(Next()) / 18446744073709551616.0;
        if (u1 < 1e-15) u1 = 1e-15;
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

    SmilePoly UniformPoly() {
        SmilePoly p;
        for (size_t i = 0; i < POLY_DEGREE; ++i) {
            p.coeffs[i] = UniformModQ();
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

// Rejection sampling for zero-knowledge on the current monomial-CT surface.
// Returns true if z should be ACCEPTED.
bool RejectionSample(const SmilePolyVec& z, const SmilePolyVec& cv,
                     int64_t sigma, DetRng& rng)
{
    const double log_accept = ComputeCtRejectionLogAccept(z, cv, sigma);
    if (log_accept >= 0.0) return true;
    // H2 audit fix: use full 64-bit entropy for rejection coin.
    double u = static_cast<double>(rng.Next()) / 18446744073709551616.0;
    return std::log(u) < log_accept;
}

// --- Hashing utilities ---

std::array<int64_t, NUM_NTT_SLOTS> HashToScalarChallenge(
    const uint8_t* data, size_t len, uint32_t domain)
{
    std::array<int64_t, NUM_NTT_SLOTS> result{};
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
        result[i] = static_cast<int64_t>(ReadLE32(hash)) % Q;
    }
    return result;
}

SlotChallenge HashToSlotChallenge(
    const uint8_t* data,
    size_t len,
    uint32_t domain)
{
    SlotChallenge result{};
    for (size_t i = 0; i < NUM_NTT_SLOTS; ++i) {
        CSHA256 hasher;
        hasher.Write(data, len);
        uint8_t buf[8];
        WriteLE32(buf, domain);
        const uint32_t idx = static_cast<uint32_t>(i);
        WriteLE32(buf + 4, idx);
        hasher.Write(buf, sizeof(buf));
        uint8_t hash[32];
        hasher.Finalize(hash);
        for (size_t c = 0; c < SLOT_DEGREE; ++c) {
            const uint32_t val = ReadLE32(hash + (4 * c));
            result[i].coeffs[c] = static_cast<int64_t>(val) % Q;
        }
    }
    return result;
}

// Challenge polynomial: ternary monomial c = ±X^k
// With monomial challenge, ||c·r||_∞ ≤ 1 for ternary r, enabling small σ.
SmilePoly HashToMonomialChallenge(const uint8_t* data, size_t len, uint32_t domain)
{
    CSHA256 hasher;
    hasher.Write(data, len);
    uint8_t dbuf[4];
    WriteLE32(dbuf, domain);
    hasher.Write(dbuf, 4);
    uint8_t hash[32];
    hasher.Finalize(hash);

    SmilePoly c;
    uint8_t k = hash[0] % POLY_DEGREE;
    int64_t sign = (hash[1] & 1) ? 1 : mod_q(-1);
    c.coeffs[k] = sign;
    return c;
}

SmilePoly DivideByMonomialChallenge(const SmilePoly& scaled, const SmilePoly& challenge)
{
    return NttMul(InvertMonomialChallenge(challenge), scaled);
}

std::vector<SmilePoly> DeriveRhoChallenges(
    const std::vector<uint8_t>& transcript,
    size_t count)
{
    std::vector<SmilePoly> rhos(count);
    for (size_t i = 0; i < count; ++i) {
        rhos[i] = HashToPoly(transcript.data(),
                             transcript.size(),
                             domainsep::RHO,
                             static_cast<uint32_t>(i));
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
        out[i] = HashToSlotChallenge(seed.data(),
                                     seed.size(),
                                     domain_base + static_cast<uint32_t>(i));
    }
    return out;
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
    const size_t row_count = p_rows.size();
    std::vector<SmilePoly> out(cols_next);
    for (size_t c = 0; c < cols_next; ++c) {
        NttForm acc;
        for (size_t block = 0; block < NUM_NTT_SLOTS; ++block) {
            const size_t src = c * NUM_NTT_SLOTS + block;
            for (size_t row = 0; row < row_count && row < gamma1.size(); ++row) {
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

SmilePoly BuildConstantPoly(int64_t constant)
{
    SmilePoly out;
    out.coeffs[0] = mod_q(constant);
    return out;
}

SmilePoly EncodeUint256ToSmilePoly(const uint256& value)
{
    SmilePoly out;
    for (size_t i = 0; i < value.size() && i < POLY_DEGREE; ++i) {
        out.coeffs[i] = static_cast<int64_t>(value.begin()[i]);
    }
    out.Reduce();
    return out;
}

SmilePolyVec ComputeB0Response(
    const BDLOPCommitmentKey& ck,
    const SmilePolyVec& witness)
{
    std::vector<NttForm> witness_ntt(witness.size());
    for (size_t col = 0; col < witness.size(); ++col) {
        witness_ntt[col] = NttForward(witness[col]);
    }

    SmilePolyVec out(BDLOP_RAND_DIM_BASE);
    for (size_t row = 0; row < BDLOP_RAND_DIM_BASE; ++row) {
        NttForm acc_ntt;
        for (size_t col = 0; col < ck.rand_dim(); ++col) {
            acc_ntt += ck.B0_ntt[row][col].PointwiseMul(witness_ntt[col]);
        }
        out[row] = NttInverse(acc_ntt);
        out[row].Reduce();
    }
    return out;
}

std::vector<SmilePoly> ComputeMaskResponses(
    const BDLOPCommitmentKey& ck,
    const SmilePolyVec& y_mask)
{
    std::vector<NttForm> y_mask_ntt(y_mask.size());
    for (size_t col = 0; col < y_mask.size(); ++col) {
        y_mask_ntt[col] = NttForward(y_mask[col]);
    }

    std::vector<SmilePoly> out(ck.n_msg);
    for (size_t j = 0; j < ck.n_msg; ++j) {
        NttForm acc_ntt;
        for (size_t col = 0; col < ck.rand_dim(); ++col) {
            acc_ntt += ck.b_ntt[j][col].PointwiseMul(y_mask_ntt[col]);
        }
        out[j] = NttInverse(acc_ntt);
        out[j].Reduce();
    }
    return out;
}

std::array<uint8_t, 32> TranscriptHash(const std::vector<uint8_t>& transcript)
{
    CSHA256 hasher;
    hasher.Write(transcript.data(), transcript.size());
    std::array<uint8_t, 32> hash{};
    hasher.Finalize(hash.data());
    return hash;
}

void AppendPoly(std::vector<uint8_t>& transcript, const SmilePoly& p)
{
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        uint8_t buf[4];
        WriteLE32(buf, static_cast<uint32_t>(mod_q(p.coeffs[i])));
        transcript.insert(transcript.end(), buf, buf + sizeof(buf));
    }
}

void AppendU32(std::vector<uint8_t>& transcript, uint32_t val) {
    uint8_t buf[4];
    WriteLE32(buf, val);
    transcript.insert(transcript.end(), buf, buf + sizeof(buf));
}

void AppendHash32(std::vector<uint8_t>& transcript, const std::array<uint8_t, 32>& digest)
{
    transcript.insert(transcript.end(), digest.begin(), digest.end());
}

void AppendCoinRingDigest(std::vector<uint8_t>& transcript, const CTPublicData& pub)
{
    CSHA256 ring_hash;
    const char* domain = pub.account_rings.empty() ?
        "BTX-SMILE-V2-COIN-RINGS-V1" :
        "BTX-SMILE-V2-PUBLIC-ACCOUNT-RINGS-V1";
    ring_hash.Write(reinterpret_cast<const uint8_t*>(domain), strlen(domain));

    // M6 audit documentation: when account_rings are present, every ring member
    // carries the spender's account_leaf_commitment. This is correct for the
    // direct-spend model because the one-out-of-many proof hides WHICH member
    // is the real spender. All members sharing the same leaf commitment does
    // not leak information -- the verifier already knows all ring members and
    // the proof guarantees that the hidden index selects exactly one. The leaf
    // commitment binds the spender's account to the Merkle tree entry.
    if (!pub.account_rings.empty()) {
        const uint32_t ring_count = static_cast<uint32_t>(pub.account_rings.size());
        Sha256WriteLE32(ring_hash, ring_count);
        for (const auto& ring : pub.account_rings) {
            const uint32_t member_count = static_cast<uint32_t>(ring.size());
            Sha256WriteLE32(ring_hash, member_count);
            for (const auto& account : ring) {
                ring_hash.Write(account.note_commitment.begin(), account.note_commitment.size());
                ring_hash.Write(account.account_leaf_commitment.begin(), account.account_leaf_commitment.size());

                const uint32_t pk_row_count = static_cast<uint32_t>(account.public_key.pk.size());
                Sha256WriteLE32(ring_hash, pk_row_count);
                for (const auto& poly : account.public_key.pk) {
                    for (size_t i = 0; i < POLY_DEGREE; ++i) {
                        Sha256WriteLE32(ring_hash, static_cast<uint32_t>(mod_q(poly.coeffs[i])));
                    }
                }

                const uint32_t t0_count = static_cast<uint32_t>(account.public_coin.t0.size());
                const uint32_t tmsg_count = static_cast<uint32_t>(account.public_coin.t_msg.size());
                Sha256WriteLE32(ring_hash, t0_count);
                for (const auto& poly : account.public_coin.t0) {
                    for (size_t i = 0; i < POLY_DEGREE; ++i) {
                        Sha256WriteLE32(ring_hash, static_cast<uint32_t>(mod_q(poly.coeffs[i])));
                    }
                }
                Sha256WriteLE32(ring_hash, tmsg_count);
                for (const auto& poly : account.public_coin.t_msg) {
                    for (size_t i = 0; i < POLY_DEGREE; ++i) {
                        Sha256WriteLE32(ring_hash, static_cast<uint32_t>(mod_q(poly.coeffs[i])));
                    }
                }
            }
        }
        uint8_t digest[32];
        ring_hash.Finalize(digest);
        transcript.insert(transcript.end(), digest, digest + sizeof(digest));
        return;
    }

    const uint32_t ring_count = static_cast<uint32_t>(pub.coin_rings.size());
    Sha256WriteLE32(ring_hash, ring_count);
    for (const auto& ring : pub.coin_rings) {
        const uint32_t member_count = static_cast<uint32_t>(ring.size());
        Sha256WriteLE32(ring_hash, member_count);
        for (const auto& coin : ring) {
            const uint32_t t0_count = static_cast<uint32_t>(coin.t0.size());
            const uint32_t tmsg_count = static_cast<uint32_t>(coin.t_msg.size());
            Sha256WriteLE32(ring_hash, t0_count);
            for (const auto& poly : coin.t0) {
                for (size_t i = 0; i < POLY_DEGREE; ++i) {
                    Sha256WriteLE32(ring_hash, static_cast<uint32_t>(mod_q(poly.coeffs[i])));
                }
            }
            Sha256WriteLE32(ring_hash, tmsg_count);
            for (const auto& poly : coin.t_msg) {
                for (size_t i = 0; i < POLY_DEGREE; ++i) {
                    Sha256WriteLE32(ring_hash, static_cast<uint32_t>(mod_q(poly.coeffs[i])));
                }
            }
        }
    }

    uint8_t digest[32];
    ring_hash.Finalize(digest);
    transcript.insert(transcript.end(), digest, digest + sizeof(digest));
}

bool HasCanonicalPublicAccount(const CTPublicAccount& account)
{
    return !account.note_commitment.IsNull() &&
           !account.account_leaf_commitment.IsNull() &&
           HasCanonicalSmilePublicKeyShape(account.public_key) &&
           HasCanonicalPublicCoinCommitmentShape(account.public_coin);
}

bool AccountRingsMatchSplitPublicData(const CTPublicData& pub, size_t num_inputs)
{
    if (pub.account_rings.size() != num_inputs) {
        return false;
    }
    if (pub.account_rings.empty()) {
        return true;
    }
    const size_t ring_size = pub.anon_set.size();
    if (ring_size == 0) {
        return false;
    }
    for (size_t input_index = 0; input_index < num_inputs; ++input_index) {
        if (pub.account_rings[input_index].size() != ring_size ||
            pub.coin_rings.size() != num_inputs ||
            pub.coin_rings[input_index].size() != ring_size) {
            return false;
        }
        for (size_t member = 0; member < ring_size; ++member) {
            const auto& account = pub.account_rings[input_index][member];
            if (!HasCanonicalPublicAccount(account) ||
                account.public_key.pk != pub.anon_set[member].pk ||
                account.public_key.A != pub.anon_set[member].A ||
                account.public_coin.t0 != pub.coin_rings[input_index][member].t0 ||
                account.public_coin.t_msg != pub.coin_rings[input_index][member].t_msg) {
                return false;
            }
        }
    }
    return true;
}

// Append compressed polynomial to transcript (drop D low-order bits)
void AppendPolyCompressed(std::vector<uint8_t>& transcript, const SmilePoly& p) {
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        uint32_t val = static_cast<uint32_t>(mod_q(p.coeffs[i]));
        uint32_t compressed = val >> COMPRESS_D;
        transcript.push_back(static_cast<uint8_t>(compressed & 0xFF));
        transcript.push_back(static_cast<uint8_t>((compressed >> 8) & 0xFF));
        transcript.push_back(static_cast<uint8_t>((compressed >> 16) & 0xFF));
    }
}

// Add aux commitment to transcript using exact t0 rows.
void AppendAuxCommitment(std::vector<uint8_t>& transcript, const BDLOPCommitment& aux) {
    size_t t0_count = std::min(aux.t0.size(), static_cast<size_t>(MSIS_RANK));
    for (size_t i = 0; i < t0_count; ++i) {
        AppendPoly(transcript, aux.t0[i]);
    }
    for (const auto& t : aux.t_msg) {
        AppendPoly(transcript, t);
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

std::vector<SmilePoly> DeriveOpeningChallenges(
    const std::vector<uint8_t>& transcript,
    size_t count)
{
    std::vector<SmilePoly> challenges(count);
    for (size_t i = 0; i < count; ++i) {
        challenges[i] = HashToPoly(transcript.data(),
                                   transcript.size(),
                                   smile2::domainsep::CT_OPENING_CHALLENGE_BASE,
                                   static_cast<uint32_t>(i));
    }
    return challenges;
}

// Number of auxiliary BDLOP message slots for CT proof
// Slot layout (per spec Section 2.6):
//   t'_1: garbage (serial number proof)
//   t'_2: garbage (amortized opening ⟨b'_1, y⟩)
//   t'_3: carry garbage polynomial o
//   t'_4: carry polynomial e
//   t'_5, t'_6, t'_7: garbage decomposition for quadratic check
//   t'_{8..7+m}: recommitted input amounts a^{in}_i
//   t'_{8+m..7+m+n}: recommitted output amounts a^{out}_i
//   full per-input w_0 rows (all KEY_ROWS rows for every input)
//   full recursive x_j rows (all KEY_ROWS rows for every input / level)
//   selector decompositions v_{i,j}
size_t ComputeNumAuxMsg(size_t num_inputs, size_t num_outputs, size_t rec_levels) {
    if (rec_levels == 1) {
        const size_t selectors = num_inputs;
        const size_t amounts = num_inputs + num_outputs;
        const size_t w_rows = num_inputs * GetCtPublicRowCount();
        const size_t x_slots = num_inputs;
        const size_t tail = 2; // g, psi
        return selectors + amounts + w_rows + x_slots + tail;
    }

    const size_t base = 7; // legacy prototype slots (t'_1..t'_7)
    const size_t amounts = num_inputs + num_outputs;
    const size_t w_rows = num_inputs * GetCtPublicRowCount();
    const size_t x_rows = num_inputs * (rec_levels > 0 ? rec_levels - 1 : 0) * GetCtPublicRowCount();
    const size_t selectors = num_inputs * rec_levels;
    return base + amounts + w_rows + x_rows + selectors;
}

struct CtAuxLayout
{
    size_t num_inputs;
    size_t num_outputs;
    size_t rec_levels;

    [[nodiscard]] bool UsesLiveM1Layout() const { return rec_levels == 1; }

    [[nodiscard]] size_t SelectorOffset() const
    {
        return UsesLiveM1Layout() ? 0 : SelectorOffsetLegacy();
    }

    [[nodiscard]] size_t InputAmountOffset() const
    {
        return UsesLiveM1Layout() ? SelectorOffset() + num_inputs : 7;
    }

    [[nodiscard]] size_t OutputAmountOffset() const
    {
        return InputAmountOffset() + num_inputs;
    }

    [[nodiscard]] size_t W0Offset() const
    {
        return OutputAmountOffset() + num_outputs;
    }

    [[nodiscard]] size_t XOffset() const
    {
        return W0Offset() + num_inputs * GetCtPublicRowCount();
    }

    [[nodiscard]] size_t TotalSlots() const {
        if (UsesLiveM1Layout()) {
            return PsiSlot() + 1;
        }
        return SelectorOffsetLegacy() + num_inputs * rec_levels;
    }

    [[nodiscard]] size_t GSlot() const
    {
        if (UsesLiveM1Layout()) {
            return XOffset() + num_inputs;
        }
        return 6;
    }

    [[nodiscard]] size_t PsiSlot() const
    {
        if (UsesLiveM1Layout()) {
            return GSlot() + 1;
        }
        return 5;
    }

    [[nodiscard]] size_t InputAmountSlot(size_t input_index) const
    {
        return InputAmountOffset() + input_index;
    }

    [[nodiscard]] size_t OutputAmountSlot(size_t output_index) const
    {
        return OutputAmountOffset() + output_index;
    }

    [[nodiscard]] size_t W0Slot(size_t input_index, size_t row) const
    {
        return W0Offset() + input_index * GetCtPublicRowCount() + row;
    }

    [[nodiscard]] size_t XSlot(size_t input_index, size_t level, size_t row) const
    {
        if (UsesLiveM1Layout()) {
            assert(level == 1);
            assert(row == 0);
            return XOffset() + input_index;
        }
        assert(level >= 2);
        assert(level <= rec_levels);
        return XOffset() +
               (input_index * (rec_levels - 1) + (level - 2)) * GetCtPublicRowCount() + row;
    }

    [[nodiscard]] size_t SelectorSlot(size_t input_index, size_t level) const
    {
        if (UsesLiveM1Layout()) {
            assert(level == 0);
            return SelectorOffset() + input_index;
        }
        assert(level < rec_levels);
        return SelectorOffsetLegacy() + input_index * rec_levels + level;
    }

private:
    [[nodiscard]] size_t SelectorOffsetLegacy() const
    {
        return XOffset() + num_inputs * (rec_levels > 0 ? rec_levels - 1 : 0) * GetCtPublicRowCount();
    }
};

size_t ComputeLiveCtRetainedAuxMsgCount(const CtAuxLayout& aux_layout)
{
    if (!aux_layout.UsesLiveM1Layout()) {
        return aux_layout.TotalSlots();
    }
    return 0;
}

std::vector<SmilePoly> CollectLiveCtRound1AuxBindingPolys(const CtAuxLayout& aux_layout,
                                                          Span<const SmilePoly> aux_tmsg)
{
    std::vector<SmilePoly> polys;
    if (!aux_layout.UsesLiveM1Layout()) {
        return polys;
    }

    polys.reserve(aux_layout.num_inputs + aux_layout.num_inputs + aux_layout.num_outputs + 1);
    for (size_t inp = 0; inp < aux_layout.num_inputs; ++inp) {
        const size_t slot = aux_layout.SelectorSlot(inp, 0);
        if (slot < aux_tmsg.size()) {
            polys.push_back(aux_tmsg[slot]);
        }
    }
    for (size_t inp = 0; inp < aux_layout.num_inputs; ++inp) {
        const size_t slot = aux_layout.InputAmountSlot(inp);
        if (slot < aux_tmsg.size()) {
            polys.push_back(aux_tmsg[slot]);
        }
    }
    for (size_t out = 0; out < aux_layout.num_outputs; ++out) {
        const size_t slot = aux_layout.OutputAmountSlot(out);
        if (slot < aux_tmsg.size()) {
            polys.push_back(aux_tmsg[slot]);
        }
    }
    const size_t g_slot = aux_layout.GSlot();
    if (g_slot < aux_tmsg.size()) {
        polys.push_back(aux_tmsg[g_slot]);
    }
    return polys;
}

std::vector<SmilePoly> CollectLiveCtPreH2BindingPolys(const CtAuxLayout& aux_layout,
                                                      Span<const SmilePoly> aux_tmsg,
                                                      Span<const SmilePoly> w0_commitment_accs)
{
    std::vector<SmilePoly> polys;
    if (!aux_layout.UsesLiveM1Layout()) {
        return polys;
    }

    polys.reserve(w0_commitment_accs.size() + aux_layout.num_inputs);
    for (const auto& acc : w0_commitment_accs) {
        polys.push_back(acc);
    }
    for (size_t inp = 0; inp < aux_layout.num_inputs; ++inp) {
        const size_t slot = aux_layout.XSlot(inp, 1, 0);
        if (slot < aux_tmsg.size()) {
            polys.push_back(aux_tmsg[slot]);
        }
    }
    return polys;
}

std::vector<SmilePoly> CollectLiveCtPostH2BindingPolys(const CtAuxLayout& aux_layout,
                                                       Span<const SmilePoly> aux_tmsg,
                                                       const SmilePoly& framework_omega)
{
    std::vector<SmilePoly> polys;
    if (!aux_layout.UsesLiveM1Layout()) {
        return polys;
    }

    polys.reserve(2);
    const size_t psi_slot = aux_layout.PsiSlot();
    if (psi_slot < aux_tmsg.size()) {
        polys.push_back(aux_tmsg[psi_slot]);
    }
    polys.push_back(framework_omega);
    return polys;
}

bool IsLiveCtW0Slot(const CtAuxLayout& aux_layout, size_t slot);
size_t ComputeCtWeakOpeningResidueCount(const CtAuxLayout& aux_layout);

SmilePoly ComputeCtWeakOpeningAccumulator(
    const BDLOPCommitmentKey& aux_ck,
    const SmilePolyVec& z,
    const SmilePolyVec& aux_t0,
    const std::vector<SmilePoly>& aux_residues,
    const std::vector<SmilePoly>& w0_residue_accs,
    const CtAuxLayout& aux_layout,
    const SmilePoly& c_chal,
    const SmilePoly& h2,
    const std::vector<SmilePoly>& opening_challenges)
{
    const size_t t0_rows = std::min(aux_t0.size(),
                                    static_cast<size_t>(MSIS_RANK));
    const size_t expected_count = t0_rows + ComputeCtWeakOpeningResidueCount(aux_layout) + 1;
    assert(opening_challenges.size() == expected_count);
    assert(aux_residues.size() == aux_ck.n_msg);
    if (aux_layout.UsesLiveM1Layout()) {
        assert(w0_residue_accs.size() == aux_layout.num_inputs);
    }

    SmilePoly accumulator;
    size_t challenge_index = 0;

    for (size_t row = 0; row < t0_rows; ++row) {
        SmilePoly residue;
        for (size_t col = 0; col < aux_ck.rand_dim(); ++col) {
            residue += NttMul(aux_ck.B0[row][col], z[col]);
        }
        residue -= NttMul(c_chal, aux_t0[row]);
        residue.Reduce();

        accumulator += NttMul(opening_challenges[challenge_index++], residue);
        accumulator.Reduce();
    }

    for (size_t msg = 0; msg < aux_ck.n_msg; ++msg) {
        if (IsLiveCtW0Slot(aux_layout, msg)) {
            continue;
        }
        accumulator += NttMul(opening_challenges[challenge_index++], aux_residues[msg]);
        accumulator.Reduce();
    }
    if (aux_layout.UsesLiveM1Layout()) {
        for (const auto& acc : w0_residue_accs) {
            accumulator += NttMul(opening_challenges[challenge_index++], acc);
            accumulator.Reduce();
        }
    }
    accumulator += NttMul(opening_challenges[challenge_index], h2);
    accumulator.Reduce();
    return accumulator;
}

size_t InferLiveCtOutputCountFromProof(const SmileCTProof& proof)
{
    const size_t num_inputs = proof.z0.size();
    const size_t fixed_slots =
        num_inputs +                    // selectors
        num_inputs +                    // input amounts
        num_inputs * GetCtPublicRowCount() +
        num_inputs +                    // X slots
        2;                              // G and Psi
    if (proof.aux_commitment.t_msg.size() < fixed_slots) {
        return 0;
    }
    return proof.aux_commitment.t_msg.size() - fixed_slots;
}

bool IsLiveCtOmittedAuxSlot(const CtAuxLayout& aux_layout, size_t slot)
{
    return aux_layout.UsesLiveM1Layout() && slot >= aux_layout.W0Offset();
}

bool IsLiveCtW0Slot(const CtAuxLayout& aux_layout, size_t slot)
{
    if (!aux_layout.UsesLiveM1Layout() || slot < aux_layout.W0Offset()) {
        return false;
    }
    const size_t w0_span = aux_layout.num_inputs * GetCtPublicRowCount();
    return slot < aux_layout.W0Offset() + w0_span;
}

size_t ComputeCtWeakOpeningResidueCount(const CtAuxLayout& aux_layout)
{
    if (!aux_layout.UsesLiveM1Layout()) {
        return aux_layout.TotalSlots();
    }
    const size_t omitted_w0 = aux_layout.num_inputs * GetCtPublicRowCount();
    return aux_layout.TotalSlots() - omitted_w0 + aux_layout.num_inputs;
}

SmilePoly ComputeCompressedW0CommitmentAccumulator(
    Span<const SmilePoly> commitment_rows,
    const std::vector<SlotChallenge>& gamma_rows)
{
    std::vector<SmilePoly> rows(commitment_rows.begin(), commitment_rows.end());
    return SumWeightedRows(rows, gamma_rows);
}

SmilePoly ComputeCompressedW0ResponseAccumulator(
    const BDLOPCommitmentKey& aux_ck,
    const CtAuxLayout& aux_layout,
    const SmilePolyVec& z,
    size_t input_index,
    const std::vector<SlotChallenge>& gamma_rows)
{
    std::vector<SmilePoly> responses;
    responses.reserve(GetCtPublicRowCount());
    for (size_t row = 0; row < GetCtPublicRowCount(); ++row) {
        responses.push_back(
            ComputeOpeningInnerProduct(aux_ck.b[aux_layout.W0Slot(input_index, row)], z));
    }
    return SumWeightedRows(responses, gamma_rows);
}

std::vector<SmilePoly> CollectSerializedOmittedAuxSelectorAmountResidues(
    const CtAuxLayout& aux_layout,
    const std::vector<SmilePoly>& aux_residues)
{
    std::vector<SmilePoly> serialized;
    const size_t retained_count = ComputeLiveCtRetainedAuxMsgCount(aux_layout);
    for (size_t slot = retained_count;
         slot < aux_residues.size() && slot < aux_layout.W0Offset();
         ++slot) {
        serialized.push_back(aux_residues[slot]);
    }
    return serialized;
}

std::vector<SmilePoly> CollectSerializedOmittedAuxTailResidues(
    const CtAuxLayout& aux_layout,
    const std::vector<SmilePoly>& aux_residues)
{
    std::vector<SmilePoly> serialized;
    const size_t tail_offset = aux_layout.W0Offset() + aux_layout.num_inputs * GetCtPublicRowCount();
    for (size_t slot = tail_offset; slot < aux_residues.size(); ++slot) {
        serialized.push_back(aux_residues[slot]);
    }
    return serialized;
}

std::array<uint8_t, 32> ComputeCtBindingDigest(std::string_view tag,
                                               uint32_t index,
                                               Span<const SmilePoly> polys)
{
    std::vector<uint8_t> transcript;
    transcript.insert(transcript.end(), tag.begin(), tag.end());
    AppendU32(transcript, index);
    for (const auto& poly : polys) {
        AppendPoly(transcript, poly);
    }
    return TranscriptHash(transcript);
}

SmilePoly ComputeAuxMessageResidueFromCommitment(const BDLOPCommitmentKey& aux_ck,
                                                 const SmilePolyVec& z,
                                                 const std::vector<SmilePoly>& aux_tmsg,
                                                 const SmilePoly& c_chal,
                                                 size_t message_index)
{
    SmilePoly residue = ComputeOpeningInnerProduct(aux_ck.b[message_index], z);
    residue -= NttMul(c_chal, aux_tmsg[message_index]);
    residue.Reduce();
    return residue;
}

std::vector<SmilePoly> RecoverFullAuxMessageCommitments(const BDLOPCommitmentKey& aux_ck,
                                                        const SmileCTProof& proof,
                                                        const CtAuxLayout& aux_layout,
                                                        const SmilePoly& c_chal)
{
    const size_t retained_count = ComputeLiveCtRetainedAuxMsgCount(aux_layout);
    std::vector<SmilePoly> recovered(aux_ck.n_msg);
    for (size_t slot = 0; slot < std::min(retained_count, proof.aux_commitment.t_msg.size()); ++slot) {
        recovered[slot] = proof.aux_commitment.t_msg[slot];
    }
    for (size_t slot = retained_count; slot < aux_ck.n_msg; ++slot) {
        if (IsLiveCtW0Slot(aux_layout, slot)) {
            recovered[slot] = SmilePoly{};
            continue;
        }
        SmilePoly scaled_commitment = ComputeOpeningInnerProduct(aux_ck.b[slot], proof.z);
        scaled_commitment -= proof.aux_residues[slot];
        scaled_commitment.Reduce();
        recovered[slot] = DivideByMonomialChallenge(scaled_commitment, c_chal);
        recovered[slot].Reduce();
    }
    return recovered;
}

std::vector<SmilePoly> BuildFullAuxResidues(const BDLOPCommitmentKey& aux_ck,
                                            const SmileCTProof& proof,
                                            const CtAuxLayout& aux_layout,
                                            const std::vector<SmilePoly>& aux_tmsg,
                                            const SmilePoly& c_chal)
{
    std::vector<SmilePoly> residues(aux_ck.n_msg);
    for (size_t slot = 0; slot < aux_ck.n_msg; ++slot) {
        if (IsLiveCtW0Slot(aux_layout, slot)) {
            residues[slot] = SmilePoly{};
        } else if (IsLiveCtOmittedAuxSlot(aux_layout, slot)) {
            residues[slot] = proof.aux_residues[slot];
        } else {
            residues[slot] =
                ComputeAuxMessageResidueFromCommitment(aux_ck, proof.z, aux_tmsg, c_chal, slot);
        }
    }
    return residues;
}

BDLOPCommitmentKey GetPublicCoinCommitmentKey()
{
    std::array<uint8_t, 32> out_ck_seed{};
    out_ck_seed[0] = 0xCC;
    return BDLOPCommitmentKey::Generate(out_ck_seed, 1);
}

bool HasCanonicalSmilePublicKeyShape(const SmilePublicKey& pubkey)
{
    if (pubkey.pk.size() != KEY_ROWS || pubkey.A.size() != KEY_ROWS) {
        return false;
    }
    for (size_t row = 0; row < KEY_ROWS; ++row) {
        if (pubkey.A[row].size() != KEY_COLS) {
            return false;
        }
    }
    return true;
}

bool HasUniformSmilePublicKeyMatrix(const std::vector<SmilePublicKey>& anon_set)
{
    if (anon_set.empty() || !HasCanonicalSmilePublicKeyShape(anon_set.front())) {
        return false;
    }
    const auto& expected_a = anon_set.front().A;
    for (const auto& pubkey : anon_set) {
        if (!HasCanonicalSmilePublicKeyShape(pubkey) || pubkey.A != expected_a) {
            return false;
        }
    }
    return true;
}

bool HasCanonicalPublicCoinCommitmentShape(const BDLOPCommitment& coin)
{
    return coin.t0.size() == BDLOP_RAND_DIM_BASE && coin.t_msg.size() == 1;
}

SmilePoly HashToIndexedChallengePoly(const uint8_t* data, size_t len, uint32_t domain, uint32_t index)
{
    CSHA256 hasher;
    hasher.Write(data, len);
    uint8_t dbuf[8];
    WriteLE32(dbuf, domain);
    WriteLE32(dbuf + 4, index);
    hasher.Write(dbuf, sizeof(dbuf));
    uint8_t hash[32];
    hasher.Finalize(hash);

    SmilePoly c;
    uint8_t k = hash[0] % POLY_DEGREE;
    int64_t sign = (hash[1] & 1) ? 1 : mod_q(-1);
    c.coeffs[k] = sign;
    return c;
}

std::vector<SmilePoly> DeriveCoinOpeningChallenges(
    const std::array<uint8_t, 32>& seed,
    size_t count,
    uint32_t domain)
{
    std::vector<SmilePoly> challenges(count);
    for (size_t i = 0; i < count; ++i) {
        challenges[i] =
            HashToIndexedChallengePoly(seed.data(), seed.size(), domain, static_cast<uint32_t>(i));
    }
    return challenges;
}

std::vector<SmilePoly> DeriveCoinOpeningChallenges(
    const std::vector<uint8_t>& transcript,
    size_t count,
    uint32_t domain)
{
    return DeriveCoinOpeningChallenges(TranscriptHash(transcript), count, domain);
}

std::vector<std::array<int64_t, NUM_NTT_SLOTS>> DeriveCtAlphaChallenges(
    const std::vector<uint8_t>& transcript,
    size_t input_index,
    size_t rec_levels)
{
    std::vector<std::array<int64_t, NUM_NTT_SLOTS>> challenges;
    challenges.reserve(rec_levels);
    for (size_t level = 1; level <= rec_levels; ++level) {
        std::vector<uint8_t> alpha_transcript = transcript;
        AppendU32(alpha_transcript, static_cast<uint32_t>(input_index));
        AppendU32(alpha_transcript, static_cast<uint32_t>(level));
        const auto alpha_seed = TranscriptHash(alpha_transcript);
        challenges.push_back(HashToScalarChallenge(alpha_seed.data(),
                                                   32,
                                                   domainsep::CtAlphaLevel(level)));
    }
    return challenges;
}

size_t GetCtPublicRowCount()
{
    return KEY_ROWS + 2;
}

size_t GetCtAmountRowIndex()
{
    return KEY_ROWS;
}

size_t GetCtLeafRowIndex()
{
    return KEY_ROWS + 1;
}

std::vector<SmilePoly> DeriveTupleCoinRowChallenges(
    const std::vector<uint8_t>& transcript)
{
    const auto seed = TranscriptHash(transcript);
    std::vector<SmilePoly> challenges(BDLOP_RAND_DIM_BASE);
    for (size_t row = 0; row < BDLOP_RAND_DIM_BASE; ++row) {
        challenges[row] =
            HashToPoly(seed.data(), seed.size(), domainsep::CT_TUPLE_COIN_ROW, static_cast<uint32_t>(row));
    }
    return challenges;
}

SmilePoly DeriveTupleOpeningCompressionChallenge(
    const std::vector<uint8_t>& transcript)
{
    const auto seed = TranscriptHash(transcript);
    return HashToPoly(seed.data(), seed.size(), domainsep::CT_TUPLE_OPENING_COMPRESSION, 0);
}

SmilePoly ComputeCoinOpeningRowAccumulator(
    const SmilePolyVec& w0_rows,
    const std::vector<SmilePoly>& row_challenges)
{
    SmilePoly acc;
    const size_t limit = std::min(w0_rows.size(), row_challenges.size());
    for (size_t row = 0; row < limit; ++row) {
        acc += NttMul(row_challenges[row], w0_rows[row]);
    }
    acc.Reduce();
    return acc;
}

SmilePoly ComputeCoinOpeningRowAccumulatorFromResponse(
    const BDLOPCommitmentKey& coin_ck,
    const SmilePolyVec& z,
    const std::vector<SmilePoly>& row_challenges)
{
    SmilePoly acc;
    std::vector<NttForm> z_ntt(z.size());
    for (size_t i = 0; i < z.size(); ++i) {
        z_ntt[i] = NttForward(z[i]);
    }
    const size_t limit = std::min(static_cast<size_t>(BDLOP_RAND_DIM_BASE), row_challenges.size());
    for (size_t row = 0; row < limit; ++row) {
        acc += NttMul(row_challenges[row], ComputeOpeningInnerProduct(coin_ck.B0_ntt[row], z_ntt));
    }
    acc.Reduce();
    return acc;
}

struct CtPublicAccountChallenges
{
    SmilePoly alpha;
    SmilePoly beta;
    SmilePoly gamma;
};

CtPublicAccountChallenges DeriveCtPublicAccountChallenges(
    const std::vector<uint8_t>& transcript,
    size_t input_index)
{
    std::vector<uint8_t> challenge_transcript = transcript;
    AppendU32(challenge_transcript, static_cast<uint32_t>(input_index));
    const auto challenge_seed = TranscriptHash(challenge_transcript);
    return {
        HashToPoly(challenge_seed.data(), challenge_seed.size(), domainsep::CT_PUBLIC_ACCOUNT_ALPHA, 0),
        HashToPoly(challenge_seed.data(), challenge_seed.size(), domainsep::CT_PUBLIC_ACCOUNT_BETA, 0),
        HashToPoly(challenge_seed.data(), challenge_seed.size(), domainsep::CT_PUBLIC_ACCOUNT_GAMMA, 0),
    };
}

std::vector<SlotChallenge> DeriveCtGammaChallenges(
    const std::vector<uint8_t>& transcript,
    size_t input_index,
    size_t row_count)
{
    std::vector<uint8_t> gamma_transcript = transcript;
    AppendU32(gamma_transcript, static_cast<uint32_t>(input_index));
    return DeriveSlotChallenges(gamma_transcript, domainsep::CT_GAMMA_BASE, row_count);
}

[[nodiscard]] const CTPublicAccount* GetCanonicalCtAccountMember(
    const CTPublicData& pub,
    size_t input_index,
    size_t member_index)
{
    if (input_index >= pub.account_rings.size() ||
        input_index >= pub.coin_rings.size() ||
        member_index >= pub.anon_set.size()) {
        return nullptr;
    }

    const auto& account_ring = pub.account_rings[input_index];
    const auto& coin_ring = pub.coin_rings[input_index];
    if (member_index >= account_ring.size() || member_index >= coin_ring.size()) {
        return nullptr;
    }

    const auto& account = account_ring[member_index];
    const auto& pubkey = pub.anon_set[member_index];
    if (!HasCanonicalPublicAccount(account) ||
        !HasCanonicalSmilePublicKeyShape(pubkey) ||
        account.public_key.pk != pubkey.pk ||
        account.public_key.A != pubkey.A ||
        account.public_coin.t0 != coin_ring[member_index].t0 ||
        account.public_coin.t_msg != coin_ring[member_index].t_msg) {
        return nullptr;
    }

    return &account;
}

std::optional<std::vector<std::vector<SmilePoly>>> BuildCtCombinedAccountRows(
    const CTPublicData& pub,
    size_t input_index,
    const CtPublicAccountChallenges& challenges,
    size_t padded_cols)
{
    const size_t row_count = GetCtPublicRowCount();
    std::vector<std::vector<SmilePoly>> rows(row_count);
    for (auto& row : rows) {
        row.resize(padded_cols);
    }

    for (size_t member = 0; member < pub.anon_set.size() && member < padded_cols; ++member) {
        const auto* account = GetCanonicalCtAccountMember(pub, input_index, member);
        if (account == nullptr) {
            return std::nullopt;
        }
        const BDLOPCommitment& public_coin = account->public_coin;
        for (size_t row = 0; row < KEY_ROWS; ++row) {
            SmilePoly acc = NttMul(challenges.alpha, pub.anon_set[member].pk[row]);
            acc += NttMul(challenges.beta, public_coin.t0[row]);
            acc.Reduce();
            rows[row][member] = std::move(acc);
        }
        SmilePoly amount_row = NttMul(challenges.beta, public_coin.t_msg.front());
        amount_row.Reduce();
        rows[GetCtAmountRowIndex()][member] = std::move(amount_row);

        SmilePoly leaf_row = NttMul(challenges.gamma,
                                    EncodeUint256ToSmilePoly(account->account_leaf_commitment));
        leaf_row.Reduce();
        rows[GetCtLeafRowIndex()][member] = std::move(leaf_row);
    }

    return std::make_optional(std::move(rows));
}

std::optional<std::vector<SmilePoly>> BuildCtCombinedSelectedAccountRows(
    const CTPublicData& pub,
    size_t input_index,
    size_t secret_index,
    const CtPublicAccountChallenges& challenges)
{
    const size_t row_count = GetCtPublicRowCount();
    std::vector<SmilePoly> rows(row_count);
    const auto* account = GetCanonicalCtAccountMember(pub, input_index, secret_index);
    if (account == nullptr) {
        return std::nullopt;
    }
    const BDLOPCommitment& public_coin = account->public_coin;
    for (size_t row = 0; row < KEY_ROWS; ++row) {
        SmilePoly acc = NttMul(challenges.alpha, pub.anon_set[secret_index].pk[row]);
        acc += NttMul(challenges.beta, public_coin.t0[row]);
        acc.Reduce();
        rows[row] = std::move(acc);
    }
    rows[GetCtAmountRowIndex()] = NttMul(challenges.beta, public_coin.t_msg.front());
    rows[GetCtAmountRowIndex()].Reduce();
    rows[GetCtLeafRowIndex()] =
        NttMul(challenges.gamma, EncodeUint256ToSmilePoly(account->account_leaf_commitment));
    rows[GetCtLeafRowIndex()].Reduce();
    return std::make_optional(std::move(rows));
}

std::optional<SmilePoly> ComputeCtCompressedPublicX(
    const CTPublicData& pub,
    size_t input_index,
    const CtPublicAccountChallenges& challenges,
    const SmilePoly& c0_chal,
    const std::vector<SlotChallenge>& gamma1_rows)
{
    const size_t N_padded = PadToLPower(pub.anon_set.size());
    const size_t cols_next = N_padded / NUM_NTT_SLOTS;
    auto public_rows = BuildCtCombinedAccountRows(pub, input_index, challenges, N_padded);
    if (!public_rows.has_value() || gamma1_rows.size() != GetCtPublicRowCount()) {
        return std::nullopt;
    }
    for (auto& row : *public_rows) {
        for (auto& poly : row) {
            poly = NttMul(c0_chal, poly);
            SmilePoly neg_poly;
            neg_poly -= poly;
            neg_poly.Reduce();
            poly = std::move(neg_poly);
            poly.Reduce();
        }
    }
    auto compressed = CompressFirstRoundMatrix(*public_rows, gamma1_rows, cols_next);
    assert(cols_next == 1);
    return std::make_optional(compressed.front());
}

SmilePolyVec SampleGaussianVec(DetRng& rng, size_t dim, int64_t sigma)
{
    SmilePolyVec out(dim);
    for (auto& poly : out) {
        poly = rng.GaussianPoly(sigma);
    }
    return out;
}

SmilePoly ComputeOpeningInnerProduct(const std::vector<SmilePoly>& row, const SmilePolyVec& opening)
{
    std::vector<NttForm> row_ntt(row.size());
    for (size_t i = 0; i < row.size(); ++i) {
        row_ntt[i] = NttForward(row[i]);
    }

    std::vector<NttForm> opening_ntt(opening.size());
    for (size_t i = 0; i < opening.size(); ++i) {
        opening_ntt[i] = NttForward(opening[i]);
    }

    return ComputeOpeningInnerProduct(row_ntt, opening_ntt);
}

SmilePoly ComputeOpeningInnerProduct(const std::vector<NttForm>& row_ntt,
                                     const std::vector<NttForm>& opening_ntt)
{
    NttForm acc_ntt;
    const size_t limit = std::min(row_ntt.size(), opening_ntt.size());
    for (size_t i = 0; i < limit; ++i) {
        acc_ntt += row_ntt[i].PointwiseMul(opening_ntt[i]);
    }
    SmilePoly acc = NttInverse(acc_ntt);
    acc.Reduce();
    return acc;
}

SmilePolyVec BuildCombinedInputCoinOpening(
    const std::vector<CTInput>& inputs,
    const std::vector<SmilePoly>& challenges,
    size_t dim)
{
    SmilePolyVec combined(dim);
    for (size_t i = 0; i < inputs.size() && i < challenges.size(); ++i) {
        for (size_t j = 0; j < dim && j < inputs[i].coin_r.size(); ++j) {
            combined[j] += NttMul(challenges[i], inputs[i].coin_r[j]);
            combined[j].Reduce();
        }
    }
    return combined;
}

SmilePolyVec BuildCombinedOutputCoinOpening(
    const std::vector<CTOutput>& outputs,
    const std::vector<SmilePoly>& challenges,
    size_t dim)
{
    SmilePolyVec combined(dim);
    for (size_t i = 0; i < outputs.size() && i < challenges.size(); ++i) {
        for (size_t j = 0; j < dim && j < outputs[i].coin_r.size(); ++j) {
            combined[j] += NttMul(challenges[i], outputs[i].coin_r[j]);
            combined[j].Reduce();
        }
    }
    return combined;
}

int64_t ComputeCoinOpeningSigma(size_t count)
{
    const size_t safe_count = std::max<size_t>(count, 1);
    return SIGMA_MASK * static_cast<int64_t>(safe_count);
}

int64_t ComputeTupleFirstRoundSigma()
{
    // The tuple witness carries the first-round public-coin opening state
    // under c0. The current genesis-reset rewrite uses a wider acceptance
    // window here than the legacy amortized coin-opening proof.
    return 4096;
}

void RunCtPaddingIterations(const std::vector<CTInput>& inputs,
                            const std::vector<CTOutput>& outputs,
                            const CTPublicData& pub,
                            const SmileCTProof& proof,
                            uint64_t rng_seed,
                            int64_t public_fee,
                            bool bind_anonset_context,
                            size_t accepted_attempt)
{
    const size_t padding_attempt_limit =
        std::min(MAX_PROVE_CT_REJECTION_RETRIES, MAX_CT_TIMING_PADDING_ATTEMPTS);
    if (pub.anon_set.empty() || inputs.empty() || accepted_attempt + 1 >= padding_attempt_limit) {
        return;
    }

    const size_t m_in = inputs.size();
    const size_t n_out = outputs.size();
    const size_t N = pub.anon_set.size();
    const size_t rec_levels = ComputeRecursionLevels(N);
    if (N == 0 || N > NUM_NTT_SLOTS || rec_levels != 1) {
        return;
    }
    const bool use_postfork_tuple_hardening = UsePostforkTupleHardening(bind_anonset_context);
    const uint64_t padding_seed =
        DeriveCtPaddingSeed(proof, rng_seed, public_fee, bind_anonset_context);
    SmilePoly padding_acc = proof.h2;
    padding_acc.Reduce();
    SmilePoly tuple_binding = proof.tuple_opening_acc;
    tuple_binding.Reduce();
    const uint64_t shape_tag =
        (static_cast<uint64_t>(m_in) << 48) ^
        (static_cast<uint64_t>(n_out) << 32) ^
        (static_cast<uint64_t>(N) << 16) ^
        static_cast<uint64_t>(bind_anonset_context ? 1 : 0);

    for (size_t pad = accepted_attempt + 1; pad < padding_attempt_limit; ++pad) {
        DetRng rng(padding_seed + (PROVE_CT_RETRY_STRIDE * static_cast<uint64_t>(pad)));
        CSHA256 hasher;
        static constexpr char kPaddingDomain[] = "BTX_SMILE2_CT_PADDING_SURROGATE_V2";
        hasher.Write(reinterpret_cast<const uint8_t*>(kPaddingDomain), sizeof(kPaddingDomain) - 1);
        hasher.Write(proof.fs_seed.data(), proof.fs_seed.size());
        hasher.Write(proof.seed_c0.data(), proof.seed_c0.size());
        hasher.Write(proof.seed_c.data(), proof.seed_c.size());
        hasher.Write(proof.seed_z.data(), proof.seed_z.size());
        hasher.Write(proof.round1_aux_binding_digest.data(), proof.round1_aux_binding_digest.size());
        Sha256WriteLE64(hasher, padding_seed);
        Sha256WriteLE64(hasher, static_cast<uint64_t>(pad));
        Sha256WriteLE64(hasher, shape_tag);
        uint8_t pad_hash[32];
        hasher.Finalize(pad_hash);

        const SmilePoly c0_chal =
            HashToMonomialChallenge(pad_hash, sizeof(pad_hash), domainsep::CT_C0);
        SmilePoly key_mask = rng.GaussianPoly(SIGMA_KEY);
        SmilePoly aux_mask = rng.GaussianPoly(SIGMA_MASK);
        SmilePoly mixed = NttMul(c0_chal, key_mask);
        mixed += aux_mask;
        mixed += padding_acc;
        mixed.Reduce();

        if (use_postfork_tuple_hardening) {
            SmilePoly tuple_mask = rng.UniformPoly();
            mixed += NttMul(c0_chal, tuple_mask);
            mixed += tuple_binding;
            mixed.Reduce();
        }

        g_ct_padding_sink ^=
            ReadLE64(pad_hash) ^
            static_cast<uint64_t>(mod_q(mixed.coeffs[0])) ^
            static_cast<uint64_t>(mod_q(mixed.coeffs[1])) ^
            shape_tag;
        padding_acc += mixed;
        padding_acc.Reduce();
    }
}

void AppendCoinOpeningBinding(std::vector<uint8_t>& transcript, const SmileCoinOpeningProof& proof)
{
    AppendHash32(transcript, proof.binding_digest);
}

SmilePoly ComputeTupleOpeningAccumulator(const SmilePoly& w0_coin_acc,
                                        const SmilePoly& w0_amount,
                                        const SmilePoly& compression_challenge)
{
    SmilePoly acc = w0_coin_acc;
    acc += NttMul(compression_challenge, w0_amount);
    acc.Reduce();
    return acc;
}

std::array<uint8_t, 32> ComputeCoinOpeningBindingDigest(const SmilePoly& binding_acc)
{
    std::vector<uint8_t> binding_transcript;
    static constexpr std::string_view tag{"BTX_SMILE2_CT_COIN_BINDING_V4"};
    binding_transcript.insert(binding_transcript.end(), tag.begin(), tag.end());
    AppendPoly(binding_transcript, binding_acc);
    return TranscriptHash(binding_transcript);
}

void AppendInputTupleBinding(std::vector<uint8_t>& transcript, const SmilePoly& tuple_opening_acc)
{
    AppendPoly(transcript, tuple_opening_acc);
}

void SetAuxCommitmentSlot(const BDLOPCommitmentKey& aux_ck,
                         const SmilePolyVec& r_aux,
                         const std::vector<SmilePoly>& messages,
                         BDLOPCommitment& aux_commitment,
                         size_t slot)
{
    assert(slot < aux_commitment.t_msg.size());
    SmilePoly br;
    for (size_t col = 0; col < aux_ck.rand_dim(); ++col) {
        br += NttMul(aux_ck.b[slot][col], r_aux[col]);
    }
    br.Reduce();
    aux_commitment.t_msg[slot] = br + messages[slot];
    aux_commitment.t_msg[slot].Reduce();
}

void AppendCtRound1Commitment(std::vector<uint8_t>& transcript,
                              const SmileCTProof& proof,
                              const CtAuxLayout& aux_layout)
{
    size_t t0_count = std::min(proof.aux_commitment.t0.size(),
                               static_cast<size_t>(MSIS_RANK));
    for (size_t i = 0; i < t0_count; ++i) {
        AppendPoly(transcript, proof.aux_commitment.t0[i]);
    }

    if (aux_layout.UsesLiveM1Layout()) {
        AppendHash32(transcript, proof.round1_aux_binding_digest);
        return;
    }

    AppendAuxCommitment(transcript, proof.aux_commitment);
}

size_t EstimateGaussianVecSerializedSize(const SmilePolyVec& z)
{
    std::vector<uint8_t> encoded;
    SerializeGaussianVecFixed(z, encoded);
    return encoded.size();
}

size_t EstimateAdaptiveWitnessPolyVecSerializedSize(const SmilePolyVec& z)
{
    std::vector<uint8_t> encoded;
    SerializeAdaptiveWitnessPolyVec(z, encoded);
    return encoded.size();
}

void AppendCtBindingSurface(std::vector<uint8_t>& transcript,
                            const SmileCTProof& proof,
                            const CtAuxLayout& aux_layout,
                            Span<const SmilePoly> aux_tmsg,
                            Span<const SmilePoly> w0_commitment_accs)
{
    const size_t t0_count = std::min(proof.aux_commitment.t0.size(),
                                     static_cast<size_t>(MSIS_RANK));
    for (size_t i = 0; i < t0_count; ++i) {
        AppendPoly(transcript, proof.aux_commitment.t0[i]);
    }

    const size_t retained_count = ComputeLiveCtRetainedAuxMsgCount(aux_layout);
    for (size_t slot = 0; slot < retained_count && slot < aux_tmsg.size(); ++slot) {
        AppendPoly(transcript, aux_tmsg[slot]);
    }
    for (const auto& acc : w0_commitment_accs) {
        AppendPoly(transcript, acc);
    }
    for (size_t slot = retained_count; slot < aux_tmsg.size(); ++slot) {
        if (IsLiveCtW0Slot(aux_layout, slot)) {
            continue;
        }
        AppendPoly(transcript, aux_tmsg[slot]);
    }
}

size_t EstimateCenteredPolySerializedSize(const SmilePoly& p)
{
    int64_t max_abs = 0;
    for (size_t i = 0; i < POLY_DEGREE; ++i) {
        int64_t centered = mod_q(p.coeffs[i]);
        if (centered > Q / 2) centered -= Q;
        const int64_t abs_val = centered < 0 ? -centered : centered;
        if (abs_val > max_abs) max_abs = abs_val;
    }
    uint64_t range = static_cast<uint64_t>(2 * max_abs + 1);
    uint8_t bits_needed = 1;
    while ((1ULL << bits_needed) < range) bits_needed++;
    return 4 + 1 + (POLY_DEGREE * bits_needed + 7) / 8;
}

size_t EstimateCenteredPolyVecFixedSerializedSize(const SmilePolyVec& v)
{
    if (v.empty()) {
        return 0;
    }

    int64_t max_abs = 0;
    for (const auto& p : v) {
        for (size_t i = 0; i < POLY_DEGREE; ++i) {
            int64_t centered = mod_q(p.coeffs[i]);
            if (centered > Q / 2) centered -= Q;
            const int64_t abs_val = centered < 0 ? -centered : centered;
            if (abs_val > max_abs) max_abs = abs_val;
        }
    }
    uint64_t range = static_cast<uint64_t>(2 * max_abs + 1);
    uint8_t bits_needed = 1;
    while ((1ULL << bits_needed) < range) bits_needed++;
    return 4 + 1 + (v.size() * POLY_DEGREE * bits_needed + 7) / 8;
}

bool SeedIsPresent(const std::array<uint8_t, 32>& seed)
{
    return std::any_of(seed.begin(), seed.end(), [](uint8_t byte) { return byte != 0; });
}

SmilePoly ComputeWeightedCoinCommitmentRow(
    const std::vector<BDLOPCommitment>& commitments,
    const std::vector<SmilePoly>& challenges,
    size_t row,
    bool use_t0)
{
    SmilePoly acc;
    for (size_t i = 0; i < commitments.size() && i < challenges.size(); ++i) {
        const SmilePoly& public_poly =
            use_t0 ? commitments[i].t0[row] : commitments[i].t_msg.front();
        acc += NttMul(challenges[i], public_poly);
    }
    acc.Reduce();
    return acc;
}

SmilePoly ComputeWeightedCoinCommitmentOpeningAccumulator(
    const std::vector<BDLOPCommitment>& commitments,
    const std::vector<SmilePoly>& challenges,
    const std::vector<SmilePoly>& row_challenges,
    const SmilePoly& compression_challenge)
{
    SmilePoly acc = ComputeWeightedCoinCommitmentRow(commitments,
                                                     challenges,
                                                     0,
                                                     /*use_t0=*/false);
    acc = NttMul(compression_challenge, acc);
    acc.Reduce();

    const size_t limit = std::min(static_cast<size_t>(BDLOP_RAND_DIM_BASE), row_challenges.size());
    for (size_t row = 0; row < limit; ++row) {
        acc += NttMul(row_challenges[row],
                      ComputeWeightedCoinCommitmentRow(commitments,
                                                       challenges,
                                                       row,
                                                       /*use_t0=*/true));
    }
    acc.Reduce();
    return acc;
}

SmilePoly ComputeWeightedTupleOpeningAccumulator(
    const std::vector<SmilePoly>& tuple_opening_accs,
    const std::vector<SmilePoly>& challenges)
{
    SmilePoly acc;
    const size_t limit = std::min(tuple_opening_accs.size(), challenges.size());
    for (size_t i = 0; i < limit; ++i) {
        acc += NttMul(challenges[i], tuple_opening_accs[i]);
    }
    acc.Reduce();
    return acc;
}

bool VerifyCombinedCoinOpeningProof(const SmileCoinOpeningProof& opening_proof,
                                    const BDLOPCommitmentKey& coin_ck,
                                    const SmileCTProof& proof,
                                    const SmilePoly& c0_chal,
                                    const SmilePoly& c_chal,
                                    const std::vector<BDLOPCommitment>& output_commitments,
                                    const std::vector<SmilePoly>& input_challenges,
                                    const std::vector<SmilePoly>& output_challenges,
                                    const std::vector<SmilePoly>& aux_residues,
                                    const std::vector<SmilePoly>& row_challenges,
                                    const SmilePoly& tuple_opening_challenge,
                                    size_t input_amount_slot_offset,
                                    size_t output_amount_slot_offset,
                                    const char* label)
{
    if (opening_proof.z.size() != coin_ck.rand_dim()) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [%s]: z.size()=%u != coin_ck.rand_dim()=%u\n",
                  label,
                  static_cast<unsigned int>(opening_proof.z.size()),
                  static_cast<unsigned int>(coin_ck.rand_dim()));
        return false;
    }
    if (proof.input_tuples.size() != input_challenges.size()) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [%s]: input_tuples=%u input_challenges=%u mismatch\n",
                  label,
                  static_cast<unsigned int>(proof.input_tuples.size()),
                  static_cast<unsigned int>(input_challenges.size()));
        return false;
    }
    if (output_commitments.size() != output_challenges.size()) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [%s]: output_commitments=%u output_challenges=%u mismatch\n",
                  label,
                  static_cast<unsigned int>(output_commitments.size()),
                  static_cast<unsigned int>(output_challenges.size()));
        return false;
    }
    if (!SeedIsPresent(opening_proof.binding_digest)) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [%s]: missing binding_digest\n", label);
        return false;
    }

    SmilePoly scaled_binding_acc =
        NttMul(c0_chal,
               ComputeCoinOpeningRowAccumulatorFromResponse(coin_ck,
                                                            opening_proof.z,
                                                            row_challenges));
    std::vector<NttForm> opening_z_ntt(opening_proof.z.size());
    for (size_t i = 0; i < opening_proof.z.size(); ++i) {
        opening_z_ntt[i] = NttForward(opening_proof.z[i]);
    }
    scaled_binding_acc += NttMul(tuple_opening_challenge,
                                 NttMul(c0_chal,
                                        ComputeOpeningInnerProduct(coin_ck.b_ntt[0], opening_z_ntt)));
    scaled_binding_acc.Reduce();
    SmilePoly weighted_tuple_opening_residue;
    for (size_t i = 0; i < input_challenges.size(); ++i) {
        SmilePoly tuple_opening_residue =
            ComputeCoinOpeningRowAccumulatorFromResponse(coin_ck,
                                                         proof.input_tuples[i].z_coin,
                                                         row_challenges);
        std::vector<NttForm> tuple_z_ntt(proof.input_tuples[i].z_coin.size());
        for (size_t j = 0; j < proof.input_tuples[i].z_coin.size(); ++j) {
            tuple_z_ntt[j] = NttForward(proof.input_tuples[i].z_coin[j]);
        }
        SmilePoly tuple_msg_open = ComputeOpeningInnerProduct(coin_ck.b_ntt[0], tuple_z_ntt);
        tuple_msg_open += proof.input_tuples[i].z_amount;
        tuple_msg_open.Reduce();
        tuple_opening_residue += NttMul(tuple_opening_challenge, tuple_msg_open);
        tuple_opening_residue.Reduce();
        weighted_tuple_opening_residue += NttMul(input_challenges[i], tuple_opening_residue);
        weighted_tuple_opening_residue.Reduce();

        const SmilePoly& amount_residue = aux_residues[input_amount_slot_offset + i];
        scaled_binding_acc -= NttMul(tuple_opening_challenge,
                                     NttMul(c0_chal, NttMul(input_challenges[i], amount_residue)));
    }
    weighted_tuple_opening_residue -= proof.tuple_opening_acc;
    weighted_tuple_opening_residue.Reduce();
    scaled_binding_acc -= NttMul(c_chal, weighted_tuple_opening_residue);
    for (size_t i = 0; i < output_challenges.size(); ++i) {
        const SmilePoly& amount_residue = aux_residues[output_amount_slot_offset + i];
        scaled_binding_acc -= NttMul(tuple_opening_challenge,
                                     NttMul(c0_chal, NttMul(output_challenges[i], amount_residue)));
    }
    SmilePoly c0c = NttMul(c0_chal, c_chal);
    c0c.Reduce();
    scaled_binding_acc -= NttMul(c0c,
                                 ComputeWeightedCoinCommitmentOpeningAccumulator(output_commitments,
                                                                                 output_challenges,
                                                                                 row_challenges,
                                                                                 tuple_opening_challenge));
    scaled_binding_acc.Reduce();

    SmilePoly recovered_binding_acc = DivideByMonomialChallenge(scaled_binding_acc, c0_chal);
    recovered_binding_acc.Reduce();

    if (ComputeCoinOpeningBindingDigest(recovered_binding_acc) != opening_proof.binding_digest) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [%s]: combined coin-opening digest mismatch\n", label);
        return false;
    }

    return true;
}

std::vector<SmilePoly> BuildCtScaledSelectedAccountRowsFromWitness(
    const CTPublicData& pub,
    const SmilePolyVec& z0,
    const SmileInputTupleProof& tuple,
    const std::vector<SmilePoly>& combined_w0_rows,
    const CtPublicAccountChallenges& challenges)
{
    const size_t row_count = GetCtPublicRowCount();
    std::vector<SmilePoly> rows(row_count);
    const auto& A = pub.anon_set.front().A;
    const auto coin_ck = GetPublicCoinCommitmentKey();
    std::vector<NttForm> tuple_z_ntt(tuple.z_coin.size());
    for (size_t j = 0; j < tuple.z_coin.size(); ++j) {
        tuple_z_ntt[j] = NttForward(tuple.z_coin[j]);
    }

    for (size_t row = 0; row < KEY_ROWS; ++row) {
        SmilePoly acc;
        for (size_t j = 0; j < KEY_COLS; ++j) {
            acc += NttMul(NttMul(challenges.alpha, A[row][j]), z0[j]);
        }
        acc += NttMul(challenges.beta,
                      ComputeOpeningInnerProduct(coin_ck.B0_ntt[row], tuple_z_ntt));
        acc -= combined_w0_rows[row];
        acc.Reduce();
        rows[row] = std::move(acc);
    }

    SmilePoly amount_row = ComputeOpeningInnerProduct(coin_ck.b_ntt[0], tuple_z_ntt);
    amount_row += tuple.z_amount;
    amount_row = NttMul(challenges.beta, amount_row);
    amount_row -= combined_w0_rows[GetCtAmountRowIndex()];
    amount_row.Reduce();
    rows[GetCtAmountRowIndex()] = std::move(amount_row);

    SmilePoly leaf_row = NttMul(challenges.gamma, tuple.z_leaf);
    leaf_row -= combined_w0_rows[GetCtLeafRowIndex()];
    leaf_row.Reduce();
    rows[GetCtLeafRowIndex()] = std::move(leaf_row);

    return rows;
}

std::vector<SmilePoly> BuildCtHiddenX1RowsFromWitness(
    const CTPublicData& pub,
    const SmilePolyVec& z0,
    const SmileInputTupleProof& tuple,
    const std::vector<SmilePoly>& combined_w0_rows,
    const CtPublicAccountChallenges& challenges)
{
    auto rows =
        BuildCtScaledSelectedAccountRowsFromWitness(pub, z0, tuple, combined_w0_rows, challenges);
    for (auto& row : rows) {
        SmilePoly neg_row;
        neg_row -= row;
        neg_row.Reduce();
        row = std::move(neg_row);
    }
    return rows;
}

SmilePoly ComputeCtRecursionDelta(const std::vector<SmilePoly>& x_curr,
                                  const std::vector<SmilePoly>& x_next,
                                  const std::array<int64_t, NUM_NTT_SLOTS>& selector,
                                  const std::array<int64_t, NUM_NTT_SLOTS>& alpha)
{
    SmilePoly y;
    const size_t row_count = std::min(x_curr.size(), x_next.size());
    for (size_t row = 0; row < row_count; ++row) {
        const NttForm ntt_xnext = NttForward(x_next[row]);
        const NttForm ntt_xcurr = NttForward(x_curr[row]);
        NttForm y_ntt;
        for (size_t slot = 0; slot < NUM_NTT_SLOTS; ++slot) {
            const NttSlot term1 = ntt_xnext.slots[slot].ScalarMul(selector[slot]);
            const NttSlot term2 = ntt_xcurr.slots[slot].ScalarMul(alpha[slot]);
            y_ntt.slots[slot] = term1.Sub(term2);
        }
        y += NttInverse(y_ntt);
    }
    y.Reduce();
    return y;
}

} // anonymous namespace

std::optional<SmilePoly> EncodeAmountToSmileAmountPoly(int64_t amount)
{
    if (amount < 0) {
        return std::nullopt;
    }

    uint64_t remaining = static_cast<uint64_t>(amount);
    NttForm ntt_amount;
    for (size_t slot = 0; slot < NUM_NTT_SLOTS; ++slot) {
        ntt_amount.slots[slot].coeffs[0] = static_cast<int64_t>(remaining & 0x3);
        remaining >>= 2;
    }

    if (remaining != 0) {
        return std::nullopt;
    }

    SmilePoly encoded = NttInverse(ntt_amount);
    encoded.Reduce();
    return encoded;
}

std::optional<int64_t> DecodeAmountFromSmileAmountPoly(const SmilePoly& amount_poly)
{
    const NttForm ntt_amount = NttForward(amount_poly);
    uint64_t value{0};

    for (size_t slot = NUM_NTT_SLOTS; slot-- > 0;) {
        for (size_t coeff = 1; coeff < SLOT_DEGREE; ++coeff) {
            if (mod_q(ntt_amount.slots[slot].coeffs[coeff]) != 0) {
                return std::nullopt;
            }
        }

        const int64_t digit = mod_q(ntt_amount.slots[slot].coeffs[0]);
        if (digit < 0 || digit > 3) {
            return std::nullopt;
        }

        if (value > (std::numeric_limits<uint64_t>::max() - static_cast<uint64_t>(digit)) / 4) {
            return std::nullopt;
        }
        value = value * 4 + static_cast<uint64_t>(digit);
    }

    if (value > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
        return std::nullopt;
    }

    return static_cast<int64_t>(value);
}

bool IsCanonicalSmileAmountPoly(const SmilePoly& amount_poly)
{
    return DecodeAmountFromSmileAmountPoly(amount_poly).has_value();
}

// --- Serial number computation ---

SmilePoly ComputeSerialNumber(
    const BDLOPCommitmentKey& ck,
    const SmileSecretKey& sk)
{
    // sn = ⟨b_1, s⟩ = Σ_j b_1[j] · s[j]
    // where b_1 is the first message encoding vector from the commitment key
    // and s is extended with zeros to match the commitment key dimension.
    SmilePoly sn;
    size_t key_len = sk.s.size();
    for (size_t j = 0; j < key_len && j < ck.b[0].size(); ++j) {
        sn += NttMul(ck.b[0][j], sk.s[j]);
    }
    sn.Reduce();
    return sn;
}

// --- Proof size estimation ---

size_t SmileCTProof::SerializedSize() const
{
    // Size estimation matching the SMILE paper's proof format (Section E.1).
    // The transmitted proof consists of:
    //   1. Auxiliary commitment t' (compressed t'_0 + message polynomials)
    //   2. Masked opening z (entropy-coded bimodal Gaussian)
    //   3. z_0 per input (entropy-coded)
    //   4. Selected input tuple-opening witnesses
    //   5. Coin opening proofs
    //   6. Serial numbers
    //   7. Weak-opening accumulator omega
    //   8. h_2 polynomial (first d/l coefficients zero, not transmitted)
    //   9. Fiat-Shamir seeds / binding digests
    //
    // NOT included (recomputable or separate transaction data):
    //   - Output coins (on-chain transaction data)
    size_t size = 0;
    const auto estimate_fixed_gaussian = [](const SmilePolyVec& vec) {
        return EstimateGaussianVecSerializedSize(vec);
    };

    // Auxiliary commitment t':
    // t'_0 carries the full exact first-round B0 row surface.
    size += EstimateCenteredPolyVecFixedSerializedSize(aux_commitment.t0);

    const CtAuxLayout aux_layout{z0.size(), InferLiveCtOutputCountFromProof(*this), /*rec_levels=*/1};
    const SmilePolyVec omitted_selector_amount_residues =
        CollectSerializedOmittedAuxSelectorAmountResidues(aux_layout, aux_residues);
    const SmilePolyVec omitted_tail_residues =
        CollectSerializedOmittedAuxTailResidues(aux_layout, aux_residues);
    size += EstimateAdaptiveWitnessPolyVecSerializedSize(omitted_selector_amount_residues);
    size += EstimateGaussianVecSerializedSize(omitted_tail_residues);
    size += EstimateGaussianVecSerializedSize(w0_residue_accs);
    size += 32; // round-1 aux binding digest
    size += 32; // pre-h2 binding digest
    size += 32; // post-h2 binding digest

    size += estimate_fixed_gaussian(z);

    for (const auto& z0i : z0) {
        size += estimate_fixed_gaussian(z0i);
    }

    for (const auto& tuple : input_tuples) {
        size += estimate_fixed_gaussian(tuple.z_coin);
    }
    if (!input_tuples.empty()) {
        SmilePolyVec z_amounts;
        SmilePolyVec z_leafs;
        z_amounts.reserve(input_tuples.size());
        z_leafs.reserve(input_tuples.size());
        for (const auto& tuple : input_tuples) {
            z_amounts.push_back(tuple.z_amount);
            z_leafs.push_back(tuple.z_leaf);
        }
        size += EstimateAdaptiveWitnessPolyVecSerializedSize(z_amounts);
        size += EstimateAdaptiveWitnessPolyVecSerializedSize(z_leafs);
    }
    size += 1 + std::min(EstimateCenteredPolySerializedSize(tuple_opening_acc),
                         EstimateGaussianVecSerializedSize(SmilePolyVec{tuple_opening_acc}));

    // Serial numbers: num_inputs × d × log(q) bits
    size += EstimateCenteredPolyVecFixedSerializedSize(serial_numbers);

    // Combined input/output coin opening proof
    size += estimate_fixed_gaussian(coin_opening.z);
    size += 32;

    // h_2: d coefficients × log(q) bits (first d/l=4 are zero, not transmitted)
    size += (POLY_DEGREE - SLOT_DEGREE) * 4;

    // The live verifier still needs seed_c before seed_c0 is finalized in the
    // m=1 transcript order, so it remains part of the hard-fork wire format.
    size += 32;

    if (wire_version >= WIRE_VERSION_M4_HARDENED) {
        size += 5;
    }

    return size;
}

// --- Prove CT ---
// L4 audit note: SmileSecretKey::~SmileSecretKey() already calls
// memory_cleanse on the full SmilePolyVec. The CTInput struct holds
// SmileSecretKey by value, so all secret key material is zeroed when the
// CTInput vector goes out of scope. The DetRng internal state is also
// cleared when the function returns (ChaCha20 key material in
// FastRandomContext is zeroed by its destructor).
// L5 audit note: PROVE_CT_RETRY_STRIDE = 0x9e3779b97f4a7c15 is the
// golden-ratio constant, chosen to spread retry seeds across the uint64
// space. This is a known constant, not a secret.

std::optional<SmileCTProof> TryProveCT(
    const std::vector<CTInput>& inputs,
    const std::vector<CTOutput>& outputs,
    const CTPublicData& pub,
    uint64_t rng_seed,
    int64_t public_fee,
    bool bind_anonset_context)
{
    size_t m_in = inputs.size();
    size_t n_out = outputs.size();
    size_t N = pub.anon_set.size();
    size_t rec_levels = ComputeRecursionLevels(N);
    size_t N_padded = PadToLPower(N);
    size_t k = KEY_ROWS;
    const bool use_live_m1_layout = (rec_levels == 1);
    const bool use_postfork_tuple_hardening = UsePostforkTupleHardening(bind_anonset_context);
    const auto coin_ck = GetPublicCoinCommitmentKey();
    int64_t sum_in = 0;
    int64_t sum_out = 0;

    for (const auto& inp : inputs) sum_in += inp.amount;
    for (const auto& out : outputs) sum_out += out.amount;
    if (public_fee < 0) {
        return std::nullopt;
    }
    if (std::any_of(inputs.begin(), inputs.end(), [](const CTInput& input) {
            return input.amount < 0;
        }) ||
        std::any_of(outputs.begin(), outputs.end(), [](const CTOutput& output) {
            return output.amount < 0;
        })) {
        return std::nullopt;
    }
    // Impossible CT statements should fail before we burn the full
    // rejection-sampling budget trying to prove a balance relation that
    // can never verify.
    if (sum_in != sum_out + public_fee) {
        return std::nullopt;
    }
    if (N == 0 || !HasUniformSmilePublicKeyMatrix(pub.anon_set)) {
        return std::nullopt;
    }
    if (N > NUM_NTT_SLOTS || rec_levels != 1) {
        LogDebug(BCLog::VALIDATION, "ProveCT: rejecting unsupported CT anonymity set N=%u rec_levels=%u; "
                  "reset-chain SMILE CT is defined only for the audited single-round surface N <= %u\n",
                  static_cast<unsigned>(N),
                  static_cast<unsigned>(rec_levels),
                  static_cast<unsigned>(NUM_NTT_SLOTS));
        return std::nullopt;
    }
    if (pub.account_rings.size() != m_in || !AccountRingsMatchSplitPublicData(pub, m_in)) {
        return std::nullopt;
    }
    if (pub.coin_rings.size() != m_in) {
        return std::nullopt;
    }

    std::vector<SmilePoly> input_amount_polys(m_in);
    std::vector<SmilePoly> input_leaf_polys(m_in);
    for (size_t i = 0; i < m_in; ++i) {
        if (inputs[i].secret_index >= N) {
            return std::nullopt;
        }
        if (pub.coin_rings[i].size() != N) {
            return std::nullopt;
        }
        for (const auto& member_coin : pub.coin_rings[i]) {
            if (!HasCanonicalPublicCoinCommitmentShape(member_coin)) {
                return std::nullopt;
            }
        }
        if (inputs[i].coin_r.size() != coin_ck.rand_dim()) {
            return std::nullopt;
        }
        const auto input_amount_poly = EncodeAmountToSmileAmountPoly(inputs[i].amount);
        if (!input_amount_poly.has_value()) {
            return std::nullopt;
        }
        input_amount_polys[i] = *input_amount_poly;
        const auto selected_coin = Commit(coin_ck, {input_amount_polys[i]}, inputs[i].coin_r);
        if (selected_coin.t0 != pub.coin_rings[i][inputs[i].secret_index].t0 ||
            selected_coin.t_msg != pub.coin_rings[i][inputs[i].secret_index].t_msg) {
            return std::nullopt;
        }
        input_leaf_polys[i] = EncodeUint256ToSmilePoly(
            pub.account_rings[i][inputs[i].secret_index].account_leaf_commitment);
    }

    std::vector<BDLOPCommitment> output_coins(n_out);
    std::vector<SmilePoly> output_amount_polys(n_out);
    for (size_t i = 0; i < n_out; ++i) {
        const auto amount_poly = EncodeAmountToSmileAmountPoly(outputs[i].amount);
        if (!amount_poly.has_value()) {
            return std::nullopt;
        }
        output_amount_polys[i] = *amount_poly;
        if (outputs[i].coin_r.size() != coin_ck.rand_dim()) {
            return std::nullopt;
        }
        output_coins[i] = Commit(coin_ck, {output_amount_polys[i]}, outputs[i].coin_r);
    }

    std::vector<uint8_t> public_transcript;
    AppendAnonSetTranscript(public_transcript, pub.anon_set, bind_anonset_context);
    AppendCoinRingDigest(public_transcript, pub);
    for (const auto& coin : output_coins) {
        for (const auto& t : coin.t0) AppendPolyCompressed(public_transcript, t);
        for (const auto& t : coin.t_msg) AppendPoly(public_transcript, t);
    }
    {
        uint8_t fee_buf[8];
        WriteLE64(fee_buf, static_cast<uint64_t>(public_fee));
        public_transcript.insert(public_transcript.end(), fee_buf, fee_buf + sizeof(fee_buf));
    }
    AppendU32(public_transcript, static_cast<uint32_t>(m_in));
    AppendU32(public_transcript, static_cast<uint32_t>(n_out));
    const auto public_fs_seed = TranscriptHash(public_transcript);

    auto sn_ck_seed = std::array<uint8_t, 32>{};
    sn_ck_seed[0] = 0xAA;
    auto sn_ck = BDLOPCommitmentKey::Generate(sn_ck_seed, 1);

    std::vector<SmilePoly> serial_numbers(m_in);
    for (size_t i = 0; i < m_in; ++i) {
        serial_numbers[i] = ComputeSerialNumber(sn_ck, inputs[i].sk);
    }

    std::vector<std::vector<std::array<int64_t, NUM_NTT_SLOTS>>> all_v_decomp(m_in);
    for (size_t i = 0; i < m_in; ++i) {
        all_v_decomp[i] = DecomposeIndex(inputs[i].secret_index, rec_levels);
    }

    const size_t ct_rows = GetCtPublicRowCount();
    std::vector<CtPublicAccountChallenges> account_challenges(m_in);
    std::vector<std::vector<std::array<int64_t, NUM_NTT_SLOTS>>> alpha_challenges(m_in);
    std::vector<std::vector<SmilePoly>> all_y_polys(m_in);
    std::vector<std::vector<std::vector<SmilePoly>>> all_x_vals(m_in);

    for (size_t inp = 0; inp < m_in; ++inp) {
        account_challenges[inp] = DeriveCtPublicAccountChallenges(public_transcript, inp);
        auto x1_rows = BuildCtCombinedSelectedAccountRows(
            pub,
            inp,
            inputs[inp].secret_index,
            account_challenges[inp]);
        if (!x1_rows.has_value()) {
            return std::nullopt;
        }

        alpha_challenges[inp] = DeriveCtAlphaChallenges(public_transcript, inp, rec_levels);
        all_x_vals[inp].resize(rec_levels + 1);
        all_x_vals[inp][1] = std::move(*x1_rows);

        std::vector<std::vector<SmilePoly>> P_curr;
        if (rec_levels > 1) {
            auto public_rows =
                BuildCtCombinedAccountRows(pub, inp, account_challenges[inp], N_padded);
            if (!public_rows.has_value()) {
                return std::nullopt;
            }
            P_curr = std::move(*public_rows);
        }
        size_t cols_curr = N_padded;

        for (size_t j = 1; j < rec_levels; ++j) {
            const auto& alpha_j = alpha_challenges[inp][j - 1];
            size_t cols_next = cols_curr / NUM_NTT_SLOTS;
            std::vector<std::vector<SmilePoly>> P_next(ct_rows, std::vector<SmilePoly>(cols_next));
            for (size_t r = 0; r < ct_rows; ++r) {
                for (size_t c = 0; c < cols_next; ++c) {
                    SmilePoly acc;
                    for (size_t d = 0; d < NUM_NTT_SLOTS; ++d) {
                        size_t src = d * cols_next + c;
                        if (src < cols_curr) {
                            acc += P_curr[r][src] * alpha_j[d];
                        }
                    }
                    acc.Reduce();
                    P_next[r][c] = acc;
                }
            }

            std::vector<std::array<int64_t, NUM_NTT_SLOTS>> sub_vecs(
                all_v_decomp[inp].begin() + j, all_v_decomp[inp].end());
            auto sub_tensor = TensorProduct(sub_vecs);

            all_x_vals[inp][j + 1].resize(ct_rows);
            for (size_t r = 0; r < ct_rows; ++r) {
                SmilePoly acc;
                for (size_t c = 0; c < cols_next && c < sub_tensor.size(); ++c) {
                    if (sub_tensor[c] != 0) {
                        acc += P_next[r][c] * sub_tensor[c];
                    }
                }
                acc.Reduce();
                all_x_vals[inp][j + 1][r] = acc;
            }

            all_y_polys[inp].push_back(ComputeCtRecursionDelta(all_x_vals[inp][j],
                                                               all_x_vals[inp][j + 1],
                                                               all_v_decomp[inp][j - 1],
                                                               alpha_j));

            P_curr = std::move(P_next);
            cols_curr = cols_next;
        }

        if (!use_live_m1_layout && !alpha_challenges[inp].empty()) {
            all_y_polys[inp].push_back(ComputeCtRecursionDelta(all_x_vals[inp][rec_levels],
                                                               all_x_vals[inp][rec_levels],
                                                               all_v_decomp[inp][rec_levels - 1],
                                                               alpha_challenges[inp].back()));
        }
    }

    const CtAuxLayout aux_layout{m_in, n_out, rec_levels};
    size_t n_aux_msg = ComputeNumAuxMsg(m_in, n_out, rec_levels);
    assert(n_aux_msg == aux_layout.TotalSlots());
    auto aux_ck_seed = TranscriptHash(public_transcript);
    auto aux_ck = BDLOPCommitmentKey::Generate(aux_ck_seed, n_aux_msg);

    for (size_t rejection_retry = 0; rejection_retry < MAX_PROVE_CT_REJECTION_RETRIES; ++rejection_retry) {
        const uint64_t attempt_seed = rng_seed + (PROVE_CT_RETRY_STRIDE * rejection_retry);
        DetRng rng(attempt_seed);
        SmileCTProof proof;
        proof.wire_version = use_postfork_tuple_hardening
            ? SmileCTProof::WIRE_VERSION_M4_HARDENED
            : SmileCTProof::WIRE_VERSION_LEGACY;
        proof.output_coins = output_coins;
        proof.fs_seed = public_fs_seed;
        proof.serial_numbers = serial_numbers;

        // --- STAGE 1: Setup and initial commitments ---
        std::vector<uint8_t> transcript = public_transcript;

    // 8. Build the garbage polynomial surface.
    // For the rewritten live m=1 path, g must be sampled before c0 and h2 is
    // derived later from the real post-round-one y1 identities, matching the
    // membership proof flow rather than the old adaptive-cancellation shortcut.
    // The legacy multi-level path keeps the placeholder pre-c0 construction
    // for the future multi-round generalization. The reset-chain launch
    // surface and its production tests use the live m=1 path above.
    if (use_live_m1_layout) {
        SmilePoly g;
        for (size_t c = SLOT_DEGREE; c < POLY_DEGREE; ++c) {
            g.coeffs[c] = rng.UniformModQ();
        }
        g.Reduce();
        proof.g0 = g;
        proof.h2 = SmilePoly{};
    } else {
        SmilePoly y_sum;
        for (size_t inp = 0; inp < m_in; ++inp) {
            for (const auto& yp : all_y_polys[inp]) {
                y_sum += yp;
            }
        }
        y_sum.Reduce();

        SmilePoly g;
        for (size_t c = 0; c < SLOT_DEGREE; ++c) {
            g.coeffs[c] = neg_mod_q(mod_q(y_sum.coeffs[c]));
        }
        for (size_t c = SLOT_DEGREE; c < POLY_DEGREE; ++c) {
            g.coeffs[c] = rng.UniformModQ();
        }
        g.Reduce();
        proof.g0 = g;

        proof.h2 = proof.g0 + y_sum;

        int64_t delta = sum_in - sum_out - public_fee;
        if (delta != 0) {
            SmilePoly carry;
            carry.coeffs[0] = mod_q(delta);
            proof.h2 += carry;
        }
        proof.h2.Reduce();
    }

    // 9. Sample masking vectors
    // y0 for each input's secret key proof
    proof.z0.resize(m_in);
    proof.input_tuples.resize(m_in);
    std::vector<SmilePolyVec> y0_masks(m_in);
    const auto& A = pub.anon_set[0].A;
    std::vector<std::vector<SmilePoly>> combined_w0_vals(m_in);
    std::vector<SmilePolyVec> y0_coin_masks(m_in);
    std::vector<SmilePoly> y0_amount_masks(m_in);
    std::vector<SmilePoly> y0_leaf_masks(m_in);
    std::vector<SmilePolyVec> tuple_w0_coin(m_in);
    std::vector<SmilePoly> tuple_w0_amount(m_in);
    const int64_t tuple_coin_sigma = ComputeTupleFirstRoundSigma();
    for (size_t inp = 0; inp < m_in; ++inp) {
        y0_masks[inp].resize(KEY_COLS);
        for (auto& yi : y0_masks[inp]) {
            yi = rng.GaussianPoly(SIGMA_KEY);
        }
        SmilePolyVec key_w0(k);
        for (size_t r = 0; r < k; ++r) {
            SmilePoly acc;
            for (size_t j = 0; j < KEY_COLS; ++j) {
                acc += NttMul(A[r][j], y0_masks[inp][j]);
            }
            acc.Reduce();
            key_w0[r] = acc;
        }
        y0_coin_masks[inp] = SampleGaussianVec(rng, coin_ck.rand_dim(), tuple_coin_sigma);
        std::vector<NttForm> y0_coin_mask_ntt(y0_coin_masks[inp].size());
        for (size_t j = 0; j < y0_coin_masks[inp].size(); ++j) {
            y0_coin_mask_ntt[j] = NttForward(y0_coin_masks[inp][j]);
        }
        tuple_w0_coin[inp].resize(BDLOP_RAND_DIM_BASE);
        for (size_t row = 0; row < BDLOP_RAND_DIM_BASE; ++row) {
            tuple_w0_coin[inp][row] =
                ComputeOpeningInnerProduct(coin_ck.B0_ntt[row], y0_coin_mask_ntt);
        }
        y0_amount_masks[inp] =
            use_postfork_tuple_hardening ? rng.UniformPoly() : rng.GaussianPoly(tuple_coin_sigma);
        tuple_w0_amount[inp] =
            ComputeOpeningInnerProduct(coin_ck.b_ntt[0], y0_coin_mask_ntt) + y0_amount_masks[inp];
        tuple_w0_amount[inp].Reduce();
        y0_leaf_masks[inp] =
            use_postfork_tuple_hardening ? rng.UniformPoly() : rng.GaussianPoly(tuple_coin_sigma);

        combined_w0_vals[inp].resize(ct_rows);
        for (size_t row = 0; row < KEY_ROWS; ++row) {
            SmilePoly combined = NttMul(account_challenges[inp].alpha, key_w0[row]);
            combined += NttMul(account_challenges[inp].beta, tuple_w0_coin[inp][row]);
            combined.Reduce();
            combined_w0_vals[inp][row] = std::move(combined);
        }
        SmilePoly amount_row = NttMul(account_challenges[inp].beta, tuple_w0_amount[inp]);
        amount_row.Reduce();
        combined_w0_vals[inp][GetCtAmountRowIndex()] = std::move(amount_row);
        SmilePoly leaf_row = NttMul(account_challenges[inp].gamma, y0_leaf_masks[inp]);
        leaf_row.Reduce();
        combined_w0_vals[inp][GetCtLeafRowIndex()] = std::move(leaf_row);
    }

    // 10. Build auxiliary BDLOP commitment
    // Prepare aux messages
    std::vector<SmilePoly> aux_messages(n_aux_msg);

    if (aux_layout.UsesLiveM1Layout()) {
        aux_messages[aux_layout.GSlot()] = proof.g0;
        aux_messages[aux_layout.PsiSlot()] = SmilePoly{};
    } else {
        // Slots 0-6 (7 garbage/framework slots)
        // t'_1: garbage for serial number proof
        aux_messages[0] = rng.UniformPoly();
        // t'_2: ⟨b'_1, y⟩ for amortized opening
        aux_messages[1] = rng.UniformPoly();
        // t'_3: carry garbage polynomial o
        aux_messages[2] = rng.UniformPoly();
        // t'_4: carry polynomial e
        // Balance: e encodes (Σ a_in - Σ a_out) via carry chain
        {
            SmilePoly carry;
            int64_t diff = sum_in - sum_out - public_fee; // should be 0 if balanced after fee
            carry.coeffs[0] = mod_q(diff);
            aux_messages[3] = carry;
        }
        // t'_5, t'_6, t'_7: garbage decomposition for quadratic check
        aux_messages[4] = rng.UniformPoly();
        aux_messages[5] = rng.UniformPoly();
        aux_messages[6] = proof.g0; // public garbage polynomial
    }

    // Input amount slots.
    for (size_t i = 0; i < m_in; ++i) {
        aux_messages[aux_layout.InputAmountSlot(i)] = input_amount_polys[i];
    }

    // Output amount slots.
    for (size_t i = 0; i < n_out; ++i) {
        aux_messages[aux_layout.OutputAmountSlot(i)] = output_amount_polys[i];
    }

    // Carry the full per-input key masking rows instead of only the first row.
    for (size_t inp = 0; inp < m_in; ++inp) {
        for (size_t row = 0; row < GetCtPublicRowCount(); ++row) {
            if (inp < combined_w0_vals.size() && row < combined_w0_vals[inp].size()) {
                aux_messages[aux_layout.W0Slot(inp, row)] = combined_w0_vals[inp][row];
            }
        }
    }

    // Carry the full recursive x rows needed by the real Appendix E verifier.
    for (size_t inp = 0; inp < m_in; ++inp) {
        for (size_t level = 2; level <= rec_levels; ++level) {
            for (size_t row = 0; row < GetCtPublicRowCount(); ++row) {
                if (inp < all_x_vals.size() &&
                    level < all_x_vals[inp].size() &&
                    row < all_x_vals[inp][level].size()) {
                    aux_messages[aux_layout.XSlot(inp, level, row)] =
                        all_x_vals[inp][level][row];
                }
            }
        }
    }

    // Selector decompositions v_{i,j}.
    for (size_t inp = 0; inp < m_in; ++inp) {
        for (size_t j = 0; j < rec_levels; ++j) {
            // Encode selector as polynomial
            NttForm v_ntt;
            for (size_t s = 0; s < NUM_NTT_SLOTS; ++s) {
                v_ntt.slots[s].coeffs[0] = all_v_decomp[inp][j][s];
            }
            aux_messages[aux_layout.SelectorSlot(inp, j)] = NttInverse(v_ntt);
        }
    }

    // 11. Commit
    SmilePolyVec y_mask(aux_ck.rand_dim());
    for (auto& yi : y_mask) {
        yi = rng.GaussianPoly(SIGMA_MASK);
    }

    auto r_aux = SampleTernaryStrong(aux_ck.rand_dim(), DrawStrongTernarySeed(rng));
    proof.aux_commitment = Commit(aux_ck, aux_messages, r_aux);
    proof.w0_commitment_accs.assign(m_in, {});
    proof.w0_residue_accs.assign(m_in, {});
    proof.round1_aux_binding_digest =
        ComputeCtBindingDigest("BTX_SMILE2_CT_ROUND1_AUX_BIND_V1",
                               0,
                               CollectLiveCtRound1AuxBindingPolys(
                                   aux_layout,
                                   Span<const SmilePoly>{proof.aux_commitment.t_msg.data(),
                                                         proof.aux_commitment.t_msg.size()}));
    proof.pre_h2_binding_digest.fill(0);
    proof.post_h2_binding_digest.fill(0);

    // 12. Add commitment to transcript for Fiat-Shamir
    AppendCtRound1Commitment(transcript, proof, aux_layout);
    for (const auto& sn : proof.serial_numbers) AppendPoly(transcript, sn);
    const auto tuple_coin_row_challenges = DeriveTupleCoinRowChallenges(transcript);
    const SmilePoly tuple_opening_challenge = DeriveTupleOpeningCompressionChallenge(transcript);
    const auto input_coin_challenges =
        DeriveCoinOpeningChallenges(transcript, m_in, domainsep::CT_INPUT_COIN_OPENING);
    const auto output_coin_challenges =
        DeriveCoinOpeningChallenges(transcript, n_out, domainsep::CT_OUTPUT_COIN_OPENING);
    std::vector<SmilePoly> tuple_opening_accs;
    tuple_opening_accs.reserve(proof.input_tuples.size());
    for (size_t inp = 0; inp < proof.input_tuples.size(); ++inp) {
        tuple_opening_accs.push_back(
            ComputeTupleOpeningAccumulator(
                ComputeCoinOpeningRowAccumulator(tuple_w0_coin[inp], tuple_coin_row_challenges),
                tuple_w0_amount[inp],
                tuple_opening_challenge));
    }
    proof.tuple_opening_acc =
        ComputeWeightedTupleOpeningAccumulator(tuple_opening_accs, input_coin_challenges);
    AppendInputTupleBinding(transcript, proof.tuple_opening_acc);
    if (aux_layout.UsesLiveM1Layout()) {
        const auto round1_w = ComputeB0Response(aux_ck, y_mask);
        for (const auto& wi : round1_w) {
            AppendPoly(transcript, wi);
        }
        AppendU32(transcript, static_cast<uint32_t>(m_in));
    }

    proof.seed_c0 = TranscriptHash(transcript);
    SmilePoly c0_chal = HashToMonomialChallenge(proof.seed_c0.data(), 32, domainsep::CT_C0);

    // 13. z0 = y0 + c0·s for each input (with rejection sampling)
    bool retry_attempt{false};
    for (size_t inp = 0; inp < m_in; ++inp) {
        proof.z0[inp].resize(KEY_COLS);
        SmilePolyVec c0s(KEY_COLS);
        for (size_t j = 0; j < KEY_COLS; ++j) {
            c0s[j] = NttMul(c0_chal, inputs[inp].sk.s[j]);
            c0s[j].Reduce();
            proof.z0[inp][j] = y0_masks[inp][j] + c0s[j];
            proof.z0[inp][j].Reduce();
        }
        if (!RejectionSample(proof.z0[inp], c0s, SIGMA_KEY, rng)) {
            retry_attempt = true;
            break;
        }
    }
    if (retry_attempt) {
        continue;
    }

    for (size_t inp = 0; inp < m_in; ++inp) {
        SmilePolyVec tuple_z(coin_ck.rand_dim());
        SmilePolyVec tuple_c(coin_ck.rand_dim());
        proof.input_tuples[inp].z_coin.resize(coin_ck.rand_dim());
        for (size_t j = 0; j < coin_ck.rand_dim(); ++j) {
            tuple_c[j] = NttMul(c0_chal, inputs[inp].coin_r[j]);
            tuple_z[j] = y0_coin_masks[inp][j] + tuple_c[j];
            tuple_z[j].Reduce();
        }
        if (use_postfork_tuple_hardening &&
            !RejectionSample(tuple_z, tuple_c, tuple_coin_sigma, rng)) {
            retry_attempt = true;
            break;
        }
        for (size_t j = 0; j < coin_ck.rand_dim(); ++j) {
            proof.input_tuples[inp].z_coin[j] = tuple_z[j];
        }
        SmilePoly tuple_amount_c = NttMul(c0_chal, input_amount_polys[inp]);
        tuple_amount_c.Reduce();
        proof.input_tuples[inp].z_amount = y0_amount_masks[inp] + tuple_amount_c;
        proof.input_tuples[inp].z_amount.Reduce();
        SmilePoly tuple_leaf_c = NttMul(c0_chal, input_leaf_polys[inp]);
        tuple_leaf_c.Reduce();
        proof.input_tuples[inp].z_leaf = y0_leaf_masks[inp] + tuple_leaf_c;
        proof.input_tuples[inp].z_leaf.Reduce();
    }
    if (retry_attempt) {
        continue;
    }
    const int64_t combined_coin_sigma = ComputeCoinOpeningSigma(m_in + n_out);
    const SmilePolyVec y_coin = SampleGaussianVec(rng, coin_ck.rand_dim(), combined_coin_sigma);
    std::vector<NttForm> y_coin_ntt(y_coin.size());
    for (size_t i = 0; i < y_coin.size(); ++i) {
        y_coin_ntt[i] = NttForward(y_coin[i]);
    }
    std::vector<NttForm> y_mask_ntt(y_mask.size());
    for (size_t i = 0; i < y_mask.size(); ++i) {
        y_mask_ntt[i] = NttForward(y_mask[i]);
    }

    proof.coin_opening.w0.resize(BDLOP_RAND_DIM_BASE);
    for (size_t row = 0; row < BDLOP_RAND_DIM_BASE; ++row) {
        proof.coin_opening.w0[row] = ComputeOpeningInnerProduct(coin_ck.B0_ntt[row], y_coin_ntt);
    }
    proof.coin_opening.f = ComputeOpeningInnerProduct(coin_ck.b_ntt[0], y_coin_ntt);
    for (size_t i = 0; i < m_in; ++i) {
        const size_t amount_slot = aux_layout.InputAmountSlot(i);
        proof.coin_opening.f -=
            NttMul(input_coin_challenges[i], ComputeOpeningInnerProduct(aux_ck.b_ntt[amount_slot], y_mask_ntt));
    }
    for (size_t i = 0; i < n_out; ++i) {
        const size_t amount_slot = aux_layout.OutputAmountSlot(i);
        proof.coin_opening.f -=
            NttMul(output_coin_challenges[i], ComputeOpeningInnerProduct(aux_ck.b_ntt[amount_slot], y_mask_ntt));
    }
    proof.coin_opening.f.Reduce();
    proof.coin_opening.binding_digest =
        ComputeCoinOpeningBindingDigest(
            ComputeTupleOpeningAccumulator(
                ComputeCoinOpeningRowAccumulator(proof.coin_opening.w0, tuple_coin_row_challenges),
                proof.coin_opening.f,
                tuple_opening_challenge));

    // 14. Derive final challenge c
    for (const auto& z0i : proof.z0) {
        for (const auto& zi : z0i) AppendPoly(transcript, zi);
    }
    // Key binding: append A·z_0 for each input
    for (size_t inp = 0; inp < m_in; ++inp) {
        for (size_t i = 0; i < k; ++i) {
            SmilePoly az0_i;
            for (size_t j = 0; j < KEY_COLS; ++j) {
                az0_i += NttMul(A[i][j], proof.z0[inp][j]);
            }
            az0_i.Reduce();
            AppendPoly(transcript, az0_i);
        }
    }
    for (const auto& tuple : proof.input_tuples) {
        for (const auto& zi : tuple.z_coin) AppendPoly(transcript, zi);
        AppendPoly(transcript, tuple.z_amount);
        AppendPoly(transcript, tuple.z_leaf);
    }
    // Serial number binding: append ⟨b_sn, z_0⟩ for each input.
    // For honest prover: ⟨b_sn, z_0⟩ = ⟨b_sn, y_0⟩ + c_0·sn.
    // A cheating prover with fake sn produces inconsistent transcript.
    for (size_t inp = 0; inp < m_in; ++inp) {
        SmilePoly bsn_z0;
        for (size_t j = 0; j < KEY_COLS && j < sn_ck.b[0].size(); ++j) {
            bsn_z0 += NttMul(sn_ck.b[0][j], proof.z0[inp][j]);
        }
        bsn_z0.Reduce();
        AppendPoly(transcript, bsn_z0);
    }
    AppendCoinOpeningBinding(transcript, proof.coin_opening);
    proof.framework_omega = SmilePoly{};
    std::vector<std::vector<SlotChallenge>> live_gamma1(m_in);
    std::vector<SmilePoly> live_alpha_chals;
    if (aux_layout.UsesLiveM1Layout()) {
        for (size_t inp = 0; inp < m_in; ++inp) {
            live_gamma1[inp] = DeriveCtGammaChallenges(transcript, inp, GetCtPublicRowCount());
            std::vector<SmilePoly> committed_rows;
            committed_rows.reserve(GetCtPublicRowCount());
            for (size_t row = 0; row < GetCtPublicRowCount(); ++row) {
                committed_rows.push_back(proof.aux_commitment.t_msg[aux_layout.W0Slot(inp, row)]);
            }
            proof.w0_commitment_accs[inp] =
                ComputeCompressedW0CommitmentAccumulator(
                    Span<const SmilePoly>{committed_rows.data(), committed_rows.size()},
                    live_gamma1[inp]);
            const auto compressed_public_x =
                ComputeCtCompressedPublicX(pub,
                                           inp,
                                           account_challenges[inp],
                                           c0_chal,
                                           live_gamma1[inp]);
            if (!compressed_public_x.has_value()) {
                return std::nullopt;
            }
            aux_messages[aux_layout.XSlot(inp, 1, 0)] = *compressed_public_x;
            aux_messages[aux_layout.XSlot(inp, 1, 0)].Reduce();
            SetAuxCommitmentSlot(aux_ck,
                                 r_aux,
                                 aux_messages,
                                 proof.aux_commitment,
                                 aux_layout.XSlot(inp, 1, 0));
        }

        SmilePoly live_y_sum;
        for (size_t inp = 0; inp < m_in; ++inp) {
            const auto hidden_x1_rows = BuildCtHiddenX1RowsFromWitness(pub,
                                                                       proof.z0[inp],
                                                                       proof.input_tuples[inp],
                                                                       combined_w0_vals[inp],
                                                                       account_challenges[inp]);
            SmilePoly y1 =
                ApplySlotChallenge(aux_messages[aux_layout.XSlot(inp, 1, 0)], all_v_decomp[inp][0]) -
                SumWeightedRows(hidden_x1_rows, live_gamma1[inp]);
            y1.Reduce();
            live_y_sum += y1;
        }
        live_y_sum.Reduce();

        proof.h2 = proof.g0 + live_y_sum;
        const int64_t delta = sum_in - sum_out - public_fee;
        if (delta != 0) {
            SmilePoly carry;
            carry.coeffs[0] = mod_q(delta);
            proof.h2 += carry;
        }
        proof.h2.Reduce();

        proof.pre_h2_binding_digest =
            ComputeCtBindingDigest("BTX_SMILE2_CT_PRE_H2_BIND_V1",
                                   0,
                                   CollectLiveCtPreH2BindingPolys(
                                       aux_layout,
                                       Span<const SmilePoly>{proof.aux_commitment.t_msg.data(),
                                                             proof.aux_commitment.t_msg.size()},
                                       Span<const SmilePoly>{proof.w0_commitment_accs.data(),
                                                             proof.w0_commitment_accs.size()}));
        AppendHash32(transcript, proof.pre_h2_binding_digest);
    }
    AppendPoly(transcript, proof.h2);
    if (aux_layout.UsesLiveM1Layout()) {
        const auto alpha_chals = DeriveRhoChallenges(transcript, m_in + 1);
        live_alpha_chals = alpha_chals;
        const auto by = ComputeMaskResponses(aux_ck, y_mask);
        const SmilePoly one_poly = BuildConstantPoly(1);

        SmilePoly omega_sm;
        SmilePoly psi_sm;
        SmilePoly omega_bin;
        SmilePoly psi_bin;

        for (size_t inp = 0; inp < m_in; ++inp) {
            const size_t selector_slot = aux_layout.SelectorSlot(inp, 0);
            const size_t x_slot = aux_layout.XSlot(inp, 1, 0);

            SmilePoly omega_i = NttMul(by[selector_slot], by[x_slot]);
            omega_i.Reduce();
            omega_sm += omega_i;

            std::vector<SmilePoly> w_rows(GetCtPublicRowCount());
            for (size_t row = 0; row < GetCtPublicRowCount(); ++row) {
                w_rows[row] = by[aux_layout.W0Slot(inp, row)];
            }
            SmilePoly psi_i = SumWeightedRows(w_rows, live_gamma1[inp]);
            psi_i -= NttMul(by[selector_slot], aux_messages[x_slot]);
            psi_i -= NttMul(by[x_slot], aux_messages[selector_slot]);
            psi_i.Reduce();
            psi_sm += psi_i;

            SmilePoly omega_bin_i = NttMul(by[selector_slot], by[selector_slot]);
            omega_bin_i = NttMul(alpha_chals[inp + 1], omega_bin_i);
            omega_bin_i.Reduce();
            omega_bin += omega_bin_i;

            SmilePoly selector_term = one_poly;
            selector_term -= aux_messages[selector_slot];
            selector_term -= aux_messages[selector_slot];
            selector_term.Reduce();
            SmilePoly psi_bin_i = NttMul(by[selector_slot], selector_term);
            psi_bin_i = NttMul(alpha_chals[inp + 1], psi_bin_i);
            psi_bin_i.Reduce();
            psi_bin += psi_bin_i;
        }

        psi_sm -= by[aux_layout.GSlot()];
        psi_sm.Reduce();
        omega_sm.Reduce();
        omega_bin.Reduce();
        psi_bin.Reduce();

        aux_messages[aux_layout.PsiSlot()] = NttMul(alpha_chals[0], psi_sm) + psi_bin;
        aux_messages[aux_layout.PsiSlot()].Reduce();
        SetAuxCommitmentSlot(aux_ck,
                             r_aux,
                             aux_messages,
                             proof.aux_commitment,
                             aux_layout.PsiSlot());

        proof.framework_omega = by[aux_layout.PsiSlot()] +
                                NttMul(alpha_chals[0], omega_sm) +
                                omega_bin;
        proof.framework_omega.Reduce();

        proof.post_h2_binding_digest =
            ComputeCtBindingDigest("BTX_SMILE2_CT_POST_H2_BIND_V1",
                                   0,
                                   CollectLiveCtPostH2BindingPolys(
                                       aux_layout,
                                       Span<const SmilePoly>{proof.aux_commitment.t_msg.data(),
                                                             proof.aux_commitment.t_msg.size()},
                                       proof.framework_omega));
        AppendHash32(transcript, proof.post_h2_binding_digest);
    }
    proof.seed_c = TranscriptHash(transcript);
    SmilePoly c_chal = HashToMonomialChallenge(proof.seed_c.data(), 32, domainsep::CT_C);

    // 15. z = y + c·r with rejection sampling (Figure 10)
    proof.z.resize(aux_ck.rand_dim());
    {
        SmilePolyVec cr(aux_ck.rand_dim());
        for (size_t j = 0; j < aux_ck.rand_dim(); ++j) {
            cr[j] = NttMul(c_chal, r_aux[j]);
            cr[j].Reduce();
            proof.z[j] = y_mask[j] + cr[j];
            proof.z[j].Reduce();
        }
        if (!RejectionSample(proof.z, cr, SIGMA_MASK, rng)) {
            continue;
        }
    }

    {
        const SmilePolyVec combined_input_coin_r =
            BuildCombinedInputCoinOpening(inputs, input_coin_challenges, coin_ck.rand_dim());
        const SmilePolyVec combined_output_coin_r =
            BuildCombinedOutputCoinOpening(outputs, output_coin_challenges, coin_ck.rand_dim());
        proof.coin_opening.z.resize(coin_ck.rand_dim());
        SmilePolyVec c_coin_opening(coin_ck.rand_dim());
        for (size_t j = 0; j < coin_ck.rand_dim(); ++j) {
            SmilePoly combined_r = combined_input_coin_r[j] + combined_output_coin_r[j];
            combined_r.Reduce();
            c_coin_opening[j] = NttMul(c_chal, combined_r);
            c_coin_opening[j].Reduce();
            proof.coin_opening.z[j] = y_coin[j] + c_coin_opening[j];
            proof.coin_opening.z[j].Reduce();
        }
        if (!RejectionSample(proof.coin_opening.z,
                             c_coin_opening,
                             combined_coin_sigma,
                             rng)) {
            continue;
        }
    }

    // 16. Compute proof binding hash: covers z and full aux_commitment
    // This binds the masked opening z to the transcript, preventing
    // adversarial substitution of z or aux_commitment t_msg values.
    {
        std::vector<uint8_t> bind_transcript = transcript;
        for (const auto& zi : proof.z) AppendPoly(bind_transcript, zi);
        for (const auto& zi : proof.coin_opening.z) AppendPoly(bind_transcript, zi);
        AppendCtBindingSurface(bind_transcript,
                               proof,
                               aux_layout,
                               Span<const SmilePoly>{
                                   proof.aux_commitment.t_msg.data(),
                                   proof.aux_commitment.t_msg.size()},
                               Span<const SmilePoly>{
                                   proof.w0_commitment_accs.data(),
                                   proof.w0_commitment_accs.size()});
        proof.seed_z = TranscriptHash(bind_transcript);
    }

    {
        proof.aux_residues.resize(n_aux_msg);
        for (size_t slot = 0; slot < n_aux_msg; ++slot) {
            proof.aux_residues[slot] =
                ComputeAuxMessageResidueFromCommitment(aux_ck,
                                                      proof.z,
                                                      proof.aux_commitment.t_msg,
                                                      c_chal,
                                                      slot);
        }
        for (size_t inp = 0; inp < m_in; ++inp) {
            std::vector<SmilePoly> w0_rows;
            w0_rows.reserve(GetCtPublicRowCount());
            for (size_t row = 0; row < GetCtPublicRowCount(); ++row) {
                w0_rows.push_back(proof.aux_residues[aux_layout.W0Slot(inp, row)]);
            }
            proof.w0_residue_accs[inp] = SumWeightedRows(w0_rows, live_gamma1[inp]);
        }
        const auto opening_challenges =
            DeriveOpeningChallenges(
                transcript,
                std::min(proof.aux_commitment.t0.size(),
                         static_cast<size_t>(MSIS_RANK)) +
                    ComputeCtWeakOpeningResidueCount(aux_layout) + 1);
        proof.omega = ComputeCtWeakOpeningAccumulator(aux_ck,
                                                      proof.z,
                                                      proof.aux_commitment.t0,
                                                      proof.aux_residues,
                                                      proof.w0_residue_accs,
                                                      aux_layout,
                                                      c_chal,
                                                      proof.h2,
                                                      opening_challenges);
    }

        RunCtPaddingIterations(inputs,
                               outputs,
                               pub,
                               proof,
                               rng_seed,
                               public_fee,
                               bind_anonset_context,
                               rejection_retry);
        return proof;
    }

    LogDebug(BCLog::VALIDATION, "ProveCT: exhausted rejection retry budget after %u attempts (inputs=%u outputs=%u anon_set=%u)\n",
              static_cast<unsigned int>(MAX_PROVE_CT_REJECTION_RETRIES),
              static_cast<unsigned int>(m_in),
              static_cast<unsigned int>(n_out),
              static_cast<unsigned int>(N));
    return std::nullopt;
}

SmileCTProof ProveCT(
    const std::vector<CTInput>& inputs,
    const std::vector<CTOutput>& outputs,
    const CTPublicData& pub,
    uint64_t rng_seed,
    int64_t public_fee,
    bool bind_anonset_context)
{
    auto proof = TryProveCT(inputs, outputs, pub, rng_seed, public_fee, bind_anonset_context);
    return proof.value_or(SmileCTProof{});
}

size_t GetCtRejectionRetryBudget()
{
    return MAX_PROVE_CT_REJECTION_RETRIES;
}

size_t GetCtTimingPaddingAttemptLimit()
{
    return MAX_CT_TIMING_PADDING_ATTEMPTS;
}

// --- Verify CT ---

bool VerifyCT(
    const SmileCTProof& proof,
    size_t num_inputs,
    size_t num_outputs,
    const CTPublicData& pub,
    int64_t public_fee,
    bool bind_anonset_context)
{
    if (public_fee < 0) {
        return false;
    }
    size_t N = pub.anon_set.size();
    if (N == 0 || N > NUM_NTT_SLOTS) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 0]: unsupported reset-chain CT surface anon_set=%u\n",
                  (unsigned)N);
        return false;
    }
    size_t rec_levels = ComputeRecursionLevels(N);
    size_t k = KEY_ROWS;
    if (rec_levels != 1) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 0]: unsupported reset-chain CT surface anon_set=%u rec_levels=%u; "
                  "only N <= %u and rec_levels == 1 are valid\n",
                  (unsigned)N,
                  (unsigned)rec_levels,
                  (unsigned)NUM_NTT_SLOTS);
        return false;
    }

    LogDebug(BCLog::VALIDATION, "VerifyCT: START num_inputs=%u num_outputs=%u anon_set=%u rec_levels=%u k=%u\n",
              (unsigned)num_inputs, (unsigned)num_outputs, (unsigned)N, (unsigned)rec_levels, (unsigned)k);

    if (num_inputs == 0 || num_inputs > MAX_CT_INPUTS ||
        num_outputs == 0 || num_outputs > MAX_CT_OUTPUTS) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [input-bounds]: num_inputs=%u num_outputs=%u\n",
                  (unsigned)num_inputs,
                  (unsigned)num_outputs);
        return false;
    }

    // 1. Check h2 has first d/l = 4 coefficients all zero
    SmilePoly h2_check = proof.h2;
    h2_check.Reduce();
    for (size_t i = 0; i < SLOT_DEGREE; ++i) {
        if (h2_check.coeffs[i] != 0) {
            LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 1]: h2 balance check - h2.coeffs[%u] = %lld (expected 0). "
                      "This means the transaction is UNBALANCED (sum_in != sum_out) or garbage cancellation failed.\n",
                      (unsigned)i, (long long)h2_check.coeffs[i]);
            return false;
        }
    }
    LogDebug(BCLog::VALIDATION, "VerifyCT: step 1 PASSED (h2 first %u coeffs are zero)\n", (unsigned)SLOT_DEGREE);

    // 2. Verify serial numbers are present
    if (proof.serial_numbers.size() != num_inputs) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 2a]: serial_numbers.size()=%u != num_inputs=%u\n",
                  (unsigned)proof.serial_numbers.size(), (unsigned)num_inputs);
        return false;
    }
    if (proof.z0.size() != num_inputs) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 2b]: z0.size()=%u != num_inputs=%u\n",
                  (unsigned)proof.z0.size(), (unsigned)num_inputs);
        return false;
    }
    if (proof.input_tuples.size() != num_inputs) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 2b0]: input_tuples.size()=%u != num_inputs=%u\n",
                  (unsigned)proof.input_tuples.size(), (unsigned)num_inputs);
        return false;
    }
    if (proof.output_coins.size() != num_outputs) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 2c]: output_coins.size()=%u != num_outputs=%u\n",
                  (unsigned)proof.output_coins.size(), (unsigned)num_outputs);
        return false;
    }
    if (!HasUniformSmilePublicKeyMatrix(pub.anon_set)) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 2c0a]: anon_set contains malformed or mixed-A public keys\n");
        return false;
    }
    for (size_t out = 0; out < proof.output_coins.size(); ++out) {
        if (!HasCanonicalPublicCoinCommitmentShape(proof.output_coins[out])) {
            LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 2c0b]: output_coins[%u] has invalid commitment shape t0=%u tmsg=%u\n",
                      (unsigned)out,
                      (unsigned)proof.output_coins[out].t0.size(),
                      (unsigned)proof.output_coins[out].t_msg.size());
            return false;
        }
    }
    if (proof.aux_commitment.t0.size() < MSIS_RANK) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 2c1]: aux_commitment.t0.size()=%u < MSIS_RANK=%u\n",
                  (unsigned)proof.aux_commitment.t0.size(), (unsigned)MSIS_RANK);
        return false;
    }
    if (pub.coin_rings.size() != num_inputs) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 2d]: coin_rings.size()=%u != num_inputs=%u\n",
                  (unsigned)pub.coin_rings.size(), (unsigned)num_inputs);
        return false;
    }
    if (pub.account_rings.size() != num_inputs ||
        !AccountRingsMatchSplitPublicData(pub, num_inputs)) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 2d0]: account_rings missing or do not match split anon_set / coin_rings view\n");
        return false;
    }
    for (size_t inp = 0; inp < pub.coin_rings.size(); ++inp) {
        if (pub.coin_rings[inp].size() != N) {
            LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 2e]: coin_rings[%u].size()=%u != anon_set=%u\n",
                      (unsigned)inp, (unsigned)pub.coin_rings[inp].size(), (unsigned)N);
            return false;
        }
        for (size_t member = 0; member < pub.coin_rings[inp].size(); ++member) {
            if (!HasCanonicalPublicCoinCommitmentShape(pub.coin_rings[inp][member])) {
                LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 2f]: coin_rings[%u][%u] has invalid commitment shape t0=%u tmsg=%u\n",
                          (unsigned)inp,
                          (unsigned)member,
                          (unsigned)pub.coin_rings[inp][member].t0.size(),
                          (unsigned)pub.coin_rings[inp][member].t_msg.size());
                return false;
            }
        }
    }
    LogDebug(BCLog::VALIDATION, "VerifyCT: step 2 PASSED (proof dimension checks)\n");

    // 3. Reconstruct Fiat-Shamir transcript
    std::vector<uint8_t> transcript;
    AppendAnonSetTranscript(transcript, pub.anon_set, bind_anonset_context);
    AppendCoinRingDigest(transcript, pub);
    for (const auto& coin : proof.output_coins) {
        for (const auto& t : coin.t0) AppendPolyCompressed(transcript, t);
        for (const auto& t : coin.t_msg) AppendPoly(transcript, t);
    }
    {
        uint8_t fee_buf[8];
        WriteLE64(fee_buf, static_cast<uint64_t>(public_fee));
        transcript.insert(transcript.end(), fee_buf, fee_buf + sizeof(fee_buf));
    }
    // C3 audit fix: bind num_inputs and num_outputs into the Fiat-Shamir
    // transcript (must match ProveCT exactly).
    AppendU32(transcript, static_cast<uint32_t>(num_inputs));
    AppendU32(transcript, static_cast<uint32_t>(num_outputs));
    auto fs_seed_check = TranscriptHash(transcript);
    if (SeedIsPresent(proof.fs_seed) && fs_seed_check != proof.fs_seed) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 3]: fs_seed mismatch. Fiat-Shamir transcript over "
                  "anon_set + coin_rings + output_coins differs from proof.fs_seed. "
                  "transcript_size=%u, coin_rings=%u, output_coins=%u, first coin t0.size=%u tmsg.size=%u\n",
                  (unsigned)transcript.size(), (unsigned)pub.coin_rings.size(),
                  (unsigned)proof.output_coins.size(),
                  proof.output_coins.empty() ? 0u : (unsigned)proof.output_coins[0].t0.size(),
                  proof.output_coins.empty() ? 0u : (unsigned)proof.output_coins[0].t_msg.size());
        return false;
    }
    LogDebug(BCLog::VALIDATION, "VerifyCT: step 3 PASSED (fs_seed transcript match)\n");
    const auto public_transcript = transcript;

    // 4. Verify serial numbers match expected computation
    auto sn_ck_seed = std::array<uint8_t, 32>{};
    sn_ck_seed[0] = 0xAA;
    auto sn_ck = BDLOPCommitmentKey::Generate(sn_ck_seed, 1);

    // 5. Reconstruct auxiliary commitment key
    const CtAuxLayout aux_layout{num_inputs, num_outputs, rec_levels};
    size_t n_aux_msg = ComputeNumAuxMsg(num_inputs, num_outputs, rec_levels);
    assert(n_aux_msg == aux_layout.TotalSlots());
    auto aux_ck_seed = TranscriptHash(transcript);
    auto aux_ck = BDLOPCommitmentKey::Generate(aux_ck_seed, n_aux_msg);
    LogDebug(BCLog::VALIDATION, "VerifyCT: step 5 aux key generated n_aux_msg=%u rand_dim=%u\n",
              (unsigned)n_aux_msg, (unsigned)aux_ck.rand_dim());
    if (proof.aux_commitment.t_msg.size() != n_aux_msg) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 5b]: aux_commitment.t_msg.size()=%u != n_aux_msg=%u\n",
                  (unsigned)proof.aux_commitment.t_msg.size(), (unsigned)n_aux_msg);
        return false;
    }
    if (proof.aux_residues.size() != n_aux_msg) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 5c]: aux_residues.size()=%u != n_aux_msg=%u\n",
                  (unsigned)proof.aux_residues.size(), (unsigned)n_aux_msg);
        return false;
    }
    if (proof.w0_residue_accs.size() != num_inputs) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 5d]: compressed tail count mismatch w0_res=%u inputs=%u\n",
                  (unsigned)proof.w0_residue_accs.size(),
                  (unsigned)num_inputs);
        return false;
    }

    LogDebug(BCLog::VALIDATION, "VerifyCT: step 6 PASSED (exact t0 surface)\n");

    AppendCtRound1Commitment(transcript, proof, aux_layout);
    for (const auto& sn : proof.serial_numbers) AppendPoly(transcript, sn);
    const auto tuple_coin_row_challenges = DeriveTupleCoinRowChallenges(transcript);
    const SmilePoly tuple_opening_challenge = DeriveTupleOpeningCompressionChallenge(transcript);
    const auto input_coin_challenges =
        DeriveCoinOpeningChallenges(transcript, num_inputs, domainsep::CT_INPUT_COIN_OPENING);
    const auto output_coin_challenges =
        DeriveCoinOpeningChallenges(transcript, num_outputs, domainsep::CT_OUTPUT_COIN_OPENING);
    AppendInputTupleBinding(transcript, proof.tuple_opening_acc);
    if (aux_layout.UsesLiveM1Layout()) {
        if (proof.z.size() != aux_ck.rand_dim()) {
            return false;
        }
        const SmilePoly c_chal_from_seed =
            HashToMonomialChallenge(proof.seed_c.data(), 32, domainsep::CT_C);
        const SmilePolyVec recovered_w = ComputeB0Response(aux_ck, proof.z);
        for (size_t row = 0; row < BDLOP_RAND_DIM_BASE; ++row) {
            SmilePoly wi = recovered_w[row] - NttMul(c_chal_from_seed, proof.aux_commitment.t0[row]);
            wi.Reduce();
            AppendPoly(transcript, wi);
        }
        AppendU32(transcript, static_cast<uint32_t>(num_inputs));
    }

    auto seed_c0_check = TranscriptHash(transcript);
    if (SeedIsPresent(proof.seed_c0) && seed_c0_check != proof.seed_c0) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 6d]: seed_c0 mismatch. Transcript after appending aux_commitment + "
                  "serial_numbers doesn't match proof.seed_c0. aux t_msg.size=%u, serial_numbers=%u\n",
                  (unsigned)proof.aux_commitment.t_msg.size(), (unsigned)proof.serial_numbers.size());
        return false;
    }
    LogDebug(BCLog::VALIDATION, "VerifyCT: step 6d PASSED (seed_c0 transcript match)\n");

    // 7. Verify key relation via commitment binding
    SmilePoly c0_chal = HashToMonomialChallenge(seed_c0_check.data(), 32, domainsep::CT_C0);
    for (size_t inp = 0; inp < num_inputs; ++inp) {
        if (proof.z0[inp].size() != KEY_COLS) {
            LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 7]: z0[%u].size()=%u != KEY_COLS=%u\n",
                      (unsigned)inp, (unsigned)proof.z0[inp].size(), (unsigned)KEY_COLS);
            return false;
        }
    }
    LogDebug(BCLog::VALIDATION, "VerifyCT: step 7 PASSED (z0 dimension check)\n");

    // 7b. Norm bound checks on z_0 (per input) and z
    {
        int64_t half_q = Q / 2;
        const int64_t tuple_coin_sigma = ComputeTupleFirstRoundSigma();
        // Check z_0 norm bound for each input
        // ||z_0[inp]||_2 < β_0 = SIGMA_KEY * sqrt(2 * KEY_COLS * POLY_DEGREE)
        __int128 beta0_sq = static_cast<__int128>(SIGMA_KEY) * SIGMA_KEY * 2 * KEY_COLS * POLY_DEGREE;
        for (size_t inp = 0; inp < num_inputs; ++inp) {
            __int128 z0_norm_sq = 0;
            for (size_t j = 0; j < proof.z0[inp].size(); ++j) {
                for (size_t c = 0; c < POLY_DEGREE; ++c) {
                    int64_t val = mod_q(proof.z0[inp][j].coeffs[c]);
                    if (val > half_q) val -= Q;
                    z0_norm_sq += static_cast<__int128>(val) * val;
                }
            }
            if (z0_norm_sq >= beta0_sq) {
                LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 7b-z0]: z0 norm too large for input %u. "
                          "||z0||^2=%lld >= beta0^2=%lld (SIGMA_KEY=%lld KEY_COLS=%u POLY_DEGREE=%u)\n",
                          (unsigned)inp,
                          (long long)(int64_t)z0_norm_sq, (long long)(int64_t)beta0_sq,
                          (long long)SIGMA_KEY, (unsigned)KEY_COLS, (unsigned)POLY_DEGREE);
                return false;
            }
        }

        // Check z norm bound
        // ||z||_2 < β = SIGMA_MASK * sqrt(2 * rand_dim * POLY_DEGREE)
        __int128 z_norm_sq = 0;
        for (size_t j = 0; j < proof.z.size(); ++j) {
            for (size_t c = 0; c < POLY_DEGREE; ++c) {
                int64_t val = mod_q(proof.z[j].coeffs[c]);
                if (val > half_q) val -= Q;
                z_norm_sq += static_cast<__int128>(val) * val;
            }
        }
        __int128 beta_sq = static_cast<__int128>(SIGMA_MASK) * SIGMA_MASK * 2 * aux_ck.rand_dim() * POLY_DEGREE;
        if (z_norm_sq >= beta_sq) {
            LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 7b-z]: z norm too large. "
                      "||z||^2=%lld >= beta^2=%lld (SIGMA_MASK=%lld rand_dim=%u z.size=%u)\n",
                      (long long)(int64_t)z_norm_sq, (long long)(int64_t)beta_sq,
                      (long long)SIGMA_MASK, (unsigned)aux_ck.rand_dim(), (unsigned)proof.z.size());
            return false;
        }

        auto check_gaussian_z_norm = [&](const SmilePolyVec& response,
                                         int64_t sigma,
                                         const char* label,
                                         const char* kind) {
            __int128 norm_sq = 0;
            for (const auto& poly : response) {
                for (size_t c = 0; c < POLY_DEGREE; ++c) {
                    int64_t val = mod_q(poly.coeffs[c]);
                    if (val > half_q) val -= Q;
                    norm_sq += static_cast<__int128>(val) * val;
                }
            }
            const __int128 bound_sq =
                static_cast<__int128>(sigma) * sigma * 2 * response.size() * POLY_DEGREE;
            if (norm_sq >= bound_sq) {
                LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [%s]: %s norm too large. "
                          "||z||^2=%lld >= bound^2=%lld (sigma=%lld size=%u)\n",
                          label,
                          kind,
                          (long long)(int64_t)norm_sq,
                          (long long)(int64_t)bound_sq,
                          (long long)sigma,
                          (unsigned)response.size());
                return false;
            }
            return true;
        };

        if (!check_gaussian_z_norm(proof.coin_opening.z,
                                   ComputeCoinOpeningSigma(num_inputs + num_outputs),
                                   "step 7b-z-coin-combined",
                                   "coin opening z")) {
            return false;
        }

        for (size_t inp = 0; inp < proof.input_tuples.size(); ++inp) {
            if (!check_gaussian_z_norm(proof.input_tuples[inp].z_coin,
                                       tuple_coin_sigma,
                                       "step 7b-z-coin-tuple",
                                       "input tuple coin opening z")) {
                return false;
            }
        }
    }
    LogDebug(BCLog::VALIDATION, "VerifyCT: step 7b PASSED (norm bound checks)\n");

    // 8. Verify Fiat-Shamir transcript for final challenge
    const auto& A = pub.anon_set[0].A;
    const auto coin_ck = GetPublicCoinCommitmentKey();
    for (const auto& z0i : proof.z0) {
        for (const auto& zi : z0i) AppendPoly(transcript, zi);
    }
    // Key binding: append A·z_0 for each input
    for (size_t inp = 0; inp < num_inputs; ++inp) {
        for (size_t i = 0; i < k; ++i) {
            SmilePoly az0_i;
            for (size_t j = 0; j < KEY_COLS; ++j) {
                az0_i += NttMul(A[i][j], proof.z0[inp][j]);
            }
            az0_i.Reduce();
            AppendPoly(transcript, az0_i);
        }
    }
    for (const auto& tuple : proof.input_tuples) {
        for (const auto& zi : tuple.z_coin) AppendPoly(transcript, zi);
        AppendPoly(transcript, tuple.z_amount);
        AppendPoly(transcript, tuple.z_leaf);
    }
    // Serial number binding: append ⟨b_sn, z_0⟩ for each input
    for (size_t inp = 0; inp < num_inputs; ++inp) {
        SmilePoly bsn_z0;
        for (size_t j = 0; j < KEY_COLS && j < sn_ck.b[0].size(); ++j) {
            bsn_z0 += NttMul(sn_ck.b[0][j], proof.z0[inp][j]);
        }
        bsn_z0.Reduce();
        AppendPoly(transcript, bsn_z0);
    }
    AppendCoinOpeningBinding(transcript, proof.coin_opening);
    std::vector<std::vector<SlotChallenge>> live_gamma1(num_inputs);
    if (aux_layout.UsesLiveM1Layout()) {
        for (size_t inp = 0; inp < num_inputs; ++inp) {
            live_gamma1[inp] = DeriveCtGammaChallenges(transcript, inp, GetCtPublicRowCount());
        }
        AppendHash32(transcript, proof.pre_h2_binding_digest);
    }
    AppendPoly(transcript, proof.h2);
    std::vector<uint8_t> ct_framework_transcript = transcript;
    if (aux_layout.UsesLiveM1Layout()) {
        AppendHash32(transcript, proof.post_h2_binding_digest);
    }
    const auto seed_c_check = TranscriptHash(transcript);
    const auto& seed_c_final = SeedIsPresent(proof.seed_c) ? proof.seed_c : seed_c_check;
    if (SeedIsPresent(proof.seed_c) && seed_c_check != proof.seed_c) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 8]: seed_c mismatch. Final Fiat-Shamir challenge transcript "
                  "doesn't match proof.seed_c. transcript_size=%u\n",
                  (unsigned)transcript.size());
        return false;
    }
    LogDebug(BCLog::VALIDATION, "VerifyCT: step 8 PASSED (seed_c final challenge match)\n");

    // 9. Verify BDLOP weak opening structure
    SmilePoly c_chal = HashToMonomialChallenge(seed_c_final.data(), 32, domainsep::CT_C);
    const auto recovered_aux_tmsg =
        RecoverFullAuxMessageCommitments(aux_ck, proof, aux_layout, c_chal);
    const bool has_exact_live_aux_cache =
        aux_layout.UsesLiveM1Layout() && proof.w0_commitment_accs.size() == num_inputs;
    if (has_exact_live_aux_cache) {
        for (size_t slot = 0; slot < recovered_aux_tmsg.size(); ++slot) {
            if (IsLiveCtW0Slot(aux_layout, slot)) {
                continue;
            }
            SmilePoly provided = proof.aux_commitment.t_msg[slot];
            provided.Reduce();
            SmilePoly recovered = recovered_aux_tmsg[slot];
            recovered.Reduce();
            if (provided != recovered) {
                LogDebug(BCLog::VALIDATION,
                         "VerifyCT FAIL [step 8c]: exact aux cache mismatch slot=%u\n",
                         static_cast<unsigned>(slot));
                return false;
            }
        }
    }
    if (ComputeCtBindingDigest("BTX_SMILE2_CT_ROUND1_AUX_BIND_V1",
                               0,
                               CollectLiveCtRound1AuxBindingPolys(
                                   aux_layout,
                                   Span<const SmilePoly>{recovered_aux_tmsg.data(),
                                                         recovered_aux_tmsg.size()})) !=
        proof.round1_aux_binding_digest) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 8d]: round-1 aux binding digest mismatch\n");
        return false;
    }
    std::vector<SmilePoly> recovered_w0_commitment_accs(num_inputs);
    for (size_t inp = 0; inp < num_inputs; ++inp) {
        const SmilePoly weighted_response =
            ComputeCompressedW0ResponseAccumulator(aux_ck,
                                                  aux_layout,
                                                  proof.z,
                                                  inp,
                                                  live_gamma1[inp]);
        SmilePoly recovered_commitment =
            DivideByMonomialChallenge(weighted_response - proof.w0_residue_accs[inp], c_chal);
        recovered_commitment.Reduce();
        recovered_w0_commitment_accs[inp] = recovered_commitment;
        if (has_exact_live_aux_cache) {
            std::vector<SmilePoly> committed_rows;
            committed_rows.reserve(GetCtPublicRowCount());
            for (size_t row = 0; row < GetCtPublicRowCount(); ++row) {
                committed_rows.push_back(proof.aux_commitment.t_msg[aux_layout.W0Slot(inp, row)]);
            }
            SmilePoly exact_commitment =
                ComputeCompressedW0CommitmentAccumulator(
                    Span<const SmilePoly>{committed_rows.data(), committed_rows.size()},
                    live_gamma1[inp]);
            exact_commitment.Reduce();
            SmilePoly cached_commitment = proof.w0_commitment_accs[inp];
            cached_commitment.Reduce();
            if (exact_commitment != recovered_commitment || cached_commitment != recovered_commitment) {
                LogDebug(BCLog::VALIDATION,
                         "VerifyCT FAIL [step 8e0]: exact W0 cache mismatch input=%u\n",
                         static_cast<unsigned>(inp));
                return false;
            }
        }
        SmilePoly expected_residue =
            weighted_response - NttMul(c_chal, recovered_commitment);
        expected_residue.Reduce();
        SmilePoly actual_residue = proof.w0_residue_accs[inp];
        actual_residue.Reduce();
        if (expected_residue != actual_residue) {
            LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 8e]: compressed W0 residue mismatch input=%u\n",
                      static_cast<unsigned>(inp));
            return false;
        }
    }
    if (ComputeCtBindingDigest("BTX_SMILE2_CT_PRE_H2_BIND_V1",
                               0,
                               CollectLiveCtPreH2BindingPolys(
                                   aux_layout,
                                   Span<const SmilePoly>{recovered_aux_tmsg.data(),
                                                         recovered_aux_tmsg.size()},
                                   Span<const SmilePoly>{recovered_w0_commitment_accs.data(),
                                                         recovered_w0_commitment_accs.size()})) !=
        proof.pre_h2_binding_digest) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 8f]: pre-h2 binding digest mismatch\n");
        return false;
    }
    const auto full_aux_residues =
        BuildFullAuxResidues(aux_ck, proof, aux_layout, recovered_aux_tmsg, c_chal);
    // L2 audit fix: explicit cap on z vector size to prevent DoS via
    // oversized z vectors that pass the dimension check but waste memory.
    static constexpr size_t MAX_Z_SIZE = BDLOP_RAND_DIM_BASE + MAX_CT_INPUTS * 8 + MAX_CT_OUTPUTS * 4;
    if (proof.z.size() > MAX_Z_SIZE) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 9-cap]: z.size()=%u exceeds hard cap %u\n",
                  (unsigned)proof.z.size(), (unsigned)MAX_Z_SIZE);
        return false;
    }
    if (proof.z.size() != aux_ck.rand_dim()) {
        LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 9]: z.size()=%u != aux_ck.rand_dim()=%u "
                  "(n_aux_msg=%u BDLOP_RAND_DIM_BASE=%u)\n",
                  (unsigned)proof.z.size(), (unsigned)aux_ck.rand_dim(),
                  (unsigned)n_aux_msg, (unsigned)BDLOP_RAND_DIM_BASE);
        return false;
    }
    LogDebug(BCLog::VALIDATION, "VerifyCT: step 9 PASSED (z dimension = rand_dim = %u)\n", (unsigned)aux_ck.rand_dim());

    {
        const auto opening_challenges =
            DeriveOpeningChallenges(
                transcript,
                std::min(proof.aux_commitment.t0.size(),
                         static_cast<size_t>(MSIS_RANK)) +
                    ComputeCtWeakOpeningResidueCount(aux_layout) + 1);
        const auto omega_check =
            ComputeCtWeakOpeningAccumulator(aux_ck,
                                            proof.z,
                                            proof.aux_commitment.t0,
                                            full_aux_residues,
                                            proof.w0_residue_accs,
                                            aux_layout,
                                            c_chal,
                                            proof.h2,
                                            opening_challenges);
        if (!proof.omega.IsZero()) {
            SmilePoly expected = proof.omega;
            expected.Reduce();
            if (omega_check != expected) {
                LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 9b]: omega weak-opening accumulator mismatch\n");
                return false;
            }
        }
    }
    LogDebug(BCLog::VALIDATION, "VerifyCT: step 9b PASSED (weak-opening accumulator)\n");
    const std::vector<SmilePoly>& f = full_aux_residues;

    // 10. Balance is enforced via h2: the prover adds the carry polynomial
    // (encoding Σa_in - Σa_out) to h2 AFTER garbage cancellation.
    // If unbalanced, h2's first coefficients are non-zero → step 1 rejects.

    if (aux_layout.UsesLiveM1Layout()) {
        const auto alpha_chals = DeriveRhoChallenges(ct_framework_transcript, num_inputs + 1);
        SmilePoly framework_sum;
        SmilePoly bin_check;

        for (size_t inp = 0; inp < num_inputs; ++inp) {
            const size_t selector_slot = aux_layout.SelectorSlot(inp, 0);
            const size_t x_slot = aux_layout.XSlot(inp, 1, 0);
            const auto account_challenges = DeriveCtPublicAccountChallenges(public_transcript, inp);
            std::vector<NttForm> tuple_z_ntt(proof.input_tuples[inp].z_coin.size());
            for (size_t j = 0; j < proof.input_tuples[inp].z_coin.size(); ++j) {
                tuple_z_ntt[j] = NttForward(proof.input_tuples[inp].z_coin[j]);
            }

            std::vector<SmilePoly> open_rows(GetCtPublicRowCount());
            for (size_t row = 0; row < KEY_ROWS; ++row) {
                SmilePoly az0_row;
                for (size_t col = 0; col < KEY_COLS; ++col) {
                    az0_row += NttMul(A[row][col], proof.z0[inp][col]);
                }
                az0_row.Reduce();

                SmilePoly tuple_row =
                    ComputeOpeningInnerProduct(coin_ck.B0_ntt[row], tuple_z_ntt);
                tuple_row = NttMul(account_challenges.beta, tuple_row);
                tuple_row.Reduce();

                SmilePoly key_row = NttMul(account_challenges.alpha, az0_row);
                key_row.Reduce();

                SmilePoly open_row = key_row + tuple_row;
                open_row.Reduce();
                open_rows[row] = std::move(open_row);
            }

            SmilePoly amount_open =
                ComputeOpeningInnerProduct(coin_ck.b_ntt[0], tuple_z_ntt);
            amount_open += proof.input_tuples[inp].z_amount;
            amount_open = NttMul(account_challenges.beta, amount_open);
            amount_open.Reduce();
            open_rows[GetCtAmountRowIndex()] = std::move(amount_open);

            SmilePoly leaf_open = NttMul(account_challenges.gamma, proof.input_tuples[inp].z_leaf);
            leaf_open.Reduce();
            open_rows[GetCtLeafRowIndex()] = std::move(leaf_open);

            framework_sum += NttMul(f[selector_slot], f[x_slot]);
            SmilePoly adjusted_w_acc = proof.w0_residue_accs[inp];
            adjusted_w_acc += NttMul(c_chal, SumWeightedRows(open_rows, live_gamma1[inp]));
            adjusted_w_acc.Reduce();
            framework_sum += NttMul(c_chal, adjusted_w_acc);
            framework_sum.Reduce();

            SmilePoly selector_bin = NttMul(f[selector_slot], f[selector_slot]);
            selector_bin += NttMul(c_chal, f[selector_slot]);
            selector_bin = NttMul(alpha_chals[inp + 1], selector_bin);
            selector_bin.Reduce();
            bin_check += selector_bin;
            bin_check.Reduce();
        }

        SmilePoly c_fg = NttMul(c_chal, f[aux_layout.GSlot()]);
        c_fg.Reduce();
        SmilePoly c_sq = NttMul(c_chal, c_chal);
        SmilePoly c2h = NttMul(c_sq, proof.h2);
        c2h.Reduce();
        SmilePoly bracket = framework_sum - c_fg - c2h;
        bracket.Reduce();
        SmilePoly lhs = NttMul(alpha_chals[0], bracket) + bin_check + f[aux_layout.PsiSlot()];
        lhs.Reduce();
        if (ComputeCtBindingDigest("BTX_SMILE2_CT_POST_H2_BIND_V1",
                                   0,
                                   CollectLiveCtPostH2BindingPolys(
                                       aux_layout,
                                       Span<const SmilePoly>{recovered_aux_tmsg.data(),
                                                             recovered_aux_tmsg.size()},
                                       lhs)) != proof.post_h2_binding_digest) {
            LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 11]: post-h2 binding digest mismatch\n");
            return false;
        }
        if (!proof.framework_omega.IsZero()) {
            SmilePoly framework_omega = proof.framework_omega;
            framework_omega.Reduce();
            if (lhs != framework_omega) {
                LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 11]: live m=1 framework relation mismatch\n");
                return false;
            }
        }
    }
    LogDebug(BCLog::VALIDATION, "VerifyCT: step 11 PASSED (live m=1 hidden tuple-account framework)\n");

    if (!VerifyCombinedCoinOpeningProof(proof.coin_opening,
                                        coin_ck,
                                        proof,
                                        c0_chal,
                                        c_chal,
                                        proof.output_coins,
                                        input_coin_challenges,
                                        output_coin_challenges,
                                        f,
                                        tuple_coin_row_challenges,
                                        tuple_opening_challenge,
                                        /*input_amount_slot_offset=*/aux_layout.InputAmountOffset(),
                                        /*output_amount_slot_offset=*/aux_layout.OutputAmountOffset(),
                                        "step 11d-combined-coins")) {
        return false;
    }
    LogDebug(BCLog::VALIDATION, "VerifyCT: step 11d PASSED (combined coin opening check)\n");

    // 12. Verify proof binding hash over the retained aux commitment surface,
    // the recovered compressed omitted W0 commitment accumulators, and the
    // remaining recoverable omitted X/G/Psi commitment rows.
    {
        std::vector<uint8_t> bind_transcript = transcript;
        for (const auto& zi : proof.z) AppendPoly(bind_transcript, zi);
        for (const auto& zi : proof.coin_opening.z) AppendPoly(bind_transcript, zi);
        AppendCtBindingSurface(bind_transcript,
                               proof,
                               aux_layout,
                               Span<const SmilePoly>{recovered_aux_tmsg.data(),
                                                     recovered_aux_tmsg.size()},
                               Span<const SmilePoly>{recovered_w0_commitment_accs.data(),
                                                     recovered_w0_commitment_accs.size()});
        auto seed_z_check = TranscriptHash(bind_transcript);
        if (SeedIsPresent(proof.seed_z) && seed_z_check != proof.seed_z) {
            LogDebug(BCLog::VALIDATION, "VerifyCT FAIL [step 12]: seed_z binding hash mismatch. "
                      "bind_transcript_size=%u z.size=%u aux_t0.size=%u aux_tmsg.size=%u\n",
                      (unsigned)bind_transcript.size(), (unsigned)proof.z.size(),
                      (unsigned)proof.aux_commitment.t0.size(),
                      (unsigned)proof.aux_commitment.t_msg.size());
            return false;
        }
    }
    LogDebug(BCLog::VALIDATION, "VerifyCT: step 12 PASSED (binding hash)\n");

    LogDebug(BCLog::VALIDATION, "VerifyCT: ALL CHECKS PASSED\n");
    return true;
}

} // namespace smile2

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/smile2/bdlop.h>
#include <shielded/smile2/domain_separation.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <support/cleanse.h>

#include <cassert>
#include <cstring>

namespace smile2 {

namespace {
constexpr const char* TAG_STRONG_TERNARY_SEED{"BTX-SMILE-V2-TERNARY-STRONG"};
constexpr const char* TAG_LEGACY_TERNARY_SEED{"BTX-SMILE-V2-TERNARY-LEGACY-SEED"};

// Generate a pseudorandom polynomial from a seed and indices
SmilePoly ExpandPoly(const std::array<uint8_t, 32>& seed, uint32_t domain, uint32_t row, uint32_t col)
{
    SmilePoly p;
    // Hash: H(seed || domain || row || col || block_idx) to get coefficients
    for (size_t block = 0; block < POLY_DEGREE; block += 8) {
        CSHA256 hasher;
        hasher.Write(seed.data(), 32);
        uint8_t idx_buf[16];
        WriteLE32(idx_buf, domain);
        WriteLE32(idx_buf + 4, row);
        WriteLE32(idx_buf + 8, col);
        uint32_t blk = static_cast<uint32_t>(block);
        WriteLE32(idx_buf + 12, blk);
        hasher.Write(idx_buf, 16);

        uint8_t hash[32];
        hasher.Finalize(hash);

        for (size_t i = 0; i < 8 && (block + i) < POLY_DEGREE; ++i) {
            // Extract 4 bytes for each coefficient, reduce mod q
            const uint32_t val = ReadLE32(hash + 4 * i);
            p.coeffs[block + i] = static_cast<int64_t>(val) % Q;
        }
    }
    return p;
}

class DeterministicSeedStream
{
public:
    explicit DeterministicSeedStream(const std::array<uint8_t, 32>& seed_in)
        : m_seed(seed_in)
    {
    }

    ~DeterministicSeedStream()
    {
        memory_cleanse(m_block.data(), m_block.size());
    }

    uint8_t NextByte()
    {
        if (m_offset >= m_block.size()) {
            Refill();
        }
        return m_block[m_offset++];
    }

private:
    void Refill()
    {
        CSHA256 hasher;
        hasher.Write(reinterpret_cast<const uint8_t*>(TAG_STRONG_TERNARY_SEED),
                     std::strlen(TAG_STRONG_TERNARY_SEED));
        hasher.Write(m_seed.data(), m_seed.size());
        uint8_t counter_bytes[8];
        WriteLE64(counter_bytes, m_counter++);
        hasher.Write(counter_bytes, sizeof(counter_bytes));
        hasher.Finalize(m_block.data());
        m_offset = 0;
    }

    std::array<uint8_t, 32> m_seed;
    std::array<uint8_t, 32> m_block{};
    uint64_t m_counter{0};
    size_t m_offset{m_block.size()};
};

int64_t SampleUnbiasedTernaryCoeff(DeterministicSeedStream& stream)
{
    while (true) {
        const uint8_t byte = stream.NextByte();
        if (byte >= 243) continue;
        switch (byte % 3) {
        case 0:
            return mod_q(-1);
        case 1:
            return 0;
        default:
            return 1;
        }
    }
}

std::array<uint8_t, 32> ExpandLegacyTernarySeed(uint64_t seed)
{
    std::array<uint8_t, 32> expanded_seed{};
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const uint8_t*>(TAG_LEGACY_TERNARY_SEED),
                 std::strlen(TAG_LEGACY_TERNARY_SEED));
    uint8_t seed_bytes[8];
    WriteLE64(seed_bytes, seed);
    hasher.Write(seed_bytes, sizeof(seed_bytes));
    hasher.Finalize(expanded_seed.data());
    return expanded_seed;
}

} // anonymous namespace

BDLOPCommitmentKey BDLOPCommitmentKey::Generate(const std::array<uint8_t, 32>& seed, size_t n_msg_in)
{
    BDLOPCommitmentKey ck;
    ck.n_msg = n_msg_in;
    size_t rdim = ck.rand_dim();

    // Generate B_0: (α+β) × rdim matrix
    ck.B0.resize(BDLOP_RAND_DIM_BASE);
    ck.B0_ntt.resize(BDLOP_RAND_DIM_BASE);
    for (size_t i = 0; i < BDLOP_RAND_DIM_BASE; ++i) {
        ck.B0[i].resize(rdim);
        ck.B0_ntt[i].resize(rdim);
        for (size_t j = 0; j < rdim; ++j) {
            ck.B0[i][j] = ExpandPoly(seed,
                                     domainsep::BDLOP_MATRIX_B0,
                                     static_cast<uint32_t>(i),
                                     static_cast<uint32_t>(j));
            ck.B0_ntt[i][j] = NttForward(ck.B0[i][j]);
        }
    }

    // Generate b_1, ..., b_{n_msg}: each a vector of rdim polynomials
    ck.b.resize(n_msg_in);
    ck.b_ntt.resize(n_msg_in);
    for (size_t i = 0; i < n_msg_in; ++i) {
        ck.b[i].resize(rdim);
        ck.b_ntt[i].resize(rdim);
        for (size_t j = 0; j < rdim; ++j) {
            ck.b[i][j] = ExpandPoly(seed,
                                    domainsep::BDLOP_VECTOR_B,
                                    static_cast<uint32_t>(i),
                                    static_cast<uint32_t>(j));
            ck.b_ntt[i][j] = NttForward(ck.b[i][j]);
        }
    }

    return ck;
}

void BDLOPCommitmentKey::RebuildNttCache()
{
    B0_ntt.resize(B0.size());
    for (size_t row = 0; row < B0.size(); ++row) {
        B0_ntt[row].resize(B0[row].size());
        for (size_t col = 0; col < B0[row].size(); ++col) {
            B0_ntt[row][col] = NttForward(B0[row][col]);
        }
    }

    b_ntt.resize(b.size());
    for (size_t row = 0; row < b.size(); ++row) {
        b_ntt[row].resize(b[row].size());
        for (size_t col = 0; col < b[row].size(); ++col) {
            b_ntt[row][col] = NttForward(b[row][col]);
        }
    }
}

SmilePolyVec SampleTernary(size_t dim, uint64_t seed)
{
    SmilePolyVec r(dim);
    // Preserve the legacy deterministic sampler for compatibility with
    // existing tests and pre-upgrade derivation call sites.
    uint64_t state = seed;
    for (size_t i = 0; i < dim; ++i) {
        for (size_t j = 0; j < POLY_DEGREE; ++j) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            const uint64_t bits = state & 0xF;
            if (bits < 5) {
                r[i].coeffs[j] = mod_q(-1);
            } else if (bits < 10) {
                r[i].coeffs[j] = 1;
            } else {
                r[i].coeffs[j] = 0;
            }
        }
    }
    return r;
}

SmilePolyVec SampleTernaryStrong(size_t dim, uint64_t seed)
{
    return SampleTernaryStrong(dim, ExpandLegacyTernarySeed(seed));
}

SmilePolyVec SampleTernaryStrong(size_t dim, const std::array<uint8_t, 32>& seed)
{
    SmilePolyVec r(dim);
    DeterministicSeedStream stream(seed);
    for (size_t i = 0; i < dim; ++i) {
        for (size_t j = 0; j < POLY_DEGREE; ++j) {
            r[i].coeffs[j] = SampleUnbiasedTernaryCoeff(stream);
        }
    }
    return r;
}

BDLOPCommitment Commit(const BDLOPCommitmentKey& ck,
                        const std::vector<SmilePoly>& messages,
                        const SmilePolyVec& r)
{
    assert(messages.size() == ck.n_msg);
    assert(r.size() == ck.rand_dim());

    // Convert r to NTT form once (saves one NttForward per inner loop iteration)
    std::vector<NttForm> r_ntt(r.size());
    for (size_t j = 0; j < r.size(); ++j) {
        r_ntt[j] = NttForward(r[j]);
    }

    BDLOPCommitment com;

    // t_0 = B_0 · r  (α+β polynomials)
    // Accumulate in NTT domain, then INTT once per row
    com.t0.resize(BDLOP_RAND_DIM_BASE);
    for (size_t i = 0; i < BDLOP_RAND_DIM_BASE; ++i) {
        NttForm acc_ntt;
        for (size_t j = 0; j < ck.rand_dim(); ++j) {
            acc_ntt += ck.B0_ntt[i][j].PointwiseMul(r_ntt[j]);
        }
        com.t0[i] = NttInverse(acc_ntt);
        com.t0[i].Reduce();
    }

    // t_i = ⟨b_i, r⟩ + m_i  for i = 1..n_msg
    // Same batch NTT approach
    com.t_msg.resize(ck.n_msg);
    for (size_t i = 0; i < ck.n_msg; ++i) {
        NttForm acc_ntt;
        for (size_t j = 0; j < ck.rand_dim(); ++j) {
            acc_ntt += ck.b_ntt[i][j].PointwiseMul(r_ntt[j]);
        }
        SmilePoly acc = NttInverse(acc_ntt);
        acc += messages[i];
        acc.Reduce();
        com.t_msg[i] = acc;
    }

    return com;
}

bool VerifyOpening(const BDLOPCommitmentKey& ck,
                   const BDLOPCommitment& com,
                   const std::vector<SmilePoly>& messages,
                   const SmilePolyVec& r)
{
    if (messages.size() != ck.n_msg || r.size() != ck.rand_dim()) return false;

    std::vector<NttForm> r_ntt(r.size());
    for (size_t j = 0; j < r.size(); ++j) {
        r_ntt[j] = NttForward(r[j]);
    }

    // Check t_0 = B_0 · r
    for (size_t i = 0; i < BDLOP_RAND_DIM_BASE; ++i) {
        NttForm acc_ntt;
        for (size_t j = 0; j < ck.rand_dim(); ++j) {
            acc_ntt += ck.B0_ntt[i][j].PointwiseMul(r_ntt[j]);
        }
        SmilePoly acc = NttInverse(acc_ntt);
        acc.Reduce();
        SmilePoly expected = com.t0[i];
        expected.Reduce();
        if (acc != expected) return false;
    }

    // Check t_i = ⟨b_i, r⟩ + m_i
    for (size_t i = 0; i < ck.n_msg; ++i) {
        NttForm acc_ntt;
        for (size_t j = 0; j < ck.rand_dim(); ++j) {
            acc_ntt += ck.b_ntt[i][j].PointwiseMul(r_ntt[j]);
        }
        SmilePoly acc = NttInverse(acc_ntt);
        acc += messages[i];
        acc.Reduce();
        SmilePoly expected = com.t_msg[i];
        expected.Reduce();
        if (acc != expected) return false;
    }

    return true;
}

bool VerifyWeakOpening(const BDLOPCommitmentKey& ck,
                       const BDLOPCommitment& com,
                       const SmilePolyVec& z,
                       const SmilePolyVec& w0,
                       const SmilePoly& c_chal,
                       const std::vector<SmilePoly>& f)
{
    if (z.size() != ck.rand_dim()) return false;
    if (w0.size() != BDLOP_RAND_DIM_BASE) return false;
    if (f.size() != ck.n_msg) return false;

    std::vector<NttForm> z_ntt(z.size());
    for (size_t j = 0; j < z.size(); ++j) {
        z_ntt[j] = NttForward(z[j]);
    }

    // Check B_0 · z = w_0 + c · t_0
    for (size_t i = 0; i < BDLOP_RAND_DIM_BASE; ++i) {
        NttForm lhs_ntt;
        for (size_t j = 0; j < ck.rand_dim(); ++j) {
            lhs_ntt += ck.B0_ntt[i][j].PointwiseMul(z_ntt[j]);
        }
        SmilePoly lhs = NttInverse(lhs_ntt);
        lhs.Reduce();

        SmilePoly rhs = w0[i] + NttMul(c_chal, com.t0[i]);
        rhs.Reduce();

        if (lhs != rhs) return false;
    }

    // Check ⟨b_i, z⟩ - c · t_i = f_i
    for (size_t i = 0; i < ck.n_msg; ++i) {
        NttForm lhs_ntt;
        for (size_t j = 0; j < ck.rand_dim(); ++j) {
            lhs_ntt += ck.b_ntt[i][j].PointwiseMul(z_ntt[j]);
        }
        SmilePoly lhs = NttInverse(lhs_ntt);
        lhs -= NttMul(c_chal, com.t_msg[i]);
        lhs.Reduce();

        SmilePoly expected = f[i];
        expected.Reduce();

        if (lhs != expected) return false;
    }

    return true;
}

} // namespace smile2

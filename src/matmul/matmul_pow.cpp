// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_pow.h>

#include <crypto/common.h>
#include <logging.h>
#include <matmul/transcript.h>
#include <primitives/block.h>
#include <span.h>

#if defined(__APPLE__)
#include <Accelerate/Accelerate.h>
#endif

#include <cassert>
#include <cmath>
#include <cstdlib>
#include <cstdint>
#include <limits>
#include <vector>

namespace matmul {
namespace {

bool IsValidConfig(const PowConfig& config)
{
    if (config.n == 0 || config.b == 0 || config.r == 0) return false;
    if (config.n % config.b != 0) return false;
    if (config.r > config.n) return false;
    return true;
}

LowRankProductProfile BuildLowRankProductProfile(uint32_t rows, uint32_t inner_dim, uint32_t cols)
{
    LowRankProductProfile profile;
#if defined(__APPLE__)
    profile.accelerate_compiled = true;
    const char* env = std::getenv("BTX_MATMUL_AMX_EXPERIMENT");
    const bool force_disable = env != nullptr && env[0] == '0';
    const bool force_enable = env != nullptr && env[0] != '\0' && env[0] != '0';

    if (force_disable) {
        profile.reason = "amx_forced_off";
        return profile;
    }
    if (rows == 0 || inner_dim == 0 || cols == 0) {
        profile.reason = "invalid_dimensions";
        return profile;
    }
    if (inner_dim > 16) {
        profile.reason = "inner_dimension_exceeds_split16_bound";
        return profile;
    }
    profile.accelerate_active = true;
    profile.reason = force_enable ? "accelerate_split16_dgemm_forced" : "accelerate_split16_dgemm_auto";
#else
    (void)rows;
    (void)inner_dim;
    (void)cols;
    profile.reason = "accelerate_unavailable_non_apple";
#endif
    return profile;
}

Matrix LowRankProductScalar(const Matrix& left, const Matrix& right, uint64_t* op_count)
{
    assert(left.cols() == right.rows());

    Matrix out(left.rows(), right.cols());

    for (uint32_t i = 0; i < left.rows(); ++i) {
        for (uint32_t j = 0; j < right.cols(); ++j) {
            field::Element acc = 0;
            for (uint32_t k = 0; k < left.cols(); ++k) {
                acc = field::add(acc, field::mul(left.at(i, k), right.at(k, j)));
                if (op_count != nullptr) {
                    ++(*op_count);
                }
            }
            out.at(i, j) = acc;
        }
    }

    return out;
}

#if defined(__APPLE__)
field::Element ReduceMersenne128(unsigned __int128 value)
{
    constexpr unsigned __int128 kModulus = static_cast<unsigned __int128>(field::MODULUS);
    // At most ceil(128/31) = 5 reduction steps are needed for 128-bit inputs.
    // Add a defensive iteration bound to prevent infinite loops on pathological inputs.
    for (int iter = 0; iter < 8 && value > kModulus; ++iter) {
        value = (value & kModulus) + (value >> 31);
    }
    return value == kModulus ? 0 : static_cast<field::Element>(value);
}

Matrix LowRankProductAccelerateSplit16(const Matrix& left, const Matrix& right, uint64_t* op_count)
{
    const int m = static_cast<int>(left.rows());
    const int k = static_cast<int>(left.cols());
    const int n = static_cast<int>(right.cols());

    const size_t left_words = static_cast<size_t>(m) * k;
    const size_t right_words = static_cast<size_t>(k) * n;
    const size_t out_words = static_cast<size_t>(m) * n;

    std::vector<double> left_lo(left_words);
    std::vector<double> left_hi(left_words);
    std::vector<double> right_lo(right_words);
    std::vector<double> right_hi(right_words);

    for (int row = 0; row < m; ++row) {
        for (int col = 0; col < k; ++col) {
            const uint32_t value = left.at(row, col);
            const size_t idx = static_cast<size_t>(row) * k + col;
            left_lo[idx] = static_cast<double>(value & 0xffffU);
            left_hi[idx] = static_cast<double>(value >> 16);
        }
    }

    for (int row = 0; row < k; ++row) {
        for (int col = 0; col < n; ++col) {
            const uint32_t value = right.at(row, col);
            const size_t idx = static_cast<size_t>(row) * n + col;
            right_lo[idx] = static_cast<double>(value & 0xffffU);
            right_hi[idx] = static_cast<double>(value >> 16);
        }
    }

    std::vector<double> c_ll(out_words, 0.0);
    std::vector<double> c_lh(out_words, 0.0);
    std::vector<double> c_hl(out_words, 0.0);
    std::vector<double> c_hh(out_words, 0.0);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    cblas_dgemm(CblasRowMajor, CblasNoTrans, CblasNoTrans, m, n, k, 1.0, left_lo.data(), k, right_lo.data(), n, 0.0, c_ll.data(), n);
    cblas_dgemm(CblasRowMajor, CblasNoTrans, CblasNoTrans, m, n, k, 1.0, left_lo.data(), k, right_hi.data(), n, 0.0, c_lh.data(), n);
    cblas_dgemm(CblasRowMajor, CblasNoTrans, CblasNoTrans, m, n, k, 1.0, left_hi.data(), k, right_lo.data(), n, 0.0, c_hl.data(), n);
    cblas_dgemm(CblasRowMajor, CblasNoTrans, CblasNoTrans, m, n, k, 1.0, left_hi.data(), k, right_hi.data(), n, 0.0, c_hh.data(), n);
#pragma clang diagnostic pop

    Matrix out(left.rows(), right.cols());
    for (int row = 0; row < m; ++row) {
        for (int col = 0; col < n; ++col) {
            const size_t idx = static_cast<size_t>(row) * n + col;
            // Guard against floating-point rounding producing negative values
            // near zero (catastrophic cancellation). Clamp to 0 before casting
            // to uint64_t to prevent wrap-around.
            const long long ll_raw = std::llround(c_ll[idx]);
            const long long lh_raw = std::llround(c_lh[idx]);
            const long long hl_raw = std::llround(c_hl[idx]);
            const long long hh_raw = std::llround(c_hh[idx]);
            const uint64_t ll = static_cast<uint64_t>(std::max<long long>(ll_raw, 0));
            const uint64_t lh = static_cast<uint64_t>(std::max<long long>(lh_raw, 0));
            const uint64_t hl = static_cast<uint64_t>(std::max<long long>(hl_raw, 0));
            const uint64_t hh = static_cast<uint64_t>(std::max<long long>(hh_raw, 0));

            const unsigned __int128 total =
                static_cast<unsigned __int128>(ll) +
                (static_cast<unsigned __int128>(lh + hl) << 16) +
                (static_cast<unsigned __int128>(hh) << 32);
            out.at(row, col) = ReduceMersenne128(total);

            if (op_count != nullptr) {
                *op_count += static_cast<uint64_t>(k);
            }
        }
    }

    return out;
}

namespace {
std::atomic<bool> g_accelerate_disabled{false};
} // namespace
#endif

Matrix LowRankProduct(const Matrix& left, const Matrix& right, uint64_t* op_count)
{
    assert(left.cols() == right.rows());
    const auto profile = BuildLowRankProductProfile(left.rows(), left.cols(), right.cols());

#if defined(__APPLE__)
    if (profile.accelerate_active && !g_accelerate_disabled.load(std::memory_order_relaxed)) {
        Matrix result = LowRankProductAccelerateSplit16(left, right, op_count);

        // Spot-check element (0,0) against the exact scalar path.
        // Cost: one inner product of length k (~30ns). Negligible vs full DGEMM.
        field::Element scalar_check = 0;
        for (uint32_t k = 0; k < left.cols(); ++k) {
            scalar_check = field::add(scalar_check, field::mul(left.at(0, k), right.at(k, 0)));
        }
        if (result.at(0, 0) != scalar_check) {
            LogError("CONSENSUS CRITICAL: BLAS/scalar divergence at (0,0): "
                     "BLAS=%u scalar=%u (left.rows=%u left.cols=%u right.cols=%u). "
                     "Disabling Accelerate permanently for this session.\n",
                     result.at(0, 0), scalar_check,
                     left.rows(), left.cols(), right.cols());
            g_accelerate_disabled.store(true, std::memory_order_relaxed);
            return LowRankProductScalar(left, right, op_count);
        }
        return result;
    }
#endif

    return LowRankProductScalar(left, right, op_count);
}

} // namespace

uint256 ComputeMatMulHeaderHash(const CBlockHeader& header)
{
    CSHA256 hasher;

    uint8_t version_le[4];
    uint8_t time_le[4];
    uint8_t bits_le[4];
    uint8_t nonce64_le[8];
    uint8_t dim_le[2];

    WriteLE32(version_le, static_cast<uint32_t>(header.nVersion));
    WriteLE32(time_le, header.nTime);
    WriteLE32(bits_le, header.nBits);
    WriteLE64(nonce64_le, header.nNonce64);
    WriteLE16(dim_le, header.matmul_dim);

    hasher.Write(version_le, sizeof(version_le));
    hasher.Write(header.hashPrevBlock.data(), uint256::size());
    hasher.Write(header.hashMerkleRoot.data(), uint256::size());
    hasher.Write(time_le, sizeof(time_le));
    hasher.Write(bits_le, sizeof(bits_le));
    hasher.Write(nonce64_le, sizeof(nonce64_le));
    hasher.Write(dim_le, sizeof(dim_le));
    hasher.Write(header.seed_a.data(), uint256::size());
    hasher.Write(header.seed_b.data(), uint256::size());

    uint8_t digest[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(digest);
    return uint256{Span<const unsigned char>{digest, CSHA256::OUTPUT_SIZE}};
}

uint256 DeriveSigma(const CBlockHeader& header)
{
    const uint256 header_hash = ComputeMatMulHeaderHash(header);

    uint8_t sigma_bytes[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(header_hash.data(), uint256::size()).Finalize(sigma_bytes);
    return uint256{Span<const unsigned char>{sigma_bytes, CSHA256::OUTPUT_SIZE}};
}

static CBlockHeader BuildHeaderFromPowState(const PowState& state)
{
    CBlockHeader header;
    header.nVersion = state.version;
    header.hashPrevBlock = state.previous_block_hash;
    header.hashMerkleRoot = state.merkle_root;
    header.nTime = state.time;
    header.nBits = state.bits;
    header.nNonce64 = state.nonce;
    header.nNonce = static_cast<uint32_t>(state.nonce);
    header.matmul_dim = state.matmul_dim;
    header.seed_a = state.seed_a;
    header.seed_b = state.seed_b;
    return header;
}

uint256 DeriveSigma(const PowState& state)
{
    return DeriveSigma(BuildHeaderFromPowState(state));
}

LowRankProductProfile ProbeLowRankProductProfile(uint32_t rows, uint32_t inner_dim, uint32_t cols)
{
    return BuildLowRankProductProfile(rows, inner_dim, cols);
}

bool VerifyCommitment(const PowState& state, const PowConfig& config)
{
    if (!IsValidConfig(config)) {
        return false;
    }
    if (state.matmul_dim != config.n) {
        return false;
    }
    return UintToArith256(state.digest) <= config.target;
}

bool Solve(PowState& state, const PowConfig& config, uint64_t& max_tries, const SolveRuntimeOptions& options)
{
    if (!IsValidConfig(config)) {
        return false;
    }
    if (max_tries == 0) {
        return false;
    }
    if (state.matmul_dim != config.n) {
        return false;
    }

    const ScopedSolveRuntime runtime{options};
    const Matrix A = FromSeed(state.seed_a, config.n);
    const Matrix B = FromSeed(state.seed_b, config.n);

    while (max_tries > 0) {
        if (SolveTimeBudgetExpired()) {
            return false;
        }
        const uint256 sigma = DeriveSigma(state);
        const noise::NoisePair np = noise::Generate(sigma, config.n, config.r);

        const Matrix E = np.E_L * np.E_R;
        const Matrix F = np.F_L * np.F_R;
        const Matrix A_prime = A + E;
        const Matrix B_prime = B + F;

        const auto result = transcript::CanonicalMatMul(A_prime, B_prime, config.b, sigma);

        --max_tries;
        if (UintToArith256(result.transcript_hash) <= config.target) {
            state.digest = result.transcript_hash;
            return true;
        }

        if (state.nonce == std::numeric_limits<uint64_t>::max()) {
            break;
        }
        ++state.nonce;
    }

    return false;
}

bool Verify(const PowState& state, const PowConfig& config)
{
    if (!VerifyCommitment(state, config)) {
        return false;
    }

    const Matrix A = FromSeed(state.seed_a, config.n);
    const Matrix B = FromSeed(state.seed_b, config.n);
    const uint256 sigma = DeriveSigma(state);
    const noise::NoisePair np = noise::Generate(sigma, config.n, config.r);

    const Matrix E = np.E_L * np.E_R;
    const Matrix F = np.F_L * np.F_R;
    const Matrix A_prime = A + E;
    const Matrix B_prime = B + F;

    const auto result = transcript::CanonicalMatMul(A_prime, B_prime, config.b, sigma);
    return result.transcript_hash == state.digest;
}

Matrix Denoise(const Matrix& C_noisy, const Matrix& A, const Matrix& B, const noise::NoisePair& np)
{
    assert(C_noisy.rows() == C_noisy.cols());
    assert(A.rows() == A.cols());
    assert(B.rows() == B.cols());
    assert(C_noisy.rows() == A.rows());
    assert(C_noisy.cols() == B.cols());
    assert(np.E_L.rows() == C_noisy.rows());
    assert(np.E_R.cols() == C_noisy.cols());
    assert(np.E_L.cols() == np.E_R.rows());
    assert(np.F_L.rows() == C_noisy.rows());
    assert(np.F_R.cols() == C_noisy.cols());
    assert(np.F_L.cols() == np.F_R.rows());

    // For C_noisy = (A + E)(B + F), recover clean product A*B by subtracting:
    // A*F + E*B + E*F.
    //
    // Low-rank structure:
    // E = E_L * E_R
    // F = F_L * F_R
    const Matrix af_left = LowRankProduct(A, np.F_L, nullptr);
    const Matrix af = LowRankProduct(af_left, np.F_R, nullptr);

    const Matrix eb_right = LowRankProduct(np.E_R, B, nullptr);
    const Matrix eb = LowRankProduct(np.E_L, eb_right, nullptr);

    const Matrix ef_mid = LowRankProduct(np.E_R, np.F_L, nullptr);
    const Matrix ef_left = LowRankProduct(np.E_L, ef_mid, nullptr);
    const Matrix ef = LowRankProduct(ef_left, np.F_R, nullptr);

    return ((C_noisy - af) - eb) - ef;
}

uint64_t DenoiseOpsForTest(const Matrix& C_noisy, const Matrix& A, const Matrix& B, const noise::NoisePair& np)
{
    uint64_t ops = 0;
    const Matrix af_left = LowRankProduct(A, np.F_L, &ops);
    (void)LowRankProduct(af_left, np.F_R, &ops);

    const Matrix eb_right = LowRankProduct(np.E_R, B, &ops);
    (void)LowRankProduct(np.E_L, eb_right, &ops);

    const Matrix ef_mid = LowRankProduct(np.E_R, np.F_L, &ops);
    const Matrix ef_left = LowRankProduct(np.E_L, ef_mid, &ops);
    (void)LowRankProduct(ef_left, np.F_R, &ops);

    // C_noisy is intentionally unused in cost accounting.
    (void)C_noisy;
    return ops;
}

} // namespace matmul

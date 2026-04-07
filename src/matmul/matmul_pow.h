// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_POW_H
#define BTX_MATMUL_MATMUL_POW_H

#include <arith_uint256.h>
#include <matmul/noise.h>
#include <matmul/solver_runtime.h>
#include <uint256.h>

#include <cstdint>
#include <string>

class CBlockHeader;

namespace matmul {

struct PowConfig {
    uint32_t n;
    uint32_t b;
    uint32_t r;
    arith_uint256 target;
};

struct PowState {
    int32_t version;
    uint256 previous_block_hash;
    uint256 merkle_root;
    uint32_t time;
    uint32_t bits;
    uint256 seed_a;
    uint256 seed_b;
    uint64_t nonce;
    uint16_t matmul_dim;
    uint256 digest;
};

struct LowRankProductProfile {
    bool accelerate_compiled{false};
    bool accelerate_active{false};
    std::string reason;
};

uint256 ComputeMatMulHeaderHash(const CBlockHeader& header);
// Consensus sigma derivation is defined from the full block header.
uint256 DeriveSigma(const CBlockHeader& header);
// Utility/test sigma derivation that follows the same full-header rule.
uint256 DeriveSigma(const PowState& state);
LowRankProductProfile ProbeLowRankProductProfile(uint32_t rows, uint32_t inner_dim, uint32_t cols);

bool Solve(PowState& state, const PowConfig& config, uint64_t& max_tries, const SolveRuntimeOptions& options = {});
bool Verify(const PowState& state, const PowConfig& config);
bool VerifyCommitment(const PowState& state, const PowConfig& config);

// Recover A*B from C_noisy = (A+E)(B+F) using low-rank factors in np.
// Requires the original A and B matrices.
Matrix Denoise(const Matrix& C_noisy, const Matrix& A, const Matrix& B, const noise::NoisePair& np);

// Test-only operation counter for verifying low-rank denoise complexity.
uint64_t DenoiseOpsForTest(const Matrix& C_noisy, const Matrix& A, const Matrix& B, const noise::NoisePair& np);

} // namespace matmul

#endif // BTX_MATMUL_MATMUL_POW_H

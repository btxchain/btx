// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_BMX4_BATCH_H
#define BTX_MATMUL_MATMUL_V4_BMX4_BATCH_H

#include <matmul/matmul_v4.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

// Cross-nonce BATCHED miner for the MatMul v4.2 / ENC-BMX4C encoding profile
// (doc/btx-matmul-v4.2-bmx4c-spec.md §7-§8; consolidated-design §5). This is
// the ENC-BMX4C sibling of matmul::v4::BatchedSketchMiner (matmul_v4_batch.h):
// the STRUCTURE is identical, only the operand ENCODING changes (§0.1). It is
// the CPU reference of the batched miner every ENC-BMX4C backend must mirror:
//
//   * A, U, V are TEMPLATE-scoped (invariant I1', §1.5): the M11+E8M0 operand
//     Ahat and the scale-free M11 projectors U, V are expanded ONCE per
//     template, and the left factor P = U*Ahat is computed ONCE per template
//     (one m x n x n exact s8xs8->s32 GEMM, amortized over the whole sweep).
//   * Per nonce, only Bhat is expanded (nonce-fresh — both its mantissa AND
//     scale planes bind seed_B, redesign condition #6); the per-nonce right
//     factor is Q_i = Bhat_i*V (n x m).
//   * The per-nonce combines fuse into ONE LARGE DENSE GEMM
//         P * [Bhat_1*V | ... | Bhat_Q*V]   (m x n by n x Q*m)
//     via matmul::v4::ComputeCombineLimbTensorStacked — reused UNCHANGED. The
//     combine consumes the exact-int32 P and Q entries and is agnostic to how
//     they were encoded, so its base-2^7 limb reference is byte-identical here
//     to the base-2^6 remainder-top reference the single-nonce ENC-BMX4C path
//     (matmul::v4::bmx4::ComputeDigestBMX4C) uses: both equal P*Q mod q as
//     exact integers, and canonical F_q residues are unique.
//
// DETERMINISM: pure integer arithmetic; every result is byte-identical to the
// per-nonce reference matmul::v4::bmx4::ComputeDigestBMX4C for every nonce in
// the batch (enforced by matmul_v4_bmx4_batch_tests.cpp). Batching is a
// MINER-ONLY optimization: the verifier (matmul::v4::bmx4::VerifySketchBMX4C)
// is untouched and still checks ONE winning nonce in O(n^2).

namespace matmul::v4::bmx4 {

/** Result of one nonce attempt inside an ENC-BMX4C batch (mirrors
 *  matmul::v4::BatchNonceResult). */
struct BatchNonceResultBMX4C {
    uint64_t nonce{0};
    uint256 digest;
    std::vector<unsigned char> payload; // serialized sketch, 8*m^2 bytes
};

/** Template-scoped batched ENC-BMX4C sketch miner. Construct once per block
 *  template; Mine() sweeps nonce windows reusing the cached Ahat, U, V and
 *  P = U*Ahat. */
class BatchedSketchMinerBMX4C
{
public:
    /** `header` is the block template. `n` must validate against kTileB and the
     *  ENC-BMX4C dim invariants (ValidateDimsBMX4C: n % 32 == 0 and
     *  CheckCombineLimbBoundBMX4C, i.e. 288*n <= 2^23-1). */
    BatchedSketchMinerBMX4C(const CBlockHeader& header, uint32_t n);

    /** False iff (n, kTileB) failed ENC-BMX4C validation; Mine() must not be
     *  called. */
    [[nodiscard]] bool Valid() const { return m_valid; }

    /** Compute digests for a window of fully-populated candidate headers (each
     *  projecting onto this miner's template — the ENC-BMX4C seeds bind the
     *  template hash for A/U/V and the full header for B). Every entry is
     *  byte-identical to matmul::v4::bmx4::ComputeDigestBMX4C on the same
     *  header. Returns false iff the miner is invalid, `headers` is empty, or
     *  any header does not project onto this miner's template (fail closed). */
    [[nodiscard]] bool Mine(const std::vector<CBlockHeader>& headers,
                            std::vector<BatchNonceResultBMX4C>& out) const;

    /** Convenience window for tests/benches: clones the construction template
     *  and sets nNonce64 = start_nonce + i for i in [0, count). Does NOT
     *  re-derive per-nonce header seed fields (see the header-window overload
     *  the solve loop uses). */
    [[nodiscard]] bool Mine(uint64_t start_nonce, uint32_t count,
                            std::vector<BatchNonceResultBMX4C>& out) const;

    /** m = n / kTileB. */
    [[nodiscard]] uint32_t SketchDim() const { return m_m; }

    /** The template hash all candidate headers must project onto. */
    [[nodiscard]] const uint256& TemplateHash() const { return m_template_hash; }

private:
    CBlockHeader m_template;
    uint256 m_template_hash;
    uint32_t m_n{0};
    uint32_t m_m{0};
    bool m_valid{false};
    std::vector<int8_t> m_A; // template-cached Ahat (n*n, M11xE8M0 dequant, |.|<=48)
    std::vector<int8_t> m_U; // template-cached projector U (m*n, scale-free M11)
    std::vector<int8_t> m_V; // template-cached projector V (n*m, scale-free M11)
    std::vector<int32_t> m_P; // template-cached left factor P = U*Ahat (m*n, exact s32)
};

} // namespace matmul::v4::bmx4

#endif // BTX_MATMUL_MATMUL_V4_BMX4_BATCH_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_FRI_EXT3_ALG_ORDER_AUDIT_H
#define BTX_MATMUL_MATMUL_V4_RC_FRI_EXT3_ALG_ORDER_AUDIT_H

#include <matmul/matmul_v4_rc_fri_ext3_alg.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc {

/**
 * Executable algebraic audit of the legacy transcript order
 *
 *   roots -> alpha -> z -> claimed per-column evaluations.
 *
 * Once alpha and z are known, two nonzero weighted coordinates expose a
 * one-dimensional kernel independently at each OOD point:
 *
 *   delta_i = 1,
 *   delta_j = -(alpha_i z^shift_i)/(alpha_j z^shift_j),
 *
 * so the individual claims change while their batched value does not.  A
 * prover which then rebuilds w/fold/query messages obtains a self-consistent
 * downstream transcript.  Merely mutating an already-built proof does not
 * exercise this attack.
 *
 * This helper is deliberately independent of the production prover.  It
 * proves the algebraic cancellation condition and keeps the protocol finding
 * explicit while the backend transcript is being cut over.
 */
struct Fri3AlgAdaptiveEvaluationOrderAudit {
    uint32_t version{1};
    uint32_t n_coeffs{0};
    std::vector<Fp3> forged_evals_z1;
    std::vector<Fp3> forged_evals_z2;
    Fp3 honest_batched_z1{};
    Fp3 forged_batched_z1{};
    Fp3 honest_batched_z2{};
    Fp3 forged_batched_z2{};
    bool z1_claim_vector_changed{false};
    bool z2_claim_vector_changed{false};
    bool z1_batched_value_unchanged{false};
    bool z2_batched_value_unchanged{false};
    bool self_consistent_legacy_kernel_exhibited{false};
    /** Hard result for the legacy alpha-before-claims order. */
    bool legacy_order_individual_eval_binding{false};
    /**
     * Conditional result for
     * roots -> z -> claims -> fresh independent alpha:
     * the exhibited delta must be fixed before alpha and survives the random
     * linear test with probability at most 1/|Fp3|.  This is one conservative
     * field event even though two OOD points are opened with the same alpha.
     */
    bool post_claim_random_batching_blocks_adaptive_kernel{false};
    uint32_t conservative_post_claim_binding_bits{0};
    std::string note;
};

namespace fri3_alg_order_audit_detail {

inline Fp3 Pow(Fp3 base, uint32_t exponent)
{
    Fp3 out = Fp3::One();
    while (exponent > 0) {
        if ((exponent & 1U) != 0) {
            out = gkr_field::Mul(out, base);
        }
        base = gkr_field::Mul(base, base);
        exponent >>= 1;
    }
    return out;
}

inline Fp3 BatchedValue(
    const std::vector<Fp3>& coefficients,
    const std::vector<uint32_t>& column_len,
    uint32_t n_coeffs,
    const Fp3& z,
    const std::vector<Fp3>& evaluations)
{
    Fp3 out = Fp3::Zero();
    for (size_t column = 0;
         column < coefficients.size(); ++column) {
        const uint32_t shift =
            n_coeffs - column_len[column];
        out = gkr_field::Add(
            out,
            gkr_field::Mul(
                gkr_field::Mul(
                    coefficients[column],
                    Pow(z, shift)),
                evaluations[column]));
    }
    return out;
}

inline bool ForgeAtPoint(
    const std::vector<Fp3>& coefficients,
    const std::vector<uint32_t>& column_len,
    uint32_t n_coeffs,
    const Fp3& z,
    std::vector<Fp3>& evaluations)
{
    size_t first = coefficients.size();
    size_t second = coefficients.size();
    std::vector<Fp3> weights(
        coefficients.size(), Fp3::Zero());
    for (size_t column = 0;
         column < coefficients.size(); ++column) {
        weights[column] =
            gkr_field::Mul(
                coefficients[column],
                Pow(
                    z,
                    n_coeffs -
                        column_len[column]));
        if (!gkr_field::Eq(
                weights[column], Fp3::Zero())) {
            if (first == coefficients.size()) {
                first = column;
            } else {
                second = column;
                break;
            }
        }
    }
    if (second == coefficients.size()) return false;
    const Fp3 delta_first = Fp3::One();
    const Fp3 delta_second =
        gkr_field::Neg(
            gkr_field::Mul(
                weights[first],
                gkr_field::Inv(weights[second])));
    evaluations[first] =
        gkr_field::Add(
            evaluations[first], delta_first);
    evaluations[second] =
        gkr_field::Add(
            evaluations[second], delta_second);
    return true;
}

inline bool Different(
    const std::vector<Fp3>& left,
    const std::vector<Fp3>& right)
{
    if (left.size() != right.size()) return true;
    for (size_t index = 0; index < left.size(); ++index) {
        if (!gkr_field::Eq(left[index], right[index])) {
            return true;
        }
    }
    return false;
}

} // namespace fri3_alg_order_audit_detail

[[nodiscard]] inline Fri3AlgAdaptiveEvaluationOrderAudit
AuditFri3AlgAdaptiveEvaluationOrder(
    const std::vector<Fp3>& coefficients,
    const std::vector<uint32_t>& column_len,
    uint32_t n_coeffs,
    const Fp3& z1,
    const Fp3& z2,
    const std::vector<Fp3>& evals_z1,
    const std::vector<Fp3>& evals_z2)
{
    Fri3AlgAdaptiveEvaluationOrderAudit out;
    out.n_coeffs = n_coeffs;
    const size_t width = coefficients.size();
    if (width < 2 ||
        column_len.size() != width ||
        evals_z1.size() != width ||
        evals_z2.size() != width ||
        n_coeffs < 2 ||
        (n_coeffs & (n_coeffs - 1)) != 0) {
        out.note =
            "fri3_eval_order_audit:invalid_shape";
        return out;
    }
    for (uint32_t length : column_len) {
        if (length == 0 || length > n_coeffs) {
            out.note =
                "fri3_eval_order_audit:invalid_length";
            return out;
        }
    }

    out.forged_evals_z1 = evals_z1;
    out.forged_evals_z2 = evals_z2;
    out.honest_batched_z1 =
        fri3_alg_order_audit_detail::BatchedValue(
            coefficients, column_len, n_coeffs,
            z1, evals_z1);
    out.honest_batched_z2 =
        fri3_alg_order_audit_detail::BatchedValue(
            coefficients, column_len, n_coeffs,
            z2, evals_z2);
    if (!fri3_alg_order_audit_detail::ForgeAtPoint(
            coefficients, column_len, n_coeffs,
            z1, out.forged_evals_z1) ||
        !fri3_alg_order_audit_detail::ForgeAtPoint(
            coefficients, column_len, n_coeffs,
            z2, out.forged_evals_z2)) {
        out.note =
            "fri3_eval_order_audit:"
            "fewer_than_two_nonzero_weights";
        return out;
    }
    out.forged_batched_z1 =
        fri3_alg_order_audit_detail::BatchedValue(
            coefficients, column_len, n_coeffs,
            z1, out.forged_evals_z1);
    out.forged_batched_z2 =
        fri3_alg_order_audit_detail::BatchedValue(
            coefficients, column_len, n_coeffs,
            z2, out.forged_evals_z2);
    out.z1_claim_vector_changed =
        fri3_alg_order_audit_detail::Different(
            evals_z1, out.forged_evals_z1);
    out.z2_claim_vector_changed =
        fri3_alg_order_audit_detail::Different(
            evals_z2, out.forged_evals_z2);
    out.z1_batched_value_unchanged =
        gkr_field::Eq(
            out.honest_batched_z1,
            out.forged_batched_z1);
    out.z2_batched_value_unchanged =
        gkr_field::Eq(
            out.honest_batched_z2,
            out.forged_batched_z2);
    out.self_consistent_legacy_kernel_exhibited =
        out.z1_claim_vector_changed &&
        out.z2_claim_vector_changed &&
        out.z1_batched_value_unchanged &&
        out.z2_batched_value_unchanged;
    out.legacy_order_individual_eval_binding = false;
    out.post_claim_random_batching_blocks_adaptive_kernel =
        out.self_consistent_legacy_kernel_exhibited;
    // Goldilocks Fp3 has just under 192 bits.  State the conservative integer
    // floor and leave protocol-wide union/grinding losses to the global
    // theorem.
    out.conservative_post_claim_binding_bits =
        out.self_consistent_legacy_kernel_exhibited
        ? 191
        : 0;
    out.note =
        out.self_consistent_legacy_kernel_exhibited
        ? "fri3_eval_order_audit:legacy_adaptive_kernel_"
          "confirmed;post_claim_alpha_required"
        : "fri3_eval_order_audit:no_kernel_exhibited";
    return out;
}

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_FRI_EXT3_ALG_ORDER_AUDIT_H

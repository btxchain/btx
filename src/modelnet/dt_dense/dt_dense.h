// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_DENSE_H
#define BITCOIN_MODELNET_DT_DENSE_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Portable dense GQA profile. This is not a V4.1 hardware port. */
inline constexpr char DT_DENSE_PROFILE[] = "dense_gqa_v1";

/** The same consumer already added a gradient. The sum stays. */
inline constexpr char DT_DENSE_DUPLICATE[] = "DUPLICATE";

/** StepAdam ran before both query heads had contributed. */
inline constexpr char DT_DENSE_MISSING[] = "MISSING";

/** Query head 0. One of the two required consumers of the shared owner. */
inline constexpr char DT_DENSE_HEAD0[] = "head0";

/** Query head 1. One of the two required consumers of the shared owner. */
inline constexpr char DT_DENSE_HEAD1[] = "head1";

/** Input or gradient length does not match the reduced geometry. */
inline constexpr char DT_DENSE_SHAPE[] = "SHAPE";

/** A value was not finite. Stored weights and moments stay. */
inline constexpr char DT_DENSE_NONFINITE[] = "NONFINITE";

/** Backward was asked for before a stored forward. */
inline constexpr char DT_DENSE_FORWARD[] = "FORWARD";

/** AdamW arguments are outside the pinned recipe. State stays. */
inline constexpr char DT_DENSE_OPT_CONFIG[] = "OPT_CONFIG";

/** The consumer id is not one of the two query heads. */
inline constexpr char DT_DENSE_CONSUMER[] = "CONSUMER";

/**
 * FP32 causal grouped-query attention with one owned weight.
 *
 * Geometry is hidden 8, heads 2, kv heads 1, sequence 4. Head dim is 4.
 * hidden % heads == 0 and heads % kv_heads == 0.
 *
 * The owner is one vector of length hidden. Both query heads share the
 * key and value built from that vector:
 *   k[j][c] = W[c] * x[j][c] + W[4+c] * x[j][4+c]
 *   v[j][c] = W[c] * x[j][4+c] + W[4+c] * x[j][c]
 * Position i softmaxes scores against keys j <= i only, then mixes those
 * values. The stored output at i does not depend on inputs at j > i.
 *
 * Squared loss is 0.5 * sum(y^2). Backward splits dW into head0 and head1.
 * NoteContribution adds each consumer once. StepAdam is AdamW on the owner
 * and refuses with MISSING until both consumers have contributed.
 *
 * qualified_v41() stays false. gpu() stays false. launched() and broadcast()
 * stay false. automatic_spend() stays "0". bytes_moved() and atoms_moved()
 * stay 0. GpuStep and the unlinked engines deepep, deepgemm, and dualpipe
 * return false with ENGINE_ABSENT and do not change the weight. No process
 * is spawned.
 */
class DtDense {
public:
    static constexpr int kHidden = 8;
    static constexpr int kHeads = 2;
    static constexpr int kKvHeads = 1;
    static constexpr int kSequence = 4;
    static constexpr int kHeadDim = kHidden / kHeads;

    static_assert(kHidden % kHeads == 0, "hidden must divide across heads");
    static_assert(kHeads % kKvHeads == 0, "heads must divide across kv heads");
    static_assert(kHeadDim % 2 == 0, "head dim stays even");
    static_assert(kHeadDim * kHeads == kHidden, "heads tile the hidden width");

    DtDense();

    const char* profile() const;
    bool qualified_v41() const;
    bool gpu() const;
    bool launched() const;
    bool broadcast() const;
    std::string automatic_spend() const;
    std::int64_t bytes_moved() const;
    std::int64_t atoms_moved() const;

    int hidden() const;
    int heads() const;
    int kv_heads() const;
    int sequence() const;

    const std::vector<float>& Weight() const;
    bool SetWeight(std::size_t index, float value);

    /** Row-major input [sequence][hidden]. Stores the causal output. */
    bool Forward(const std::vector<float>& input, std::string& err);
    const std::vector<float>& Output() const;
    /** 0.5 * sum of squares of the stored output. */
    float SquaredLoss() const;

    /** Analytic d(squared loss)/dW, split across the two query heads. */
    bool Backward(std::string& err);
    const std::vector<float>& AnalyticGradient() const;
    const std::vector<float>& ConsumerGradient(const std::string& consumer) const;

    /**
     * Add this consumer's gradient into the owner once.
     * The same consumer again sets err to DUPLICATE and does not add.
     */
    bool NoteContribution(const std::string& consumer, const std::vector<float>& gradient, std::string& err);
    const std::vector<float>& ContributionSum() const;

    /**
     * AdamW on the owner. Before both consumers have contributed, sets err
     * to MISSING and leaves the weight and both moments unchanged.
     */
    bool StepAdam(float lr, float beta1, float beta2, float eps, float weight_decay, std::string& err);
    const std::vector<float>& Moment1() const;
    const std::vector<float>& Moment2() const;
    std::int64_t adam_step() const;

    /** No GPU step. err is ENGINE_ABSENT. The weight stays. */
    bool GpuStep(std::string& err);
    /**
     * deepep, deepgemm, and dualpipe are absent. err is ENGINE_ABSENT.
     * The weight stays. No process is spawned.
     */
    bool GpuStep(const std::string& engine, std::string& err);

private:
    bool RefuseAbsent(std::string& err);
    int ConsumerIndex(const std::string& consumer) const;

    std::vector<float> m_weight;
    std::vector<float> m_output;
    std::vector<float> m_input;
    std::vector<float> m_value;
    std::vector<float> m_prob;
    std::vector<float> m_grad;
    std::vector<float> m_consumer_grad[2];
    std::vector<float> m_sum;
    std::vector<float> m_m;
    std::vector<float> m_v;
    std::vector<float> m_empty;
    bool m_have_forward{false};
    bool m_got[2]{false, false};
    std::int64_t m_adam_step{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_DENSE_H

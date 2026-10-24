// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_MASK_DT_MASK_H
#define BITCOIN_MODELNET_DT_MASK_DT_MASK_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/** The sample id was empty, or Reduce ran with no stored sample. */
inline constexpr char DT_MASK_SAMPLE[] = "SAMPLE";

/** The token count was below 1. Nothing is stored. */
inline constexpr char DT_MASK_MASK[] = "MASK";

/**
 * The reduced token mean does not fit in int64.
 * The previous numerator and denominator stay.
 */
inline constexpr char DT_MASK_OVERFLOW[] = "OVERFLOW";

/**
 * In-memory token-normalized gradient mean for unequal masks.
 *
 * Add stores one sample. An empty sample id is SAMPLE and stores nothing.
 * A token count below 1 is MASK and stores nothing. A sample id already
 * stored is NIFDT_REPLAY and the first gradient and token count stay.
 *
 * Reduce publishes sum(gradient) / sum(tokens) across stored samples.
 * The denominator is the token total, so a one-token sample and a
 * three-token sample weigh the mean as 1 and 3. Gradients 2 and 4 with
 * token counts 1 and 3 are 6/4, which reduces to 3/2. Fewer than one
 * stored sample is SAMPLE and leaves the previous fraction in place.
 * num() and den() are that reduced fraction. den() is positive.
 * Before the first successful Reduce they are 0 and 1.
 *
 * Gpu returns false with NIFDT_ENGINE_ABSENT and leaves num() and den()
 * unchanged. launched(), gpu(), and broadcast() stay false.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND ("0").
 * hardware_qualified() stays false. No socket is opened and no process
 * is started.
 */
class DtMask {
public:
    bool Add(const std::string& sample, int64_t gradient, int64_t tokens, std::string& err);
    bool Reduce(std::string& err);
    bool Gpu(std::string& err);

    /** Reduced numerator. 0 before the first successful Reduce. */
    int64_t num() const { return m_num; }
    /** Reduced positive denominator. 1 before the first successful Reduce. */
    int64_t den() const { return m_den; }

    int64_t sample_count() const;
    bool has_sample(const std::string& sample) const;
    /** Stored gradient, or 0 when the sample was not stored. */
    int64_t gradient_of(const std::string& sample) const;
    /** Stored token count, or 0 when the sample was not stored. */
    int64_t tokens_of(const std::string& sample) const;

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool hardware_qualified() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Sample {
        int64_t gradient{0};
        int64_t tokens{0};
    };

    std::map<std::string, Sample> m_samples;
    int64_t m_num{0};
    int64_t m_den{1};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_MASK_DT_MASK_H

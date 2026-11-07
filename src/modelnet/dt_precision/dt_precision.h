// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_PRECISION_H
#define BITCOIN_MODELNET_DT_PRECISION_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** Active profile is not a name this engine stores, or StepFp32 is not on fp32. */
inline constexpr char DT_PRECISION_PROFILE[] = "PROFILE";

/** Selectable compute profile. The master weight stays in this format. */
inline constexpr char DT_PRECISION_FP32[] = "fp32";

/** Selectable compute profile. StepFp32 does not run while this is active. */
inline constexpr char DT_PRECISION_BF16[] = "bf16";

/** Named, but no kernel is linked. SetProfile does not store it. */
inline constexpr char DT_PRECISION_FP8[] = "fp8";

/** Named, but no kernel is linked. SetProfile does not store it. */
inline constexpr char DT_PRECISION_FP4[] = "fp4";

/**
 * FP32 master weight with an optional low-precision cache tag.
 *
 * The master value starts at 1.0. Its precision tag stays fp32. The active
 * profile starts as fp32.
 *
 * SetProfile accepts fp32 and bf16. fp8 and fp4 are not linked: both return
 * false with ENGINE_ABSENT, leave the active profile, and leave the master.
 * That refusal is not a successful FP8 or FP4 step. Any other name is
 * PROFILE and stores nothing.
 *
 * StepFp32 applies master = master - lr * gradient only while the active
 * profile is fp32. A nonzero gradient and learning rate change the weight.
 * Any other active profile, and a non-finite gradient or learning rate, is
 * PROFILE and leaves the master. training_proved() becomes true only after
 * that update succeeds.
 *
 * CacheLowPrecision records a bf16 cache tag. The master value and the master
 * tag stay fp32. low_precision_cache() does not set training_proved().
 *
 * gpu(), launched(), and broadcast() stay false. automatic_spend() is "0".
 * bytes_moved() and atoms_moved() stay 0.
 */
class DtPrecision {
public:
    bool SetProfile(const std::string& name, std::string& err);
    bool StepFp32(double gradient, double lr, std::string& err);
    bool CacheLowPrecision(std::string& err);

    const std::string& profile() const { return m_profile; }
    double master() const { return m_master; }
    const std::string& master_precision() const { return m_master_precision; }
    const std::string& cache_tag() const { return m_cache_tag; }
    bool low_precision_cache() const { return m_low_precision_cache; }
    bool training_proved() const { return m_training_proved; }

    bool gpu() const;
    bool launched() const;
    bool broadcast() const;
    std::string automatic_spend() const;
    std::int64_t bytes_moved() const;
    std::int64_t atoms_moved() const;

private:
    double m_master{1.0};
    std::string m_profile{DT_PRECISION_FP32};
    std::string m_master_precision{DT_PRECISION_FP32};
    std::string m_cache_tag;
    bool m_low_precision_cache{false};
    bool m_training_proved{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_PRECISION_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_precision/dt_precision.h>

#include <cmath>

namespace modelnet {

bool DtPrecision::SetProfile(const std::string& name, std::string& err)
{
    if (name == DT_PRECISION_FP8 || name == DT_PRECISION_FP4) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (name != DT_PRECISION_FP32 && name != DT_PRECISION_BF16) {
        err = DT_PRECISION_PROFILE;
        return false;
    }
    m_profile = name;
    err.clear();
    return true;
}

bool DtPrecision::StepFp32(double gradient, double lr, std::string& err)
{
    if (m_profile != DT_PRECISION_FP32 || !std::isfinite(gradient) || !std::isfinite(lr)) {
        err = DT_PRECISION_PROFILE;
        return false;
    }
    const double updated = m_master - lr * gradient;
    if (!std::isfinite(updated)) {
        err = DT_PRECISION_PROFILE;
        return false;
    }
    m_master = updated;
    m_training_proved = true;
    err.clear();
    return true;
}

bool DtPrecision::CacheLowPrecision(std::string& err)
{
    m_cache_tag = DT_PRECISION_BF16;
    m_low_precision_cache = true;
    err.clear();
    return true;
}

bool DtPrecision::gpu() const
{
    return false;
}

bool DtPrecision::launched() const
{
    return false;
}

bool DtPrecision::broadcast() const
{
    return false;
}

std::string DtPrecision::automatic_spend() const
{
    return std::string{NIFDT_AUTOMATIC_SPEND};
}

std::int64_t DtPrecision::bytes_moved() const
{
    return static_cast<std::int64_t>(0);
}

std::int64_t DtPrecision::atoms_moved() const
{
    return static_cast<std::int64_t>(0);
}

} // namespace modelnet

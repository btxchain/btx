// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_measure/swarm_measure.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

bool SwarmMeasure::Measure(const std::vector<int64_t>& samples_ms, std::string& err)
{
    if (samples_ms.empty()) {
        err = kSwarmMeasureMeasure;
        return false;
    }
    for (const int64_t sample : samples_ms) {
        if (sample < 0) {
            err = kSwarmMeasureMeasure;
            return false;
        }
    }

    std::vector<int64_t> ordered = samples_ms;
    std::sort(ordered.begin(), ordered.end());

    const int64_t n = static_cast<int64_t>(ordered.size());
    // Lower of the two middle samples when n is even: index (n - 1) / 2.
    const int64_t p50_index = (n - 1) / 2;
    // Index (n - 1) * 95 / 100, split so the multiply does not wrap.
    const int64_t span = n - 1;
    const int64_t p95_index = (span / 100) * 95 + (span % 100) * 95 / 100;

    m_count = n;
    m_min_ms = ordered.front();
    m_max_ms = ordered.back();
    m_p50 = ordered[static_cast<std::size_t>(p50_index)];
    m_p95 = ordered[static_cast<std::size_t>(p95_index)];
    m_local_measured = true;
    err.clear();
    return true;
}

bool SwarmMeasure::Platform(const std::string& name, const std::string& evidence, std::string& err)
{
    if (name.empty()) {
        err = kSwarmMeasurePlatform;
        return false;
    }
    if (name == kSwarmMeasureWindows) {
        if (evidence.empty()) {
            err = kSwarmMeasureWindowsAbsent;
            return false;
        }
        m_platform_name = name;
        m_platform_evidence = evidence;
        err.clear();
        return true;
    }
    if (name == kSwarmMeasureLinux) {
        if (evidence.empty()) {
            err = kSwarmMeasureEvidence;
            return false;
        }
        m_platform_name = name;
        m_platform_evidence = evidence;
        err.clear();
        return true;
    }
    err = kSwarmMeasurePlatform;
    return false;
}

bool SwarmMeasure::local_measured() const
{
    return m_local_measured;
}

bool SwarmMeasure::gpu_measured() const
{
    return kSwarmMeasureGpuMeasured;
}

bool SwarmMeasure::gpu_passed() const
{
    return kSwarmMeasureGpuPassed;
}

bool SwarmMeasure::windows_passed() const
{
    return kSwarmMeasureWindowsPassed;
}

int64_t SwarmMeasure::count() const
{
    return m_count;
}

int64_t SwarmMeasure::min_ms() const
{
    return m_min_ms;
}

int64_t SwarmMeasure::max_ms() const
{
    return m_max_ms;
}

int64_t SwarmMeasure::p50() const
{
    return m_p50;
}

int64_t SwarmMeasure::p95() const
{
    return m_p95;
}

const std::string& SwarmMeasure::platform_name() const
{
    return m_platform_name;
}

const std::string& SwarmMeasure::platform_evidence() const
{
    return m_platform_evidence;
}

bool SwarmMeasure::launched() const
{
    return kSwarmMeasureLaunched;
}

bool SwarmMeasure::gpu() const
{
    return kSwarmMeasureGpu;
}

bool SwarmMeasure::broadcast() const
{
    return kSwarmMeasureBroadcast;
}

std::string SwarmMeasure::automatic_spend() const
{
    return std::string{kSwarmMeasureAutomaticSpend};
}

int64_t SwarmMeasure::bytes_moved() const
{
    return kSwarmMeasureBytesMoved;
}

} // namespace modelnet

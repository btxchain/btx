// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_MEASURE_H
#define BITCOIN_MODELNET_SWARM_MEASURE_H

#include <modelnet/swarm_measure/codes.h>
#include <modelnet/swarm_measure/limits.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Measurement and platform record.
 *
 * Measure copies the sample list, sorts that copy, and stores count, min,
 * max, p50, and p95 as integers. An empty list is MEASURE and stores
 * nothing. Any negative sample is MEASURE and stores nothing. p50 is the
 * middle sample when the count is odd, and the lower of the two middle
 * samples when the count is even. p95 is the sample at index
 * (count - 1) * 95 / 100. A stored measure sets local_measured().
 * gpu_measured() and gpu_passed() stay false. This is not a GPU benchmark.
 *
 * Platform stores one name and its evidence. An empty name is PLATFORM
 * and stores nothing. The name windows with empty evidence is
 * WINDOWS_ABSENT and stores nothing. Non-empty windows evidence is stored
 * as a record, and windows_passed() still returns false. There is no
 * method that sets windows_passed() true. The name linux with empty
 * evidence is EVIDENCE and stores nothing. Non-empty linux evidence is
 * stored and platform_name() returns linux. Any other name is PLATFORM
 * and stores nothing.
 *
 * A refused call leaves a previously stored measure or platform record
 * unchanged. launched(), gpu(), and broadcast() stay false.
 * automatic_spend() returns "0". bytes_moved() returns 0.
 */
class SwarmMeasure {
public:
    bool Measure(const std::vector<int64_t>& samples_ms, std::string& err);
    bool Platform(const std::string& name, const std::string& evidence, std::string& err);

    bool local_measured() const;
    bool gpu_measured() const;
    bool gpu_passed() const;
    bool windows_passed() const;

    int64_t count() const;
    int64_t min_ms() const;
    int64_t max_ms() const;
    int64_t p50() const;
    int64_t p95() const;

    const std::string& platform_name() const;
    const std::string& platform_evidence() const;

    bool launched() const;
    bool gpu() const;
    bool broadcast() const;
    std::string automatic_spend() const;
    int64_t bytes_moved() const;

private:
    bool m_local_measured{false};
    int64_t m_count{0};
    int64_t m_min_ms{0};
    int64_t m_max_ms{0};
    int64_t m_p50{0};
    int64_t m_p95{0};
    std::string m_platform_name;
    std::string m_platform_evidence;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_MEASURE_H

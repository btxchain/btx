// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MATMUL_COMPUTE_PASSPORT_H
#define BITCOIN_MATMUL_COMPUTE_PASSPORT_H

#include <cstdint>
#include <string>
#include <vector>

class UniValue;

namespace pwc {

struct PassportSamples {
    std::string profile_name;
    std::vector<uint64_t> wall_us;
    int64_t generated_at_ms{0};
    std::string backend_requested;
    std::string backend_resolved;
    bool all_fully_accelerated{false};
    bool device_backend_present{false};
    uint64_t device_calls{0};
    uint64_t device_macs{0};
    uint64_t cpu_calls{0};
    uint64_t cpu_macs{0};
    uint64_t cpu_fallbacks{0};
    uint64_t device_xof_calls{0};
    uint64_t device_xof_fallbacks{0};
    uint64_t host_xof_calls{0};
    std::string provider_family;
    std::string device_architecture;
    std::string runtime_identity;
    std::string driver_identity;
    uint64_t device_memory_bytes{0};
    bool native_fp4_available{false};
    bool native_fp8_available{false};
    bool resident_profile_support{false};
    std::string embedded_source_revision;
    std::string source_tree_fingerprint;
    bool embedded_source_dirty{false};
    std::string raw_report_digest;
};

/** floor(sample_count * 1e6 * 3.6e9 / total_wall_us). Rejects zero and overflow. */
bool MicrounitsPerHour(uint64_t sample_count, uint64_t total_wall_us, uint64_t& out, std::string& err);

/** Convert finite non-negative seconds to integer microseconds. */
bool WallSecondsToMicros(const std::vector<double>& seconds, std::vector<uint64_t>& out, std::string& err);

bool BuildPassport(const PassportSamples& samples, UniValue& out, std::string& err);

/** A self-attested passport is capability evidence, not a qualification. */
bool PassportIsSelfAttested(const UniValue& passport);

} // namespace pwc

#endif

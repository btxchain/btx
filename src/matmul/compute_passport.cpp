// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/compute_passport.h>

#include <matmul/compute_profile.h>

#include <univalue.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cmath>
#include <limits>

namespace pwc {
namespace {

uint64_t NearestRank(std::vector<uint64_t> sorted, double q)
{
    if (sorted.empty()) return 0;
    std::sort(sorted.begin(), sorted.end());
    const double rank = std::ceil(q * static_cast<double>(sorted.size()));
    size_t idx = rank < 1.0 ? 0 : static_cast<size_t>(rank) - 1;
    if (idx >= sorted.size()) idx = sorted.size() - 1;
    return sorted[idx];
}

} // namespace

bool MicrounitsPerHour(uint64_t sample_count, uint64_t total_wall_us, uint64_t& out, std::string& err)
{
    if (sample_count == 0 || total_wall_us == 0) {
        err = "COMPUTE_RATE_TOO_LOW";
        return false;
    }
    constexpr uint64_t kScale = 1000000ull * 3600000000ull;
    const unsigned __int128 num = static_cast<unsigned __int128>(sample_count) * kScale;
    if (num / kScale != sample_count) {
        err = "COMPUTE_CREDIT_OVERFLOW";
        return false;
    }
    const unsigned __int128 rate = num / total_wall_us;
    if (rate > std::numeric_limits<uint64_t>::max()) {
        err = "COMPUTE_CREDIT_OVERFLOW";
        return false;
    }
    out = static_cast<uint64_t>(rate);
    return true;
}

bool WallSecondsToMicros(const std::vector<double>& seconds, std::vector<uint64_t>& out, std::string& err)
{
    out.clear();
    out.reserve(seconds.size());
    for (double s : seconds) {
        if (!std::isfinite(s) || s < 0.0) {
            err = "COMPUTE_RECORD_INVALID";
            return false;
        }
        const long double us = static_cast<long double>(s) * 1000000.0L;
        if (us > static_cast<long double>(std::numeric_limits<uint64_t>::max())) {
            err = "COMPUTE_CREDIT_OVERFLOW";
            return false;
        }
        out.push_back(static_cast<uint64_t>(std::llround(us)));
    }
    return true;
}

bool BuildPassport(const PassportSamples& samples, UniValue& out, std::string& err)
{
    if (samples.wall_us.empty() || samples.wall_us.size() > 100000) {
        err = "COMPUTE_RECORD_INVALID";
        return false;
    }
    std::string code;
    const WorkProfile* profile = FindWorkProfile(samples.profile_name, /*allow_test=*/true, code);
    if (!profile) {
        err = code.empty() ? "COMPUTE_PROFILE_UNKNOWN" : code;
        return false;
    }
    uint64_t total = 0;
    uint64_t min_us = std::numeric_limits<uint64_t>::max();
    uint64_t max_us = 0;
    for (uint64_t us : samples.wall_us) {
        if (us == 0) {
            err = "COMPUTE_RATE_TOO_LOW";
            return false;
        }
        if (total > std::numeric_limits<uint64_t>::max() - us) {
            err = "COMPUTE_CREDIT_OVERFLOW";
            return false;
        }
        total += us;
        min_us = std::min(min_us, us);
        max_us = std::max(max_us, us);
    }
    uint64_t rate = 0;
    if (!MicrounitsPerHour(samples.wall_us.size(), total, rate, err)) return false;

    UniValue o(UniValue::VOBJ);
    o.pushKV("kind", "compute_passport_v1");
    o.pushKV("schema_version", 1);
    o.pushKV("profile_id", ProfileIdHex(*profile));
    o.pushKV("profile_name", profile->profile_name);
    o.pushKV("test_only", profile->test_only);
    o.pushKV("self_attested", true);
    o.pushKV("generated_at_ms", samples.generated_at_ms);
    o.pushKV("sample_count", static_cast<uint64_t>(samples.wall_us.size()));
    o.pushKV("total_wall_us", total);
    o.pushKV("sample_min_us", min_us);
    o.pushKV("sample_max_us", max_us);
    o.pushKV("p50_us", NearestRank(samples.wall_us, 0.50));
    o.pushKV("p95_us", NearestRank(samples.wall_us, 0.95));
    o.pushKV("p99_us", NearestRank(samples.wall_us, 0.99));
    o.pushKV("p99_claimable", samples.wall_us.size() >= 100);
    o.pushKV("p1e_microunits_per_hour", rate);
    o.pushKV("backend_requested", samples.backend_requested);
    o.pushKV("backend_resolved", samples.backend_resolved);
    o.pushKV("all_fully_accelerated", samples.all_fully_accelerated);
    o.pushKV("device_backend_present", samples.device_backend_present);
    o.pushKV("device_calls", samples.device_calls);
    o.pushKV("device_macs", samples.device_macs);
    o.pushKV("cpu_calls", samples.cpu_calls);
    o.pushKV("cpu_macs", samples.cpu_macs);
    o.pushKV("cpu_fallbacks", samples.cpu_fallbacks);
    o.pushKV("device_xof_calls", samples.device_xof_calls);
    o.pushKV("device_xof_fallbacks", samples.device_xof_fallbacks);
    o.pushKV("host_xof_calls", samples.host_xof_calls);
    UniValue device(UniValue::VOBJ);
    device.pushKV("provider_family", samples.provider_family);
    device.pushKV("device_architecture", samples.device_architecture);
    device.pushKV("runtime_identity", samples.runtime_identity);
    device.pushKV("driver_identity", samples.driver_identity);
    o.pushKV("device", device);
    UniValue caps(UniValue::VOBJ);
    caps.pushKV("device_memory_bytes", samples.device_memory_bytes);
    caps.pushKV("native_fp4_available", samples.native_fp4_available);
    caps.pushKV("native_fp8_available", samples.native_fp8_available);
    caps.pushKV("resident_profile_support", samples.resident_profile_support);
    o.pushKV("capability", caps);
    o.pushKV("embedded_source_revision", samples.embedded_source_revision);
    o.pushKV("source_tree_fingerprint", samples.source_tree_fingerprint);
    o.pushKV("embedded_source_dirty", samples.embedded_source_dirty);
    o.pushKV("raw_report_digest", samples.raw_report_digest);
    UniValue evidence(UniValue::VOBJ);
    evidence.pushKV("public", true);
    evidence.pushKV("host_identity_omitted", true);
    o.pushKV("public_evidence", evidence);
    o.pushKV("note", "Self-attested performance evidence. Settlement requires accepted receipts.");
    out = std::move(o);
    return true;
}

bool PassportIsSelfAttested(const UniValue& passport)
{
    return passport.isObject() && passport.exists("self_attested") && passport["self_attested"].isTrue();
}

} // namespace pwc

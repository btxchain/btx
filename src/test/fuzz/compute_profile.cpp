// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/compute_passport.h>
#include <matmul/compute_profile.h>
#include <test/fuzz/fuzz.h>
#include <univalue.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>

FUZZ_TARGET(compute_profile)
{
    if (buffer.size() > 4096) return;
    const std::string name(buffer.begin(), buffer.end());
    std::string code;
    (void)pwc::FindWorkProfile(name, true, code);
    (void)pwc::FindWorkProfile(name, false, code);

    pwc::PassportSamples samples;
    samples.profile_name = name.substr(0, std::min<size_t>(name.size(), 64));
    samples.backend_requested = "cpu";
    samples.backend_resolved = "cpu";
    const size_t n = std::min<size_t>(buffer.size(), 8);
    for (size_t i = 0; i < n; ++i) {
        samples.wall_us.push_back(static_cast<uint64_t>(buffer[i]) + 1);
    }
    if (samples.wall_us.empty()) samples.wall_us.push_back(1);
    UniValue out;
    std::string err;
    (void)pwc::BuildPassport(samples, out, err);
}

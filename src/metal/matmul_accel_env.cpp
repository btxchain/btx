// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <metal/matmul_accel_env.h>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>

namespace btx::metal::detail {

TranscriptPipelineMode ParseTranscriptPipelineEnv(const char* env_value)
{
    if (env_value == nullptr || env_value[0] == '\0' || std::strcmp(env_value, "auto") == 0) {
        return TranscriptPipelineMode::AUTO;
    }
    if (std::strcmp(env_value, "legacy") == 0) {
        return TranscriptPipelineMode::LEGACY;
    }
    if (std::strcmp(env_value, "fused") == 0) {
        return TranscriptPipelineMode::FUSED;
    }
    return TranscriptPipelineMode::AUTO;
}

FunctionConstantMode ParseFunctionConstantEnv(const char* env_value)
{
    if (env_value == nullptr || env_value[0] == '\0' || std::strcmp(env_value, "auto") == 0) {
        return FunctionConstantMode::AUTO;
    }
    if (std::strcmp(env_value, "1") == 0 ||
        std::strcmp(env_value, "on") == 0 ||
        std::strcmp(env_value, "true") == 0) {
        return FunctionConstantMode::ENABLED;
    }
    if (std::strcmp(env_value, "0") == 0 ||
        std::strcmp(env_value, "off") == 0 ||
        std::strcmp(env_value, "false") == 0) {
        return FunctionConstantMode::DISABLED;
    }
    return FunctionConstantMode::AUTO;
}

bool ParseTruthyEnv(const char* env_value, bool default_value)
{
    if (env_value == nullptr || env_value[0] == '\0') {
        return default_value;
    }
    if (std::strcmp(env_value, "0") == 0 ||
        std::strcmp(env_value, "false") == 0 ||
        std::strcmp(env_value, "FALSE") == 0 ||
        std::strcmp(env_value, "off") == 0 ||
        std::strcmp(env_value, "OFF") == 0) {
        return false;
    }
    return true;
}

std::optional<uint32_t> ParsePoolSlotsEnv(const char* env_value,
                                          uint32_t max_slots,
                                          uint32_t default_fallback)
{
    if (env_value == nullptr || env_value[0] == '\0') {
        return std::nullopt;
    }

    // Clamp default_fallback into [1, max_slots] up-front so all return paths
    // honour the caller's invariant: the returned value is always in range.
    const uint32_t clamped_default = std::clamp<uint32_t>(default_fallback, 1U, max_slots);

    char* end{nullptr};
    errno = 0;
    const long parsed = std::strtol(env_value, &end, 10);
    const bool parse_failed = (end == env_value) || (*end != '\0');
    if (parse_failed || parsed <= 0) {
        return clamped_default;
    }

    // strtol returns long; clamp to [1, max_slots] before narrowing to uint32_t.
    const long clamped = std::clamp<long>(parsed, 1L, static_cast<long>(max_slots));
    return static_cast<uint32_t>(clamped);
}

} // namespace btx::metal::detail

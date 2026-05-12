// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_METAL_MATMUL_ACCEL_ENV_H
#define BITCOIN_METAL_MATMUL_ACCEL_ENV_H

#include <cstdint>
#include <optional>

// Pure-function parsers for the BTX_MATMUL_METAL_* environment variables that
// configure the Metal MatMul accelerator. Extracted into their own header so
// that the parsing rules — clamping, fallback on malformed input, mode token
// recognition — are unit-testable without spawning a Metal device, mucking
// with process-global env state, or pulling in Objective-C++.
//
// Each function takes the env value as a (possibly null) C string. A null or
// empty pointer is treated as "variable unset". The implementation lives in
// matmul_accel_env.cpp; matmul_accel.mm calls these from the public-facing
// Resolve*() helpers after a single std::getenv() lookup.
//
// These are intentionally placed in the btx::metal::detail namespace: they are
// not part of the supported MatMul backend ABI, only the test suite and
// matmul_accel.mm should call them.

namespace btx::metal::detail {

enum class TranscriptPipelineMode : uint8_t {
    AUTO,
    FUSED,
    LEGACY,
};

// Parse the value of BTX_MATMUL_METAL_PIPELINE.
//
// Recognised tokens (exact case-sensitive match): "auto", "fused", "legacy".
// A null pointer, empty string, or unrecognised token all map to AUTO.
TranscriptPipelineMode ParseTranscriptPipelineEnv(const char* env_value);

enum class FunctionConstantMode : uint8_t {
    AUTO,
    ENABLED,
    DISABLED,
};

// Parse the value of BTX_MATMUL_METAL_FUNCTION_CONSTANTS.
//
// Recognised tokens (exact case-sensitive match):
//   "auto"                              → AUTO
//   "1", "on", "true"                   → ENABLED
//   "0", "off", "false"                 → DISABLED
// A null pointer, empty string, or any other token all map to AUTO.
FunctionConstantMode ParseFunctionConstantEnv(const char* env_value);

// Parse a generic truthy/falsy env value such as BTX_MATMUL_METAL_POOL_PREWARM.
//
// Recognised falsy tokens (exact match): "0", "false", "FALSE", "off", "OFF".
// A null pointer or empty string returns default_value.
// Any other non-empty value is treated as truthy (returns true).
bool ParseTruthyEnv(const char* env_value, bool default_value);

// Parse the value of BTX_MATMUL_METAL_POOL_SLOTS.
//
// Returns std::nullopt if env_value is null or empty (caller should fall back
// to its own auto-detection path).
//
// Returns default_fallback (clamped to [1, max_slots]) if env_value is set but
// fails to parse as a strict base-10 integer or parses to a non-positive value.
//
// Otherwise returns the parsed integer clamped to [1, max_slots].
//
// "Strict" means: leading whitespace is permitted (matches std::strtol), but
// any trailing non-digit character (including whitespace) causes the parse to
// be rejected. Values that overflow long are left to std::strtol's saturated
// positive result and then clamped to max_slots, matching the original inline
// parser in matmul_accel.mm.
std::optional<uint32_t> ParsePoolSlotsEnv(const char* env_value,
                                          uint32_t max_slots,
                                          uint32_t default_fallback);

} // namespace btx::metal::detail

#endif // BITCOIN_METAL_MATMUL_ACCEL_ENV_H

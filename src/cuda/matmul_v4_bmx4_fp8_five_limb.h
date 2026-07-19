// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CUDA_MATMUL_V4_BMX4_FP8_FIVE_LIMB_H
#define BITCOIN_CUDA_MATMUL_V4_BMX4_FP8_FIVE_LIMB_H

#include <matmul/int8_field.h>
#include <matmul/matmul_v4_bmx4.h>

#include <cstdint>
#include <string>
#include <vector>

// Device FP8 five-limb combine lane (Rubin-class planner selection).
//
// The committed object is five balanced base-32 digits in the exact E4M3
// integer alphabet (CPU: matmul::v4::bmx4::ComputeCombineFp8FiveLimbBMX4C).
// A future Rubin native FP8 MMA path may replace the 25 limb-pair GEMMs; until
// silicon headers + qualification exist, this surface is fail-closed and every
// caller MUST use the CPU five-limb reference (always available, exact).
//
// Honesty contract:
//   * IsDeviceFp8FiveLimbAvailable() is true ONLY after a real device kernel
//     TU is linked AND a bit-exact self-test vs the CPU reference passes.
//   * LaunchDeviceFp8FiveLimbCombine never silently returns approximate floats.
//   * Default / no-CUDA builds link a stub: available=false, launch fails closed.

namespace matmul_v4::cuda {

/** True iff a device FP8 five-limb combine kernel is linked and self-tested. */
[[nodiscard]] bool IsDeviceFp8FiveLimbAvailable();

/** True iff the device FP8 five-limb TU was compiled into this binary (does not
 *  imply it is trusted — see IsDeviceFp8FiveLimbAvailable). */
[[nodiscard]] bool IsDeviceFp8FiveLimbCompiled();

/** Device five-limb combine. On success, `out` is byte-identical to
 *  matmul::v4::bmx4::ComputeCombineFp8FiveLimbBMX4C(P, Q, n, m). Returns false
 *  and sets `error` when the device path is unavailable or any safety gate
 *  fails — caller MUST fall back to the CPU reference. */
[[nodiscard]] bool LaunchDeviceFp8FiveLimbCombine(const std::vector<int32_t>& P,
                                                  const std::vector<int32_t>& Q,
                                                  uint32_t n,
                                                  uint32_t m,
                                                  std::vector<::matmul::int8_field::Fq>& out,
                                                  std::string& error);

/** Exact combine with transparent fallback: tries the device path when
 *  available, otherwise runs the CPU five-limb reference. Always produces a
 *  result (or returns false only on invalid dims). `used_device` reports whether
 *  the device kernel served the call (never true for a CPU fallback). */
[[nodiscard]] bool ComputeCombineFp8FiveLimbDeviceOrCpu(const std::vector<int32_t>& P,
                                                        const std::vector<int32_t>& Q,
                                                        uint32_t n,
                                                        uint32_t m,
                                                        std::vector<::matmul::int8_field::Fq>& out,
                                                        bool& used_device,
                                                        std::string& error);

} // namespace matmul_v4::cuda

#endif // BITCOIN_CUDA_MATMUL_V4_BMX4_FP8_FIVE_LIMB_H

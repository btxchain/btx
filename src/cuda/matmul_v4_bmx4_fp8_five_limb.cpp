// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <cuda/matmul_v4_bmx4_fp8_five_limb.h>

// Portable / default build: no Rubin FP8 device kernel. CPU five-limb remains
// the exact always-available path (see doc/btx-matmul-v4.4-exact-accel-lanes.md).

namespace matmul_v4::cuda {

bool IsDeviceFp8FiveLimbCompiled()
{
#if defined(BTX_BMX4C_DEVICE_FP8_FIVE_LIMB)
    return true;
#else
    return false;
#endif
}

bool IsDeviceFp8FiveLimbAvailable()
{
    // Device kernel requires a dedicated CUDA TU + self-qual (see .cu when
    // BTX_BMX4C_DEVICE_FP8_FIVE_LIMB is enabled). Default builds: unavailable.
    return false;
}

bool LaunchDeviceFp8FiveLimbCombine(const std::vector<int32_t>& /*P*/,
                                    const std::vector<int32_t>& /*Q*/,
                                    uint32_t /*n*/,
                                    uint32_t /*m*/,
                                    std::vector<matmul::int8_field::Fq>& /*out*/,
                                    std::string& error)
{
    error = "device FP8 five-limb combine unavailable (no qualified Rubin/FP8 "
            "kernel; use matmul::v4::bmx4::ComputeCombineFp8FiveLimbBMX4C)";
    return false;
}

bool ComputeCombineFp8FiveLimbDeviceOrCpu(const std::vector<int32_t>& P,
                                          const std::vector<int32_t>& Q,
                                          uint32_t n,
                                          uint32_t m,
                                          std::vector<matmul::int8_field::Fq>& out,
                                          bool& used_device,
                                          std::string& error)
{
    used_device = false;
    if (IsDeviceFp8FiveLimbAvailable()) {
        if (LaunchDeviceFp8FiveLimbCombine(P, Q, n, m, out, error)) {
            used_device = true;
            return true;
        }
        // Device advertised but failed — fall through to CPU (fail-closed on
        // the device claim, not on the digest).
    }
    uint32_t m_chk = 0;
    if (!matmul::v4::bmx4::ValidateDimsBMX4C(n, matmul::v4::kTileB, m_chk) || m_chk != m) {
        error = "ComputeCombineFp8FiveLimbDeviceOrCpu: invalid dims";
        return false;
    }
    out = matmul::v4::bmx4::ComputeCombineFp8FiveLimbBMX4C(P, Q, n, m);
    error.clear();
    return true;
}

} // namespace matmul_v4::cuda

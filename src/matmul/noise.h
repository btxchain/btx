// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_NOISE_H
#define BTX_MATMUL_NOISE_H

#include <matmul/matrix.h>

#include <cstdint>
#include <string>
#include <string_view>

class uint256;

namespace matmul::noise {

inline constexpr std::string_view TAG_EL{"matmul_noise_EL_v1"};
inline constexpr std::string_view TAG_ER{"matmul_noise_ER_v1"};
inline constexpr std::string_view TAG_FL{"matmul_noise_FL_v1"};
inline constexpr std::string_view TAG_FR{"matmul_noise_FR_v1"};

struct NoisePair {
    Matrix E_L;
    Matrix E_R;
    Matrix F_L;
    Matrix F_R;
};

struct NoiseGenerationProfile {
    bool parallel_supported{false};
    uint32_t worker_count{1};
    std::string reason;
};

uint256 DeriveNoiseSeed(std::string_view domain_tag, const uint256& sigma);
NoiseGenerationProfile ProbeNoiseGenerationProfile(uint32_t rows, uint32_t cols);
NoisePair Generate(const uint256& sigma, uint32_t n, uint32_t r);

} // namespace matmul::noise

#endif // BTX_MATMUL_NOISE_H

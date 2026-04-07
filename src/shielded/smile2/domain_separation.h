// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_SHIELDED_SMILE2_DOMAIN_SEPARATION_H
#define BTX_SHIELDED_SMILE2_DOMAIN_SEPARATION_H

#include <cstddef>
#include <cstdint>

namespace smile2::domainsep {

constexpr uint32_t BDLOP_MATRIX_B0{0};
constexpr uint32_t BDLOP_VECTOR_B{1};

constexpr uint32_t PUBLIC_ACCOUNT_MATRIX{100};

constexpr uint32_t MEMBERSHIP_C0{200};
constexpr uint32_t MEMBERSHIP_GAMMA1_ROWS{300};
constexpr uint32_t MEMBERSHIP_RECURSION_GAMMA_BASE{330};
constexpr uint32_t MEMBERSHIP_FINAL_GAMMA{360};
constexpr uint32_t MEMBERSHIP_C{400};

constexpr uint32_t CT_ALPHA_BASE{500};
constexpr uint32_t CT_PUBLIC_ACCOUNT_ALPHA{540};
constexpr uint32_t CT_PUBLIC_ACCOUNT_BETA{541};
constexpr uint32_t CT_PUBLIC_ACCOUNT_GAMMA{542};
constexpr uint32_t CT_C0{600};
constexpr uint32_t CT_C{700};
constexpr uint32_t RHO{800};
constexpr uint32_t CT_GAMMA_BASE{820};
constexpr uint32_t CT_OPENING_CHALLENGE_BASE{920};
constexpr uint32_t CT_INPUT_COIN_OPENING{930};
constexpr uint32_t CT_OUTPUT_COIN_OPENING{940};
constexpr uint32_t CT_TUPLE_COIN_ROW{965};
constexpr uint32_t CT_TUPLE_OPENING_COMPRESSION{966};

[[nodiscard]] constexpr uint32_t CtAlphaLevel(size_t level)
{
    return CT_ALPHA_BASE + static_cast<uint32_t>(level);
}

[[nodiscard]] constexpr uint32_t CtGammaRow(size_t row)
{
    return CT_GAMMA_BASE + static_cast<uint32_t>(row);
}

[[nodiscard]] constexpr uint32_t MembershipRecursionGamma(size_t level)
{
    return MEMBERSHIP_RECURSION_GAMMA_BASE + static_cast<uint32_t>(level);
}

} // namespace smile2::domainsep

#endif // BTX_SHIELDED_SMILE2_DOMAIN_SEPARATION_H

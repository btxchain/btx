// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <policy/feerate.h>
#include <tinyformat.h>

#include <cstdlib>

#include <cmath>

CFeeRate::CFeeRate(const CAmount& nFeePaid, uint32_t num_bytes)
{
    const int64_t nSize{num_bytes};

    if (nSize > 0) {
        nSatoshisPerK = nFeePaid * 1000 / nSize;
    } else {
        nSatoshisPerK = 0;
    }
}

CAmount CFeeRate::GetFee(uint32_t num_bytes) const
{
    const int64_t nSize{num_bytes};

    // Be explicit that we're converting from a double to int64_t (CAmount) here.
    // We've previously had issues with the silent double->int64_t conversion.
    CAmount nFee{static_cast<CAmount>(std::ceil(nSatoshisPerK * nSize / 1000.0))};

    if (nFee == 0 && nSize != 0) {
        if (nSatoshisPerK > 0) nFee = CAmount(1);
        if (nSatoshisPerK < 0) nFee = CAmount(-1);
    }

    return nFee;
}

std::string CFeeRate::ToString(const FeeEstimateMode& fee_estimate_mode) const
{
    const auto format_feerate = [](const CAmount fee_rate, const CAmount divisor,
                                   const int decimals, const std::string& currency_unit,
                                   const std::string& size_unit) {
        assert(divisor > 0);
        const char* sign{fee_rate < 0 ? "-" : ""};
        const CAmount quotient{std::abs(fee_rate / divisor)};
        const CAmount remainder{std::abs(fee_rate % divisor)};
        return strprintf("%s%d.%0*d %s/%s", sign, quotient, decimals, remainder,
                         currency_unit, size_unit);
    };
    switch (fee_estimate_mode) {
    case FeeEstimateMode::SAT_VB: return format_feerate(nSatoshisPerK, 1000, 3, CURRENCY_ATOM, "vB");
    default:                      return format_feerate(nSatoshisPerK, COIN, 8, CURRENCY_UNIT, "kvB");
    }
}

std::string CFeeRate::SatsToString() const {
    const char* sign{nSatoshisPerK < 0 ? "-" : ""};
    return strprintf("%s%d.%03d", sign, std::abs(nSatoshisPerK / 1000),
                     std::abs(nSatoshisPerK % 1000));
}

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_TEST_SHIELDED_V2_SEND_RUNTIME_REPORT_H
#define BTX_TEST_SHIELDED_V2_SEND_RUNTIME_REPORT_H

#include <consensus/amount.h>
#include <univalue.h>

#include <cstddef>
#include <vector>

namespace btx::test::shieldedv2send {

enum class RuntimeValidationSurface {
    PREFORK,
    POSTFORK,
};

struct RuntimeScenarioConfig
{
    size_t spend_count{1};
    size_t output_count{2};
};

struct RuntimeReportConfig
{
    size_t warmup_iterations{0};
    size_t measured_iterations{1};
    CAmount fee_sat{1000};
    RuntimeValidationSurface validation_surface{RuntimeValidationSurface::POSTFORK};
    std::vector<RuntimeScenarioConfig> scenarios;
};

UniValue BuildRuntimeReport(const RuntimeReportConfig& config);

} // namespace btx::test::shieldedv2send

#endif // BTX_TEST_SHIELDED_V2_SEND_RUNTIME_REPORT_H

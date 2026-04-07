// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_TEST_SHIELDED_V2_EGRESS_RUNTIME_REPORT_H
#define BTX_TEST_SHIELDED_V2_EGRESS_RUNTIME_REPORT_H

#include <univalue.h>

#include <cstddef>
#include <vector>

namespace btx::test::shieldedv2egress {

struct RuntimeScenarioConfig
{
    size_t output_count{32};
    size_t outputs_per_chunk{32};
};

struct RuntimeReportConfig
{
    size_t warmup_iterations{0};
    size_t measured_iterations{1};
    std::vector<RuntimeScenarioConfig> scenarios;
};

UniValue BuildRuntimeReport(const RuntimeReportConfig& config);

} // namespace btx::test::shieldedv2egress

#endif // BTX_TEST_SHIELDED_V2_EGRESS_RUNTIME_REPORT_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_TEST_SHIELDED_INGRESS_RUNTIME_REPORT_H
#define BTX_TEST_SHIELDED_INGRESS_RUNTIME_REPORT_H

#include <univalue.h>

#include <cstddef>
#include <vector>

namespace btx::test::ingress {

struct RuntimeReportConfig
{
    size_t warmup_iterations{0};
    size_t measured_iterations{1};
    size_t reserve_output_count{1};
    std::vector<size_t> leaf_counts{100, 1000, 5000, 10000};
};

UniValue BuildRuntimeReport(const RuntimeReportConfig& config);

} // namespace btx::test::ingress

#endif // BTX_TEST_SHIELDED_INGRESS_RUNTIME_REPORT_H

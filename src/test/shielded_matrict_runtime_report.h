// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_TEST_SHIELDED_MATRICT_RUNTIME_REPORT_H
#define BTX_TEST_SHIELDED_MATRICT_RUNTIME_REPORT_H

#include <univalue.h>

#include <cstddef>

namespace btx::test::matrictplus {

struct RuntimeReportConfig
{
    size_t warmup_iterations{0};
    size_t measured_iterations{1};
};

UniValue BuildRuntimeReport(const RuntimeReportConfig& config);

} // namespace btx::test::matrictplus

#endif // BTX_TEST_SHIELDED_MATRICT_RUNTIME_REPORT_H

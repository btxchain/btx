// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/proc05/proc05.h>

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

constexpr int64_t kWeight = 3;
constexpr int64_t kBias = 1;

} // namespace

bool Proc05::Run(const std::string& provider_key, bool weights_present, int64_t input, int64_t& output, std::string& err)
{
    if (!provider_key.empty()) {
        err = "PROVIDER";
        return false;
    }
    if (!weights_present) {
        err = "MODEL";
        return false;
    }
    if (input < static_cast<int64_t>(0)) {
        err = "BOUND";
        return false;
    }
    output = input * kWeight + kBias;
    m_last_output = output;
    m_ran = true;
    err.clear();
    return true;
}

} // namespace modelnet

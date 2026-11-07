// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/git_remote/git_remote.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

bool ExactAbsentEngine(const std::string& text)
{
    return text == "vllm" || text == "sglang" || text == "lmcache" ||
           text == "nixl" || text == "mooncake" || text == "rdma" ||
           text == "deepinfer" || text == "dualpipe" || text == "fp8" ||
           text == "fp4";
}

} // namespace

bool GitRemote::Add(const std::string& name, const std::string& url, std::string& err)
{
    if (name.empty() || url.empty()) {
        err = "FIELD";
        return false;
    }
    if (url == "shell") {
        err = "HELPER";
        return false;
    }
    if (url.compare(0, 8, "https://") != 0) {
        err = "HELPER";
        return false;
    }
    if (name.find("private") != std::string::npos || url.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (ExactAbsentEngine(name) || ExactAbsentEngine(url)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (m_on) {
        if (url == m_url) {
            err = NIFDT_REPLAY;
            return false;
        }
        err = "UNCHANGED";
        return false;
    }
    m_on = true;
    m_name = name;
    m_url = url;
    err.clear();
    return true;
}

bool GitRemote::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool GitRemote::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool GitRemote::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool GitRemote::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool GitRemote::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet

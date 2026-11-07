// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/git_origin/git_origin.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {
namespace {

bool LowerHex64(const std::string& digest)
{
    if (digest.size() != 64) return false;
    for (const unsigned char ch : digest) {
        const bool digit = ch >= '0' && ch <= '9';
        const bool lower = ch >= 'a' && ch <= 'f';
        if (!digit && !lower) return false;
    }
    return true;
}

bool ExactEngine(const std::string& digest)
{
    return digest == "vllm" || digest == "sglang" || digest == "lmcache" ||
           digest == "nixl" || digest == "mooncake" || digest == "rdma" ||
           digest == "deepinfer" || digest == "dualpipe" || digest == "fp8" ||
           digest == "fp4";
}

} // namespace

bool GitOrigin::stored(const std::string& name) const
{
    return m_rows.find(name) != m_rows.end();
}

std::string GitOrigin::digest(const std::string& name) const
{
    const auto it = m_rows.find(name);
    if (it == m_rows.end()) return std::string();
    return it->second;
}

bool GitOrigin::Record(const std::string& name, const std::string& digest, std::string& err)
{
    if (name.empty() || digest.empty()) {
        err = "FIELD";
        return false;
    }
    if (name.find("private") != std::string::npos || digest.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (ExactEngine(digest)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (digest == "sha1" || !LowerHex64(digest)) {
        err = "DIGEST";
        return false;
    }
    const auto it = m_rows.find(name);
    if (it != m_rows.end()) {
        if (it->second == digest) {
            err = NIFDT_REPLAY;
            return false;
        }
        err = "UNCHANGED";
        return false;
    }
    m_rows.emplace(name, digest);
    err.clear();
    return true;
}

bool GitOrigin::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool GitOrigin::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool GitOrigin::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool GitOrigin::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool GitOrigin::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet

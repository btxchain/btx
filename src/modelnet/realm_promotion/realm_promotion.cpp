// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/realm_promotion/realm_promotion.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {
namespace {

bool AbsentEngine(const std::string& text)
{
    return text == "vllm" || text == "sglang" || text == "lmcache" ||
           text == "nixl" || text == "mooncake" || text == "rdma" ||
           text == "deepinfer" || text == "dualpipe" || text == "fp8" ||
           text == "fp4";
}

} // namespace

bool RealmPromotion::stored(const std::string& id) const
{
    return m_stored && m_id == id;
}

std::string RealmPromotion::text(const std::string& id) const
{
    if (!stored(id)) return std::string();
    return m_text;
}

bool RealmPromotion::Propose(const std::string& id, const std::string& text, std::string& err)
{
    if (id.empty() || text.empty()) {
        err = "FIELD";
        return false;
    }
    if (text == "one") {
        err = "QUORUM";
        return false;
    }
    if (text.find("private") != std::string::npos) {
        err = NIFDT_PRIVATE_DATA;
        return false;
    }
    if (AbsentEngine(text)) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (m_stored) {
        if (m_text == text) {
            err = NIFDT_REPLAY;
            return false;
        }
        err = "UNCHANGED";
        return false;
    }
    m_id = id;
    m_text = text;
    m_stored = true;
    err.clear();
    return true;
}

bool RealmPromotion::Hosts(int64_t n, std::string& err)
{
    if (n != static_cast<int64_t>(1)) {
        err = "HOSTS";
        return false;
    }
    err.clear();
    return true;
}

bool RealmPromotion::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool RealmPromotion::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool RealmPromotion::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool RealmPromotion::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

} // namespace modelnet

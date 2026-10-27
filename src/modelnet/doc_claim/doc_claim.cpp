// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/doc_claim/doc_claim.h>
#include <modelnet/nifdt_contract/contract.h>

#include <string>
#include <vector>

namespace modelnet {
namespace {

bool KnownSurface(const std::string& surface)
{
    return surface == "readme" || surface == "rpc" || surface == "build" ||
           surface == "recovery" || surface == "operator";
}

bool Forbidden(const std::string& text)
{
    return text.find("release qualified") != std::string::npos ||
           text.find("production ready") != std::string::npos ||
           text.find("gpu passed") != std::string::npos ||
           text.find("windows passed") != std::string::npos;
}

} // namespace

bool DocClaim::stored(const std::string& surface) const
{
    for (const Sentence& row : m_stored) {
        if (row.surface == surface) return true;
    }
    return false;
}

std::string DocClaim::text(const std::string& surface) const
{
    for (const Sentence& row : m_stored) {
        if (row.surface == surface) return row.text;
    }
    return {};
}

bool DocClaim::Claim(const std::string& surface, const std::string& text, std::string& err)
{
    if (!KnownSurface(surface)) {
        err = DOC_CLAIM_SURFACE;
        return false;
    }
    if (text.empty()) {
        err = DOC_CLAIM_TEXT;
        return false;
    }
    if (Forbidden(text)) {
        err = DOC_CLAIM_CLAIM;
        return false;
    }
    if (stored(surface)) {
        err = NIFDT_REPLAY;
        return false;
    }
    m_stored.push_back(Sentence{surface, text});
    err.clear();
    return true;
}

bool DocClaim::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool DocClaim::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool DocClaim::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool DocClaim::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

} // namespace modelnet

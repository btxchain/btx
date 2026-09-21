// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/source_huggingface.h>

#include <modelnet/source_local.h>

#include <cstddef>

namespace modelnet {

HuggingFaceByteSource::HuggingFaceByteSource(std::string locator, std::string snapshot_token,
                                             bool follow_redirects)
    : m_locator(std::move(locator)), m_snapshot_token(std::move(snapshot_token)),
      m_follow_redirects(follow_redirects)
{
}

bool HuggingFaceByteSource::Pin(std::string& err)
{
    // Never follow redirects. A live HTTP client is not wired in this adapter.
    if (m_follow_redirects) {
        err = "redirects forbidden";
        return false;
    }
    if (m_snapshot_token.empty()) {
        err = "snapshot_token";
        return false;
    }
    if (!HuggingFaceLocatorAllowed(m_locator, err)) return false;
    m_recorded_snapshot = m_snapshot_token;
    m_pinned = true;
    return true;
}

bool HuggingFaceByteSource::Read(const ReadExtent& extent, std::vector<unsigned char>& out,
                                 uint64_t budget_bytes, std::string& err)
{
    out.clear();
    if (!m_pinned && !Pin(err)) return false;
    if (!m_has_injected) {
        err = "not wired to live network";
        return false;
    }
    if (extent.length > budget_bytes) {
        err = "credit exhausted";
        return false;
    }
    if (extent.offset > m_injected.size() || extent.length > m_injected.size() - extent.offset) {
        err = "extent";
        return false;
    }
    out.assign(m_injected.begin() + static_cast<std::ptrdiff_t>(extent.offset),
               m_injected.begin() + static_cast<std::ptrdiff_t>(extent.offset + extent.length));
    return true;
}

void HuggingFaceByteSource::InjectTestBytes(std::vector<unsigned char> bytes)
{
    m_injected = std::move(bytes);
    m_has_injected = true;
}

} // namespace modelnet

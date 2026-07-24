// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_BANK_ROOT_CACHE_H
#define BTX_MATMUL_MATMUL_V4_RC_BANK_ROOT_CACHE_H

#include <uint256.h>

#include <cstdint>
#include <mutex>

namespace matmul::v4::rc {

struct RCCoupBankRootCacheKey {
    uint256 template_hash{};
    uint256 params_fingerprint{};
    int32_t height{0};
    uint32_t transcript_version{0};
    uint32_t bank_pages{0};
    uint32_t width{0};

    friend bool operator==(const RCCoupBankRootCacheKey&,
                           const RCCoupBankRootCacheKey&) = default;
};

/**
 * Mining-only in-process memo for the template-scoped coupled bank root.
 *
 * It stores 112 bytes of key/root payload, never bank pages. Consensus validation
 * and winning-candidate CPU reseal leave this unset and recompute independently.
 */
class RCCoupBankRootCache
{
public:
    [[nodiscard]] bool Lookup(const RCCoupBankRootCacheKey& key, uint256& root_out) const
    {
        std::lock_guard<std::mutex> lock{m_mutex};
        if (!m_valid || m_key != key) return false;
        root_out = m_root;
        return true;
    }

    void Store(const RCCoupBankRootCacheKey& key, const uint256& root)
    {
        std::lock_guard<std::mutex> lock{m_mutex};
        m_key = key;
        m_root = root;
        m_valid = !root.IsNull();
    }

    void Clear()
    {
        std::lock_guard<std::mutex> lock{m_mutex};
        m_valid = false;
        m_key = {};
        m_root.SetNull();
    }

private:
    mutable std::mutex m_mutex;
    RCCoupBankRootCacheKey m_key{};
    uint256 m_root{};
    bool m_valid{false};
};

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_BANK_ROOT_CACHE_H

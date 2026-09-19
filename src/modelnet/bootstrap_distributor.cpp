// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/bootstrap_distributor.h>

#include <algorithm>
#include <utility>
#include <vector>

namespace modelnet {

BootstrapDistributor::BootstrapDistributor(uint64_t file_size, uint64_t extent)
    : m_file_size(file_size), m_extent(extent ? extent : (256ull << 20))
{
}

void BootstrapDistributor::NoteHave(uint64_t offset, uint64_t length)
{
    if (length == 0 || offset >= m_file_size) return;
    if (length > m_file_size - offset) length = m_file_size - offset;
    m_have.emplace_back(offset, offset + length);
}

bool BootstrapDistributor::AdvertiseMissing(uint64_t offset, uint64_t length) const
{
    if (length == 0 || offset >= m_file_size) return false;
    if (length > m_file_size - offset) return false;
    const uint64_t end = offset + length;
    for (const auto& iv : m_have) {
        if (iv.first <= offset && iv.second >= end) return false;
    }
    return true;
}

bool BootstrapDistributor::AssignLease(const std::string& peer, int64_t now_ms, int64_t ttl_ms,
                                        BootstrapLease& out, std::string& err)
{
    Expire(now_ms);
    std::vector<std::pair<uint64_t, uint64_t>> occupied;
    occupied.reserve(m_leases.size());
    for (const auto& l : m_leases) {
        occupied.emplace_back(l.offset, l.offset + l.length);
    }
    std::sort(occupied.begin(), occupied.end());
    std::vector<std::pair<uint64_t, uint64_t>> merged;
    for (const auto& iv : occupied) {
        if (merged.empty() || iv.first > merged.back().second) {
            merged.push_back(iv);
        } else if (iv.second > merged.back().second) {
            merged.back().second = iv.second;
        }
    }
    uint64_t gap_off = 0;
    uint64_t gap_len = 0;
    uint64_t cursor = 0;
    auto consider = [&](uint64_t start, uint64_t end) {
        if (gap_len > 0 || end <= start) return;
        gap_off = start;
        gap_len = std::min(m_extent, end - start);
    };
    for (const auto& iv : merged) {
        if (iv.first > cursor) consider(cursor, std::min(iv.first, m_file_size));
        if (iv.second > cursor) cursor = iv.second;
        if (cursor >= m_file_size) break;
    }
    if (gap_len == 0 && cursor < m_file_size) consider(cursor, m_file_size);
    if (gap_len == 0) {
        err = "no scarce extent";
        return false;
    }
    out = {};
    out.peer = peer;
    out.offset = gap_off;
    out.length = gap_len;
    out.expiry_ms = now_ms + ttl_ms;
    m_leases.push_back(out);
    return true;
}

void BootstrapDistributor::NoteSent(const std::string& peer, uint64_t bytes)
{
    for (auto& l : m_leases) {
        if (l.peer == peer) {
            l.sent_bytes += bytes;
            return;
        }
    }
}

void BootstrapDistributor::Expire(int64_t now_ms)
{
    std::vector<BootstrapLease> keep;
    for (const auto& l : m_leases) {
        if (l.expiry_ms > now_ms) keep.push_back(l);
    }
    m_leases.swap(keep);
}

bool OriginOfferAllowed(const OriginOffer& offer, std::string& err)
{
    if (offer.follow_redirects) {
        err = "redirects forbidden";
        return false;
    }
    if (offer.mode == OriginMode::EXPLICIT_EXTERNAL && offer.locator.empty()) {
        err = "external origin requires locator";
        return false;
    }
    return true;
}

} // namespace modelnet

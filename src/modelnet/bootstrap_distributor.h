// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_BOOTSTRAP_DISTRIBUTOR_H
#define BITCOIN_MODELNET_BOOTSTRAP_DISTRIBUTOR_H

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {

struct BootstrapLease {
    std::string peer;
    uint64_t offset{0};
    uint64_t length{0};
    int64_t expiry_ms{0};
    uint64_t sent_bytes{0};
};

/** Truthful superseeding: advertise real availability; bounded scarce-extent leases. */
class BootstrapDistributor {
    uint64_t m_file_size{0};
    uint64_t m_extent{256ull << 20};
    std::vector<BootstrapLease> m_leases;
    std::vector<std::pair<uint64_t, uint64_t>> m_have;

public:
    BootstrapDistributor(uint64_t file_size, uint64_t extent);
    /** Record locally verified bytes. Advertising those ranges as missing is untruthful. */
    void NoteHave(uint64_t offset, uint64_t length);
    bool AdvertiseMissing(uint64_t offset, uint64_t length) const;
    bool AssignLease(const std::string& peer, int64_t now_ms, int64_t ttl_ms, BootstrapLease& out,
                     std::string& err);
    void NoteSent(const std::string& peer, uint64_t bytes);
    void Expire(int64_t now_ms);
    size_t LeaseCount() const { return m_leases.size(); }
};

enum class OriginMode {
    NATIVE_PROXY = 0,
    EXPLICIT_EXTERNAL = 1,
};

struct OriginOffer {
    OriginMode mode{OriginMode::NATIVE_PROXY};
    std::string locator;
    bool follow_redirects{false};
};

bool OriginOfferAllowed(const OriginOffer& offer, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_BOOTSTRAP_DISTRIBUTOR_H

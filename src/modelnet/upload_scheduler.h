// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_UPLOAD_SCHEDULER_H
#define BITCOIN_MODELNET_UPLOAD_SCHEDULER_H

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

enum class UploadClass {
    NEWCOMER = 0,
    NORMAL = 1,
    RARE = 2,
    EXPLORATORY = 3,
    RELAY_TRANSIT = 4,
    PROVIDER_PAYLOAD = 5,
    CLOUD_PROXIED = 6,
    TORRENT_REVERSE = 7,
};

struct UploadRequest {
    std::string identity;
    std::string netgroup;
    UploadClass cls{UploadClass::NORMAL};
    uint64_t bytes{0};
};

struct UploadAdmission {
    int slots{4};
    int max_slots{16};
    int per_identity{2};
    int per_netgroup{4};
};

struct UploadDecision {
    bool admitted{false};
    int slot{-1};
    std::string reason;
};

/** Finite slots + per-identity and per-netgroup limits as separate dimensions. */
class UploadScheduler {
    UploadAdmission m_adm;
    int m_active{0};
    std::vector<std::string> m_identities;
    std::vector<std::string> m_netgroups;

public:
    explicit UploadScheduler(UploadAdmission adm = {});
    UploadDecision Admit(const UploadRequest& req);
    void Release(const UploadRequest& req);
    int Active() const { return m_active; }
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_UPLOAD_SCHEDULER_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_UPLOAD_SCHEDULER_DRR_H
#define BITCOIN_MODELNET_UPLOAD_SCHEDULER_DRR_H

#include <modelnet/upload_scheduler.h>

#include <cstdint>
#include <deque>
#include <map>
#include <string>

namespace modelnet {

/** Host resource accounting classes (spec §8.1). Counters only — never ranking. */
enum class HostAccountingClass {
    NATIVE_P2P = 0,
    RELAY_TRANSIT = 1,
    PROVIDER_PAYLOAD = 2,
    CLOUD_PROXIED = 3,
    TORRENT_REVERSE = 4,
};

inline constexpr int kHostAccountingClassCount = 5;
inline constexpr uint64_t kDrrQuantumBytes = 256ull * 1024;       // SUBPIECE_V1
inline constexpr uint64_t kDrrMaxDeficitBytes = 4ull * 1024 * 1024;
inline constexpr uint32_t kDrrRareWeightMax = 4;                   // bounded multiplier
inline constexpr int kDrrRareLaneSlots = 1;

struct DrrConfig {
    UploadAdmission admission{};
    uint64_t quantum_bytes{kDrrQuantumBytes};
    uint64_t max_deficit_bytes{kDrrMaxDeficitBytes};
    uint32_t rare_weight{2}; // rarity boost cannot monopolize (capped at kDrrRareWeightMax)
    int rare_lane_slots{kDrrRareLaneSlots};
    bool reserve_newcomer_normal{true};
};

struct DrrUploadRequest {
    std::string identity;
    std::string netgroup;
    UploadClass schedule{UploadClass::NORMAL};
    HostAccountingClass accounting{HostAccountingClass::NATIVE_P2P};
    uint64_t bytes{0};
    bool receiver_writable{true};
    bool storage_credit_reserved{true};
    bool origin_credit_reserved{true};
};

struct DrrSelection {
    bool selected{false};
    uint64_t request_id{0};
    int slot{-1};
    UploadClass schedule{UploadClass::NORMAL};
    HostAccountingClass accounting{HostAccountingClass::NATIVE_P2P};
    std::string identity;
    std::string netgroup;
    uint64_t bytes{0};
    std::string reason;
};

const char* HostAccountingClassName(HostAccountingClass c);
bool HostAccountingClassFromName(const std::string& name, HostAccountingClass& out);
/** DRR class weight. RARE is a bounded multiplier; other schedule classes are 1. */
uint32_t DrrClassWeight(UploadClass schedule, uint32_t rare_weight = 2);
UploadClass DrrScheduleClass(UploadClass c);

/**
 * Deficit round robin above UploadScheduler's finite slots.
 * Per-identity and per-netgroup limits are independent dimensions (not fallbacks).
 * HostAccountingClass is incremented on accepted work and is not a pick key.
 */
class UploadSchedulerDrr {
    DrrConfig m_cfg;
    uint64_t m_next_id{1};
    int m_active{0};
    int m_active_rare{0};
    int m_active_exploratory{0};
    bool m_served_fair_this_epoch{false};
    bool m_exploratory_used_this_epoch{false};
    uint64_t m_class_deficit[4]{};
    uint64_t m_acct_bytes[kHostAccountingClassCount]{};
    uint64_t m_acct_count[kHostAccountingClassCount]{};
    std::map<std::string, int> m_id_active;
    std::map<std::string, int> m_ng_active;
    std::map<std::string, uint64_t> m_id_deficit;
    std::map<std::string, uint64_t> m_ng_deficit;

    struct Queued {
        uint64_t id{0};
        DrrUploadRequest req;
        bool active{false};
    };
    std::deque<Queued> m_q;

    static int ScheduleIndex(UploadClass c);
    static int AccountingIndex(HostAccountingClass c);
    uint64_t AddDeficit(uint64_t cur, uint64_t add) const;
    bool Eligible(const Queued& q, bool enforce_rare_lane, std::string& why) const;
    void Activate(Queued& q, DrrSelection& out);

public:
    explicit UploadSchedulerDrr(DrrConfig cfg = {});

    bool Enqueue(const DrrUploadRequest& req, uint64_t& request_id, std::string& err);
    /** Add quantum × weight to class and to each waiting identity/netgroup; cap credit. */
    void RunEpoch();
    bool Select(DrrSelection& out);
    bool NoteAcceptedWork(uint64_t request_id, uint64_t bytes, std::string& err);
    void Release(uint64_t request_id);
    bool SetReceiverWritable(uint64_t request_id, bool writable);
    bool SetStorageReady(uint64_t request_id, bool ready);
    bool SetOriginCreditReserved(uint64_t request_id, bool reserved);

    int Active() const { return m_active; }
    size_t Ready() const;
    int IdentityActive(const std::string& identity) const;
    int NetgroupActive(const std::string& netgroup) const;
    uint64_t ClassDeficit(UploadClass schedule) const;
    uint64_t IdentityDeficit(const std::string& identity) const;
    uint64_t NetgroupDeficit(const std::string& netgroup) const;
    uint64_t AccountedBytes(HostAccountingClass c) const;
    uint64_t AccountedCount(HostAccountingClass c) const;
    int Slots() const { return m_cfg.admission.slots; }
    const DrrConfig& Config() const { return m_cfg; }
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_UPLOAD_SCHEDULER_DRR_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRP30_GRP30_H
#define BITCOIN_MODELNET_GRP30_GRP30_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/nif_manifest/nif_manifest.h>
#include <modelnet/dt_share/dt_share.h>
#include <modelnet/dt_rollout/dt_rollout.h>
#include <modelnet/dt_delay/dt_delay.h>
#include <modelnet/nif_status/nif_status.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Group 30 of the unfinished NIF/DT rows.
 * Requirements: NIF-KV-002, NIF-KV-007, NIF-QA-001, DT-GRD-003, DT-RLP-006, DT-RLP-007, DT-WAN-006.
 * Each id calls the engine that already implements that row and returns that engine result.
 * Any other id returns ID.
 * release_qualified(), qualified(), and hardware_qualified() stay false.
 * hosts() and physical_hosts() are 1. bytes_moved() is 0.
 * No socket, no process, and no broadcast.
 */
class Grp30 {
public:
    bool Apply(const std::string& id, std::string& err);
    bool Vendor(std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Spend(std::string& err);

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool advertised() const { return false; }
    int hosts() const { return 1; }
    int physical_hosts() const { return 1; }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

    /** True when the expired piece id was stored. An expired open leaves this false. */
    bool expired_stored() const { return m_manifest.stored(kExpiredId); }
    /** True when the open incomplete manifest id was stored. */
    bool open_held() const { return m_manifest.stored(kOpenId); }
    int64_t open_accepted() const { return m_manifest.accepted(kOpenId); }
    /** True only when every stored manifest is sealed. */
    bool complete() const { return m_manifest.sealed(); }
    bool compute_proof() const { return m_manifest.compute_proof(); }

    int64_t component_count() const { return m_status.component_count(); }
    int64_t native_count() const { return m_status.native_count(); }
    int64_t hardware_count() const { return m_status.hardware_count(); }
    int64_t release_count() const { return m_status.release_count(); }

    int64_t gradient_pending() const { return m_share.pending(kOwner); }
    bool incompatible_stored() const { return m_rollout.has_sample(kSample); }
    int64_t full_trajectories() const { return m_rollout.finished_count(); }
    int64_t short_trajectories() const { return m_rollout.short_count(); }
    bool replenished() const { return m_rollout.replenished(); }

    int64_t delay_head() const { return m_delay.head(); }
    int64_t delay_pending() const { return m_delay.pending(); }
    bool delay_has_base() const { return m_delay.has_base(); }

private:
    static constexpr char kExpiredId[] = "kv-expired";
    static constexpr char kOpenId[] = "kv-open";
    static constexpr char kProofId[] = "kv-proof";
    static constexpr char kStatusName[] = "row";
    static constexpr char kOwner[] = "owner";
    static constexpr char kConsumer[] = "consumer";
    static constexpr char kSample[] = "sample";
    static constexpr char kEarly[] = "early";
    static constexpr char kBase[] = "base-a";
    static constexpr char kChanged[] = "base-b";

    NifManifest m_manifest;
    NifStatus m_status;
    DtShare m_share;
    DtRollout m_rollout;
    DtDelay m_delay;
};

} // namespace modelnet

#endif

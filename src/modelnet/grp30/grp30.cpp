// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp30/grp30.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/nif_manifest/nif_manifest.h>
#include <modelnet/dt_share/dt_share.h>
#include <modelnet/dt_rollout/dt_rollout.h>
#include <modelnet/dt_delay/dt_delay.h>
#include <modelnet/nif_status/nif_status.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool Grp30::Vendor(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp30::Release(std::string& err)
{
    err = NIFDT_UNQUALIFIED;
    return false;
}

bool Grp30::Gpu(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool Grp30::Spend(std::string& err)
{
    err = NIFDT_AUTOMATIC_SPEND;
    return false;
}

bool Grp30::Apply(const std::string& id, std::string& err)
{
    if (id == "NIF-KV-002") {
        // An expired piece is refused and stores nothing.
        std::string step;
        if (m_manifest.Open(kExpiredId, static_cast<int64_t>(2), static_cast<int64_t>(8), static_cast<int64_t>(8), step)) {
            err = step;
            return true;
        }
        if (step != NIF_MANIFEST_EXPIRED) {
            err = step;
            return false;
        }
        // A manifest that is still missing a piece is not complete.
        if (!m_manifest.stored(kOpenId)) {
            if (!m_manifest.Open(kOpenId, static_cast<int64_t>(2), static_cast<int64_t>(1), static_cast<int64_t>(40), step)) {
                err = step;
                return false;
            }
        }
        return m_manifest.Seal(kOpenId, err);
    }
    if (id == "NIF-KV-007") {
        std::string step;
        if (!m_manifest.stored(kProofId)) {
            if (!m_manifest.Open(kProofId, static_cast<int64_t>(1), static_cast<int64_t>(1), static_cast<int64_t>(30), step)) {
                err = step;
                return false;
            }
        }
        // Claim(id) is a producer claim. compute_proof() stays false.
        return m_manifest.Claim(kProofId, err);
    }
    if (id == "NIF-QA-001") {
        std::string step;
        if (!m_status.component_stored(kStatusName)) {
            if (!m_status.Record("component", kStatusName, step)) {
                err = step;
                return false;
            }
        }
        if (!m_status.native_stored(kStatusName)) {
            if (!m_status.Record("native", kStatusName, step)) {
                err = step;
                return false;
            }
        }
        if (!m_status.hardware_stored(kStatusName)) {
            if (!m_status.Record("hardware", kStatusName, step)) {
                err = step;
                return false;
            }
        }
        if (!m_status.release_stored(kStatusName)) {
            if (!m_status.Record("release", kStatusName, step)) {
                err = step;
                return false;
            }
        }
        // Release on the status engine stays unqualified.
        return m_status.Release(kStatusName, err);
    }
    if (id == "DT-GRD-003") {
        std::string step;
        if (m_share.owner_of(kConsumer).empty()) {
            if (!m_share.Bind(kOwner, kConsumer, step)) {
                err = step;
                return false;
            }
            if (!m_share.Grad(kOwner, kConsumer, static_cast<int64_t>(1), step)) {
                err = step;
                return false;
            }
        }
        // A second gradient from the same consumer is refused.
        return m_share.Grad(kOwner, kConsumer, static_cast<int64_t>(1), err);
    }
    if (id == "DT-RLP-006") {
        // An incompatible route is refused and stores nothing.
        return m_rollout.Route(kSample, static_cast<uint64_t>(1), false, err);
    }
    if (id == "DT-RLP-007") {
        std::string step;
        if (!m_rollout.has_sample(kEarly)) {
            if (!m_rollout.Route(kEarly, static_cast<uint64_t>(1), true, step)) {
                err = step;
                return false;
            }
            if (!m_rollout.Finish(kEarly, static_cast<int64_t>(1), true, step)) {
                err = step;
                return false;
            }
        }
        // An early trajectory does not count toward a full replenishment.
        return m_rollout.Replenish(static_cast<int64_t>(1), err);
    }
    if (id == "DT-WAN-006") {
        std::string step;
        if (!m_delay.has_base()) {
            if (!m_delay.Base(kBase, step)) {
                err = step;
                return false;
            }
        }
        if (m_delay.pending() == static_cast<int64_t>(0)) {
            if (!m_delay.Delay(static_cast<int64_t>(4), static_cast<int64_t>(1), step)) {
                err = step;
                return false;
            }
        }
        // A different base does not resume. head() stays.
        return m_delay.Resume(kChanged, err);
    }
    err = "ID";
    return false;
}

} // namespace modelnet

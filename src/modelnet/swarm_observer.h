// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_OBSERVER_H
#define BITCOIN_MODELNET_SWARM_OBSERVER_H

#include <util/fs.h>

#include <map>
#include <string>

namespace modelnet {

/** SHA-384 of BTX/ProvisionalModelTopic/1 || 0x00 || {"model_id":"<id>"}. */
std::string SwarmProvisionalLineage(const std::string& model_id);

/** Resolved local catalog identity shared by observer and contribution views. */
struct SwarmCatalogEntry {
    std::string artifact_id;
    std::string model_id;
    std::string lineage_id;
    std::string lineage_assurance;
    std::string visibility;
    std::string quantization{"unspecified"};
    std::string checkpoint;
    std::string recipe;
};
using SwarmCatalog = std::map<std::string, SwarmCatalogEntry>;

/** Read a bounded catalog and local lineage mappings. Missing catalog is empty.
 *  On invalid input, returns false with an empty result. Mappings are trusted
 *  local policy; this reader does not authenticate an external mapping. */
bool SwarmReadCatalog(const fs::path& modeldir, SwarmCatalog& entries, std::string& err);

/**
 * Reconcile modeldir/swarm/observers.json to the verified, complete catalog.
 * Removed or ineligible models lose their active subscription; missing catalog
 * clears subscriptions. This file is a snapshot, not a follow-history store.
 * Subscriptions grant no compute, seeding or spend authority. Unusable input
 * returns false without replacing the last valid snapshot; the poll skips live
 * publication on failure, and a saved snapshot alone does not prove freshness.
 */
bool SwarmObserveCatalog(const fs::path& modeldir, std::string& err);

/** Poll the catalog until StopSwarmObserver. A failure is logged and does not stop btxd. */
void StartSwarmObserver(const fs::path& modeldir);
void StopSwarmObserver() noexcept;

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_OBSERVER_H

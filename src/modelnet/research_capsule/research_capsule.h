// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_RESEARCH_CAPSULE_RESEARCH_CAPSULE_H
#define BITCOIN_MODELNET_RESEARCH_CAPSULE_RESEARCH_CAPSULE_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/training_integer.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Research capsule. Seals one integer training step under an id.
 *
 * Seal: an empty id returns FIELD and stores nothing. A new id calls
 * IntegerTrainer::Step once, then stores IntegerStateHash of State()
 * under that id. A second seal of the same id returns NIFDT_REPLAY and
 * keeps the first hash.
 *
 * Open returns the stored hash. An unknown id returns CAPSULE.
 * pairs() is IntegerDataset().size() and stays 8.
 *
 * Release returns NIFDT_UNQUALIFIED even after a seal.
 * qualified_v41(), qualified(), release_qualified(), and
 * hardware_qualified() stay false.
 * Gpu and Vendor return NIFDT_ENGINE_ABSENT and do not change the hash.
 * Spend returns NIFDT_AUTOMATIC_SPEND. bytes_moved() stays 0.
 * hosts() and physical_hosts() stay 1.
 * launched(), gpu(), and broadcast() stay false.
 */
class ResearchCapsule {
public:
    bool Seal(const std::string& id, std::string& err);
    std::string Open(const std::string& id, std::string& err) const;
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Vendor(std::string& err);
    bool Spend(std::string& err);

    int64_t pairs() const { return static_cast<int64_t>(IntegerDataset().size()); }
    bool qualified_v41() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Sealed {
        std::string id;
        std::string hash;
    };

    const std::string* Find(const std::string& id) const;

    std::vector<Sealed> m_sealed;
};

} // namespace modelnet

#endif

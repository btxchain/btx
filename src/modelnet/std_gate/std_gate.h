// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_STD_GATE_STD_GATE_H
#define BITCOIN_MODELNET_STD_GATE_STD_GATE_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Closed gate for the six standard names: stix, taxii, ocsf, sigma, eve, cacao.
 *
 * Note: an empty or unknown name returns NAME and records nothing. A known
 * name is recorded. A second note of a recorded name returns NIFDT_REPLAY
 * and keeps the first record.
 *
 * Import: an empty body returns BODY and stores nothing. stix without the
 * substring "version" returns VERSION. taxii returns BOUNDED and stores
 * nothing. ocsf without the substring "lineage" returns LINEAGE. sigma
 * returns BACKEND and stores nothing. eve with a body size over 64 returns
 * OVERSIZE. cacao without the substring "typed" returns SUBSET. A refused
 * import stores nothing. An accepted import stores that body.
 *
 * Release returns NIFDT_UNQUALIFIED even after every name is noted.
 * qualified(), release_qualified(), and hardware_qualified() stay false.
 * hosts() and physical_hosts() stay 1. bytes_moved() stays 0.
 * Spend returns NIFDT_AUTOMATIC_SPEND. Vendor and Gpu return
 * NIFDT_ENGINE_ABSENT. launched(), gpu(), and broadcast() stay false.
 * This class opens no file, socket, or process, and it uses no network.
 */
class StdGate {
public:
    bool Note(const std::string& name, std::string& err);
    bool Import(const std::string& name, const std::string& body, std::string& err);
    bool Release(std::string& err);
    bool Gpu(std::string& err);
    bool Vendor(std::string& err);
    bool Spend(std::string& err);

    bool noted(const std::string& name) const;
    bool stored(const std::string& name) const;
    std::string body_of(const std::string& name) const;

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool advertised() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Held {
        std::string name;
        std::string body;
    };
    std::vector<std::string> m_noted;
    std::vector<Held> m_held;
};

} // namespace modelnet

#endif

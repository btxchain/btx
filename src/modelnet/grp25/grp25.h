// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRP25_GRP25_H
#define BITCOIN_MODELNET_GRP25_GRP25_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_decode/swarm_decode_run.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Group 25. Node behaviors 1 and 2.
 * A local workload starts without a sidecar, and a public prompt can be pulled.
 * This does not qualify a release.
 *
 * Open, Prompt, and Pull forward to SwarmDecodeRun. text(), tokens(), and
 * engine_of() forward to that object. bytes_moved() stays 0 and does not
 * read the decode object's byte count. launched(), gpu(), broadcast(),
 * qualified(), release_qualified(), and hardware_qualified() stay false.
 * hosts() and physical_hosts() stay 1. automatic_spend() stays "0".
 * No socket, no process, and no broadcast.
 */
class Grp25 {
public:
    bool Open(const std::string& session, const std::string& engine, std::string& err);
    bool Prompt(const std::string& session, const std::string& text, bool is_private, std::string& err);
    bool Pull(const std::string& session, std::string& err);

    const std::string& text() const;
    int64_t tokens() const;
    std::string engine_of(const std::string& session) const;

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
    int hosts() const { return 1; }
    int physical_hosts() const { return 1; }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    SwarmDecodeRun m_decode;
};

} // namespace modelnet

#endif

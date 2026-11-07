// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_KVFABRIC_FABRIC_H
#define BTX_MODELNET_SWARM_KVFABRIC_FABRIC_H

#include <modelnet/swarm_kvfabric/compatibility.h>
#include <modelnet/swarm_kvfabric/engine_probe.h>
#include <modelnet/swarm_kvfabric/multiplier.h>
#include <modelnet/swarm_kvfabric/placement.h>
#include <modelnet/swarm_kvfabric/prefetch.h>
#include <modelnet/swarm_kvfabric/revocation.h>
#include <modelnet/swarm_kvfabric/truncation.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * KV fabric control plane.
 *
 * Probe, placement, share, prefetch, revocation, cache-size admission, and
 * publication are records only. A missing engine moves no bytes.
 * bytes_moved stays false on every path. This type does not start a process,
 * allocate a CUDA buffer, or store a tok/s claim.
 *
 * Probe(name, present): known names are vllm, sglang, lmcache, nixl,
 * mooncake, and rdma. present false, and any unknown name, return
 * ENGINE_ABSENT. present true on a known name returns INSTALLED.
 * advertised and qualified stay false.
 *
 * Place(page, family) stores the page id. An empty page or family is PAGE
 * and stores nothing.
 *
 * Share(page, family_a, family_b, compatible) returns NOT_COMPAT when
 * family_a == family_b or compatible is false, and does not mark the page.
 * A real share records the page id.
 *
 * Prefetch(page) returns ENGINE_ABSENT unless the engine status is
 * INSTALLED. An installed prefetch records the page id.
 *
 * Revoke(member) then Read(member, page) returns NOT_READ and does not
 * record that read. A non-revoked member records a read of a placed page.
 *
 * Accept(size) records a cache body size only when size > 0 and
 * size <= 33554432. Otherwise the code is TRUNCATED and nothing is stored.
 *
 * Publish(rate) returns HELD and published stays false.
 *
 * Success codes are PLACED, SHARED, PREFETCH, REVOKED, READ, and ACCEPTED.
 * Empty ids on share, prefetch, revoke, and read are PAGE.
 */
class SwarmKvFabric {
public:
    SwarmKvFabricResult Probe(const std::string& name, bool present);
    SwarmKvFabricResult Place(const std::string& page, const std::string& family);
    SwarmKvFabricResult Share(const std::string& page,
                              const std::string& family_a,
                              const std::string& family_b,
                              bool compatible);
    SwarmKvFabricResult Prefetch(const std::string& page);
    SwarmKvFabricResult Revoke(const std::string& member);
    SwarmKvFabricResult Read(const std::string& member, const std::string& page);
    SwarmKvFabricResult Accept(int64_t size);
    SwarmKvFabricResult Publish(int64_t rate);

    bool bytes_moved() const;
    bool advertised() const;
    bool qualified() const;
    bool published() const;
    bool process_started() const;
    bool engine_installed() const;
    std::string engine_status() const;

    bool placed(const std::string& page) const;
    bool holds_family() const;
    bool shared(const std::string& page) const;
    bool prefetched(const std::string& page) const;
    bool cuda_buffer() const;

    bool revoked(const std::string& member) const;
    bool read_recorded(const std::string& member, const std::string& page) const;

    bool cache_accepted() const;
    int64_t admitted_size() const;
    bool body_retained() const;
    bool rate_stored() const;

private:
    KvFabricEngines m_engines;
    KvFabricPlacement m_placement;
    KvFabricCompatibility m_compatibility;
    KvFabricPrefetch m_prefetch;
    KvFabricRevocation m_revocation;
    KvFabricTruncation m_truncation;
    KvFabricMultiplier m_multiplier;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_KVFABRIC_FABRIC_H

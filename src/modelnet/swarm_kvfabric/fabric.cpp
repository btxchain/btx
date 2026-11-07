// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvfabric/fabric.h>

#include <modelnet/swarm_kvfabric/bytes.h>

namespace modelnet {
namespace {

SwarmKvFabricResult Seal(SwarmKvFabricResult result)
{
    result.advertised = false;
    result.qualified = false;
    result.published = false;
    result.bytes_moved = KvFabricBytesMoved();
    result.bytes = 0;
    return result;
}

} // namespace

SwarmKvFabricResult SwarmKvFabric::Probe(const std::string& name, bool present)
{
    return Seal(m_engines.Probe(name, present));
}

SwarmKvFabricResult SwarmKvFabric::Place(const std::string& page, const std::string& family)
{
    return Seal(m_placement.Place(page, family));
}

SwarmKvFabricResult SwarmKvFabric::Share(const std::string& page,
                                         const std::string& family_a,
                                         const std::string& family_b,
                                         bool compatible)
{
    return Seal(m_compatibility.Share(page, family_a, family_b, compatible));
}

SwarmKvFabricResult SwarmKvFabric::Prefetch(const std::string& page)
{
    return Seal(m_prefetch.Request(m_engines.status(), page));
}

SwarmKvFabricResult SwarmKvFabric::Revoke(const std::string& member)
{
    return Seal(m_revocation.Revoke(member));
}

SwarmKvFabricResult SwarmKvFabric::Read(const std::string& member, const std::string& page)
{
    return Seal(m_revocation.Read(member, page, m_placement.placed(page)));
}

SwarmKvFabricResult SwarmKvFabric::Accept(int64_t size)
{
    return Seal(m_truncation.Accept(size));
}

SwarmKvFabricResult SwarmKvFabric::Publish(int64_t rate)
{
    return Seal(m_multiplier.Publish(rate));
}

bool SwarmKvFabric::bytes_moved() const
{
    return KvFabricBytesMoved();
}

bool SwarmKvFabric::advertised() const
{
    return m_engines.advertised();
}

bool SwarmKvFabric::qualified() const
{
    return m_engines.qualified();
}

bool SwarmKvFabric::published() const
{
    return m_multiplier.published();
}

bool SwarmKvFabric::process_started() const
{
    return m_engines.process_started();
}

bool SwarmKvFabric::engine_installed() const
{
    return m_engines.installed();
}

std::string SwarmKvFabric::engine_status() const
{
    return m_engines.status();
}

bool SwarmKvFabric::placed(const std::string& page) const
{
    return m_placement.placed(page);
}

bool SwarmKvFabric::holds_family() const
{
    return m_placement.holds_family();
}

bool SwarmKvFabric::shared(const std::string& page) const
{
    return m_compatibility.shared(page);
}

bool SwarmKvFabric::prefetched(const std::string& page) const
{
    return m_prefetch.prefetched(page);
}

bool SwarmKvFabric::cuda_buffer() const
{
    return m_prefetch.cuda_buffer();
}

bool SwarmKvFabric::revoked(const std::string& member) const
{
    return m_revocation.revoked(member);
}

bool SwarmKvFabric::read_recorded(const std::string& member, const std::string& page) const
{
    return m_revocation.recorded(member, page);
}

bool SwarmKvFabric::cache_accepted() const
{
    return m_truncation.accepted();
}

int64_t SwarmKvFabric::admitted_size() const
{
    return m_truncation.admitted_size();
}

bool SwarmKvFabric::body_retained() const
{
    return m_truncation.body_retained();
}

bool SwarmKvFabric::rate_stored() const
{
    return m_multiplier.rate_stored();
}

} // namespace modelnet

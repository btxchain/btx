// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvwire/swarm_kvwire.h>

#include <modelnet/swarm_kvwire/codes.h>
#include <modelnet/swarm_kvwire/limits.h>
#include <modelnet/swarm_kvwire/pair.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {

bool SwarmKvWire::Transfer(const std::vector<unsigned char>& body, std::string& err)
{
    std::vector<unsigned char> got;
    if (!SwarmKvWireCarry(body, got, err)) {
        return false;
    }
    m_bytes_moved += static_cast<std::int64_t>(got.size());
    m_received = std::move(got);
    return true;
}

bool SwarmKvWire::Remote(const std::string& engine, std::string& err)
{
    if (engine == kSwarmKvWireEngineNixl || engine == kSwarmKvWireEngineMooncake ||
        engine == kSwarmKvWireEngineRdma) {
        err = kSwarmKvWireEngineAbsent;
        return false;
    }
    err = kSwarmKvWireEngine;
    return false;
}

const std::vector<unsigned char>& SwarmKvWire::received() const
{
    return m_received;
}

std::int64_t SwarmKvWire::bytes_moved() const
{
    return m_bytes_moved;
}

std::string SwarmKvWire::engine() const
{
    return std::string{kSwarmKvWireEngineLocal};
}

bool SwarmKvWire::launched() const
{
    return kSwarmKvWireLaunched;
}

bool SwarmKvWire::gpu() const
{
    return kSwarmKvWireGpu;
}

bool SwarmKvWire::broadcast() const
{
    return kSwarmKvWireBroadcast;
}

bool SwarmKvWire::connected() const
{
    return kSwarmKvWireConnected;
}

std::string SwarmKvWire::automatic_spend() const
{
    return std::string{kSwarmKvWireAutomaticSpend};
}

} // namespace modelnet

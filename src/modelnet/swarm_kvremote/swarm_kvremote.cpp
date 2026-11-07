// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvremote/swarm_kvremote.h>

#include <modelnet/swarm_kvmove/codes.h>
#include <modelnet/swarm_kvremote/dstbody.h>
#include <modelnet/swarm_kvremote/limits.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

bool SwarmKvRemote::Put(const std::string& slot, const std::string& fingerprint, const std::string& quantization,
                        const std::vector<unsigned char>& body, std::string& err)
{
    return m_move.Put(slot, fingerprint, quantization, body, err);
}

bool SwarmKvRemote::Move(const std::string& src, const std::string& dst, const std::string& engine, std::string& err)
{
    return m_move.Move(src, dst, engine, err);
}

bool SwarmKvRemote::Transfer(const std::string& src, const std::string& dst, const std::vector<unsigned char>& body,
                             std::string& err)
{
    if (!m_move.Put(src, kSwarmKvRemoteFingerprint, kSwarmKvMoveQuantFull, body, err)) {
        return false;
    }
    const std::vector<unsigned char> placeholder = SwarmKvRemoteDifferentByte(body);
    if (!m_move.Put(dst, kSwarmKvRemoteFingerprint, kSwarmKvMoveQuantFull, placeholder, err)) {
        return false;
    }
    return m_move.Move(src, dst, kSwarmKvMoveEngineMemory, err);
}

bool SwarmKvRemote::Remote(const std::string& src, const std::string& dst, std::string& err)
{
    return Move(src, dst, kSwarmKvMoveEngineNixl, err);
}

bool SwarmKvRemote::in_family(const std::string& slot) const
{
    return m_move.in_family(slot);
}

bool SwarmKvRemote::in_kv(const std::string& slot) const
{
    return m_move.in_kv(slot);
}

std::size_t SwarmKvRemote::body_size(const std::string& slot) const
{
    return m_move.body_size(slot);
}

const std::vector<unsigned char>& SwarmKvRemote::body(const std::string& slot) const
{
    return m_move.body(slot);
}

std::int64_t SwarmKvRemote::bytes_moved() const
{
    return m_move.bytes_moved();
}

std::int64_t SwarmKvRemote::page_bytes() const
{
    return bytes_moved();
}

bool SwarmKvRemote::launched() const
{
    return kSwarmKvRemoteLaunched;
}

bool SwarmKvRemote::gpu() const
{
    return kSwarmKvRemoteGpu;
}

bool SwarmKvRemote::broadcast() const
{
    return kSwarmKvRemoteBroadcast;
}

std::string SwarmKvRemote::automatic_spend() const
{
    return std::string{kSwarmKvRemoteAutomaticSpend};
}

} // namespace modelnet

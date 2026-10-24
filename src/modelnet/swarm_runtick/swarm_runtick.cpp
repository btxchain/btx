// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_runtick/swarm_runtick.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {
namespace {

/** One byte that is not the hash body. The page copy is SwarmKvMove::Move. */
std::vector<unsigned char> DifferentOneByte(const std::vector<unsigned char>& hash_bytes)
{
    constexpr unsigned char byte = 0x01;
    if (hash_bytes.size() == 1 && hash_bytes[0] == byte) {
        return {static_cast<unsigned char>(0x02)};
    }
    return {byte};
}

} // namespace

bool SwarmRunTick::Tick(uint64_t steps, std::string& err)
{
    if (steps < 1) {
        err = SWARM_RUNTICK_STEPS;
        return false;
    }
    if (!m_cycle.Run(steps, err)) {
        return false;
    }
    if (!m_prefix_ready) {
        if (!m_exec.Allow("work/", err)) {
            return false;
        }
        m_prefix_ready = true;
    }
    const std::string& state_hash = m_cycle.state_hash();
    if (!m_exec.Execute("sha256", "work/state", state_hash, err)) {
        return false;
    }
    const std::vector<unsigned char> src_body(state_hash.begin(), state_hash.end());
    const std::vector<unsigned char> dst_body = DifferentOneByte(src_body);
    if (!m_kv.Put("src", state_hash, "full", src_body, err)) {
        return false;
    }
    if (!m_kv.Put("dst", state_hash, "full", dst_body, err)) {
        return false;
    }
    return m_kv.Move("src", "dst", "memory", err);
}

bool SwarmRunTick::GpuTick(uint64_t, std::string& err)
{
    err = SWARM_RUNTICK_ENGINE_ABSENT;
    return false;
}

std::string SwarmRunTick::digest() const
{
    return m_exec.result();
}

std::int64_t SwarmRunTick::page_bytes() const
{
    return m_kv.bytes_moved();
}

uint64_t SwarmRunTick::trained_steps() const
{
    return m_cycle.steps();
}

bool SwarmRunTick::launched() const
{
    return false;
}

bool SwarmRunTick::gpu() const
{
    return false;
}

} // namespace modelnet

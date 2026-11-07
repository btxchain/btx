// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_runtimeclass/swarm_runtimeclass.h>

#include <modelnet/swarm_agentexec/limits.h>
#include <modelnet/swarm_experience/kind.h>
#include <modelnet/swarm_experience/limits.h>
#include <modelnet/swarm_kvmove/codes.h>

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
        return std::vector<unsigned char>{static_cast<unsigned char>(0x02)};
    }
    return std::vector<unsigned char>{byte};
}

/**
 * outcome_ppm for a stored row. steps * 1000 when that product is inside
 * the experience plane's range. A larger product is passed as one past
 * the maximum so Store refuses it.
 */
int64_t OutcomePpm(uint64_t steps)
{
    constexpr uint64_t kPerStep = 1000;
    if (steps > static_cast<uint64_t>(kExperiencePpmMax) / kPerStep) {
        return kExperiencePpmMax + 1;
    }
    return static_cast<int64_t>(steps * kPerStep);
}

} // namespace

bool SwarmRuntimeClass::Tick(const std::string& id, uint64_t steps, std::string& err)
{
    if (steps < 1) {
        err = SWARM_RUNTIMECLASS_STEPS;
        return false;
    }
    if (id.empty()) {
        err = SWARM_RUNTIMECLASS_WORK;
        return false;
    }
    // ExperienceReward returns -1 when the id was never stored.
    if (m_experience.reward(id) != -1) {
        err = SWARM_RUNTIMECLASS_REPLAY;
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
    if (!m_exec.Execute(kSwarmAgentExecToolSha256, "work/state", state_hash, err)) {
        return false;
    }

    // The first tick uses src and dst. A later id needs its own slots:
    // Put of a slot that is already resident is the mover's replay and
    // would keep the first body.
    std::string src = "src";
    std::string dst = "dst";
    if (m_kv.in_kv(src) || m_kv.in_kv(dst)) {
        src = std::string("src/") + id;
        dst = std::string("dst/") + id;
    }

    const std::vector<unsigned char> src_body(state_hash.begin(), state_hash.end());
    const std::vector<unsigned char> dst_body = DifferentOneByte(src_body);
    if (!m_kv.Put(src, state_hash, kSwarmKvMoveQuantFull, src_body, err)) {
        return false;
    }
    if (!m_kv.Put(dst, state_hash, kSwarmKvMoveQuantFull, dst_body, err)) {
        return false;
    }
    if (!m_kv.Move(src, dst, kSwarmKvMoveEngineMemory, err)) {
        return false;
    }
    m_src = src;
    m_dst = dst;

    if (!m_experience.Store(id, kExperiencePublic, OutcomePpm(steps), err)) {
        return false;
    }
    m_experience.Enqueue();
    return true;
}

bool SwarmRuntimeClass::GpuTick(const std::string&, uint64_t, std::string& err)
{
    err = SWARM_RUNTIMECLASS_ENGINE_ABSENT;
    return false;
}

bool SwarmRuntimeClass::PrivateTick(const std::string&, uint64_t, std::string& err)
{
    err = SWARM_RUNTIMECLASS_PRIVATE_DATA;
    return false;
}

bool SwarmRuntimeClass::RemoteMove(std::string& err)
{
    if (m_src.empty() || m_dst.empty()) {
        err = SWARM_RUNTIMECLASS_ENGINE_ABSENT;
        return false;
    }
    return m_kv.Move(m_src, m_dst, kSwarmKvMoveEngineNixl, err);
}

std::string SwarmRuntimeClass::digest() const
{
    return m_exec.result();
}

int64_t SwarmRuntimeClass::page_bytes() const
{
    return m_kv.bytes_moved();
}

uint64_t SwarmRuntimeClass::trained_steps() const
{
    return m_cycle.steps();
}

int SwarmRuntimeClass::reward_of(const std::string& id) const
{
    return m_experience.reward(id);
}

bool SwarmRuntimeClass::launched() const
{
    return false;
}

bool SwarmRuntimeClass::gpu() const
{
    return false;
}

bool SwarmRuntimeClass::private_stored() const
{
    return m_experience.private_stored();
}

} // namespace modelnet

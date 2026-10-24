// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_RUNTIMECLASS_H
#define BITCOIN_MODELNET_SWARM_RUNTIMECLASS_H

#include <modelnet/swarm_agentexec/swarm_agentexec.h>
#include <modelnet/swarm_experience/experience.h>
#include <modelnet/swarm_intcycle/swarm_intcycle.h>
#include <modelnet/swarm_kvmove/swarm_kvmove.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** Run was asked for fewer than one step. The trainer is not called. */
inline constexpr char SWARM_RUNTIMECLASS_STEPS[] = "STEPS";

/** id is empty. Nothing is trained, hashed, copied, or stored. */
inline constexpr char SWARM_RUNTIMECLASS_WORK[] = "WORK";

/** This id is already stored. No further steps are taken. */
inline constexpr char SWARM_RUNTIMECLASS_REPLAY[] = "REPLAY";

/** A GPU tick was requested. No step is taken. */
inline constexpr char SWARM_RUNTIMECLASS_ENGINE_ABSENT[] = "ENGINE_ABSENT";

/** A private tick was requested. Nothing is stored. */
inline constexpr char SWARM_RUNTIMECLASS_PRIVATE_DATA[] = "PRIVATE_DATA";

/**
 * In-process runtime.
 *
 * Tick owns and calls SwarmIntCycle, SwarmAgentExec, SwarmKvMove, and
 * SwarmExperience. The integer trainer, the sha256 digest, the byte copy,
 * and the experience row stay in those engines.
 *
 * digest() is the agent result. page_bytes() is SwarmKvMove::bytes_moved().
 * trained_steps() is SwarmIntCycle::steps().
 * reward_of(id) is SwarmExperience::reward(id).
 * launched() stays false. gpu() stays false. private_stored() stays false.
 * There is no method that marks a GPU run or a benchmark.
 */
class SwarmRuntimeClass {
public:
    /**
     * Train, hash, copy, and store one public experience row.
     * steps below 1 sets err to STEPS and does nothing.
     * An empty id sets err to WORK and does nothing.
     * An id already stored sets err to REPLAY and does not call Run.
     * Otherwise calls SwarmIntCycle::Run(steps, err). A failed Run
     * returns false and does not hash, copy, or store.
     * On success, Allow("work/") when that prefix is not stored yet,
     * then Execute("sha256", "work/state", state_hash()). A failed
     * Execute returns false and does not copy or store.
     * Then Put two full slots whose fingerprints are state_hash().
     * The src body is the raw bytes of that hash string. The dst body
     * is a different one-byte body. Move(src, dst, "memory") copies
     * the src bytes onto dst.
     * Then Store(id, public_trajectory, steps * 1000) and Enqueue().
     * Returns true only when train, hash, move, and store all succeed.
     */
    bool Tick(const std::string& id, uint64_t steps, std::string& err);

    /**
     * Refuse a GPU tick. Always sets err to ENGINE_ABSENT and returns
     * false. Does not train, hash, copy, or store. gpu() stays false.
     */
    bool GpuTick(const std::string& id, uint64_t steps, std::string& err);

    /**
     * Refuse a private tick. Always sets err to PRIVATE_DATA and returns
     * false. Does not store. private_stored() stays false.
     */
    bool PrivateTick(const std::string& id, uint64_t steps, std::string& err);

    /**
     * Move the slots from the last memory copy with engine "nixl".
     * That engine copies nothing, so this returns false with
     * ENGINE_ABSENT. page_bytes() stays at the memory copy from Tick.
     */
    bool RemoteMove(std::string& err);

    /** Agent result. Empty until Execute stores a digest. */
    std::string digest() const;

    /** SwarmKvMove::bytes_moved(). A remote attempt adds nothing. */
    int64_t page_bytes() const;

    /** SwarmIntCycle::steps(). */
    uint64_t trained_steps() const;

    /** SwarmExperience::reward(id). A missing id is -1. */
    int reward_of(const std::string& id) const;

    bool launched() const;
    bool gpu() const;
    bool private_stored() const;

private:
    SwarmIntCycle m_cycle;
    SwarmAgentExec m_exec;
    SwarmKvMove m_kv;
    SwarmExperience m_experience;
    bool m_prefix_ready{false};
    std::string m_src;
    std::string m_dst;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_RUNTIMECLASS_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_RUNTICK_H
#define BITCOIN_MODELNET_SWARM_RUNTICK_H

#include <modelnet/swarm_agentexec/swarm_agentexec.h>
#include <modelnet/swarm_intcycle/swarm_intcycle.h>
#include <modelnet/swarm_kvmove/swarm_kvmove.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** Run was asked for fewer than one step. The trainer is not called. */
inline constexpr char SWARM_RUNTICK_STEPS[] = "STEPS";

/** A GPU tick was requested. No step is taken. */
inline constexpr char SWARM_RUNTICK_ENGINE_ABSENT[] = "ENGINE_ABSENT";

/**
 * In-process run tick.
 *
 * Tick trains with SwarmIntCycle, hashes the stored state with
 * SwarmAgentExec, and copies that page with SwarmKvMove. The integer
 * trainer, the sha256 digest, and the byte copy stay in those engines.
 *
 * digest() is the agent result. page_bytes() is SwarmKvMove::bytes_moved().
 * trained_steps() is SwarmIntCycle::steps().
 * launched() stays false. gpu() stays false.
 * There is no method that sets either true.
 */
class SwarmRunTick {
public:
    /**
     * Train `steps`, hash the stored state, and copy that page.
     * steps below 1 sets err to STEPS and does not call the trainer.
     * Otherwise calls SwarmIntCycle::Run(steps, err). A failed Run
     * returns false with the trainer error and does not hash or copy.
     * On success, Allow("work/") when that prefix is not stored yet,
     * then Execute("sha256", "work/state", state_hash()). A failed
     * Execute returns false and does not copy.
     * Then Put("src", state_hash(), "full", the raw bytes of the
     * state_hash string) and Put("dst", state_hash(), "full", a
     * different one-byte body), then Move("src", "dst", "memory").
     * Returns true only when that move returns true.
     */
    bool Tick(uint64_t steps, std::string& err);

    /**
     * Refuse a GPU tick. Always sets err to ENGINE_ABSENT and returns
     * false. Does not call Run, Execute, or Move. trained_steps() stays
     * unchanged. gpu() stays false.
     */
    bool GpuTick(uint64_t steps, std::string& err);

    /** Agent result. Empty until Execute stores a digest. */
    std::string digest() const;

    /** SwarmKvMove::bytes_moved(). */
    std::int64_t page_bytes() const;

    /** SwarmIntCycle::steps(). */
    uint64_t trained_steps() const;

    bool launched() const;
    bool gpu() const;

private:
    SwarmIntCycle m_cycle;
    SwarmAgentExec m_exec;
    SwarmKvMove m_kv;
    bool m_prefix_ready{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_RUNTICK_H

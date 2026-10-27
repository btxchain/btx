// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_OBSERVE_NIF_OBSERVE_H
#define BITCOIN_MODELNET_NIF_OBSERVE_NIF_OBSERVE_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/nif_exec/nif_exec.h>
#include <modelnet/nif_lifecycle/nif_lifecycle.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * In-process observation of one admitted inference id.
 *
 * Admit stores one id. An empty id is REQUEST and stores nothing. While that
 * id is stored, another Admit returns NIFDT_REPLAY and keeps the first id,
 * including a second admit of the same id.
 *
 * Tick(now_ms, err) performs one bounded pass and returns. It does not loop
 * and it does not sleep. ticks() increases by 1 on every call, including a
 * call that does no work. With no admitted request, Tick returns true, err is
 * empty, and bytes_moved() stays 0. After one admit, the next Tick records
 * that id as observed once. A later Tick does not observe it again.
 * observed() stays 1.
 *
 * The pass asks NifLifecycle and NifExec whether that id is already held,
 * whether any bytes moved, and whether a launch, gpu, broadcast, or spend
 * key is present. Observation records the id only. It does not pull a byte.
 *
 * Spend returns false with NIFDT_AUTOMATIC_SPEND and does not change a
 * balance. automatic_spend() stays NIFDT_AUTOMATIC_SPEND. balance() stays 0.
 * Gpu returns false with NIFDT_ENGINE_ABSENT. gpu(), launched(), and
 * broadcast() stay false.
 *
 * This class does not spawn a process, open a socket, or broadcast.
 */
class NifObserve {
public:
    bool Admit(const std::string& id, std::string& err);
    bool Tick(int64_t now_ms, std::string& err);
    bool Spend(std::string& err);
    bool Gpu(std::string& err);

    int64_t ticks() const { return m_ticks; }
    int64_t observed() const { return m_observed; }
    std::string observed_id() const { return m_observed_id; }
    int64_t last_tick_ms() const { return m_now_ms; }
    int64_t bytes_moved() const;
    int64_t balance() const { return m_balance; }
    std::string automatic_spend() const;
    bool gpu() const;
    bool launched() const;
    bool broadcast() const;

private:
    bool Quiet() const;

    NifLifecycle m_life;
    NifExec m_exec;
    std::string m_id;
    std::string m_observed_id;
    int64_t m_ticks{0};
    int64_t m_observed{0};
    int64_t m_bytes{0};
    int64_t m_balance{0};
    int64_t m_now_ms{0};
    bool m_has{false};
    bool m_seen{false};
    bool m_gpu{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_OBSERVE_NIF_OBSERVE_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_ACC02_ACC02_H
#define BITCOIN_MODELNET_ACC02_ACC02_H

#include <modelnet/nif_drain/nif_drain.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/realm_channel.h>
#include <modelnet/swarm_discover/swarm_discover.h>
#include <modelnet/swarm_evidence/swarm_evidence.h>
#include <modelnet/swarm_handoff/swarm_handoff.h>
#include <modelnet/swarm_hostinterp.h>
#include <modelnet/swarm_leasefence.h>
#include <modelnet/swarm_manifestok.h>
#include <modelnet/swarm_progress/swarm_progress.h>
#include <modelnet/swarm_revokegate.h>
#include <modelnet/swarm_sandboxfs.h>
#include <modelnet/training_integer.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Acc02 covers ASR-EXE-007 through ASR-ART-001.
 *
 * Pass latches. The first Pass calls the existing public functions that
 * already perform those sentences. A later Pass clears err and returns
 * true without calling them again.
 *
 * ASR-CAP-002 is not closed: Qualify stays NIFDT_UNQUALIFIED because no
 * real environment evidence is collected here.
 *
 * passed(), gpu_passed(), windows_passed(), release_qualified(), and
 * hardware_qualified() stay false. hosts() and physical_hosts() stay 1.
 * Spend returns NIFDT_AUTOMATIC_SPEND. bytes_moved() stays 0.
 */
class Acc02 {
public:
    bool Pass(std::string& err);
    bool Gpu(std::string& err);
    bool Hosts(int64_t n, std::string& err);
    bool Release(std::string& err);
    bool Spend(std::string& err);
    bool Qualify(std::string& err);
    bool Apply(const std::string& id, const std::string& text, int64_t aux, bool flag, std::string& err);

    bool Scan(std::string& err);
    bool RouteOutsideScope(std::string& err);
    bool TryExtendAuthority(int64_t now_ms, int64_t until_ms, std::string& err);
    bool TryUseAuthority(int64_t now_ms, std::string& err);
    bool ShareTrace(std::string& err);
    bool RetrievePromise(std::string& err);
    bool RefuseAmbiguousAgain(std::string& err);
    SwarmRevokeGateResult FenceResult(std::string& err) const;

    bool covered(const std::string& id) const;
    int64_t authority_until() const { return m_authority_until; }
    int64_t weight_before_resume() const { return m_weight_before_resume; }
    int64_t passes() const { return m_passes; }

    const SwarmDiscover& discover() const { return m_discover; }
    const NifDrain& drain() const { return m_drain; }
    const SwarmHandoff& handoff() const { return m_handoff; }
    const IntegerTrainer& resumed() const { return m_resumed; }
    const SwarmProgress& progress() const { return m_progress; }
    const SwarmEvidence& evidence() const { return m_evidence; }
    const SwarmHostInterp& interpreters() const { return m_interpreters; }
    const SwarmSandboxFs& sandbox() const { return m_sandbox; }
    const SwarmManifestOk& manifest() const { return m_manifest; }
    const RealmRollout& updates() const { return m_updates; }

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool advertised() const { return false; }
    bool passed() const { return false; }
    bool gpu_passed() const { return false; }
    bool windows_passed() const { return false; }
    bool process_present() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
    std::string classification() const { return "SIMULATION_NOT_HARDWARE_MEASUREMENT"; }

private:
    bool m_done{false};
    int64_t m_passes{0};
    int64_t m_authority_until{0};
    int64_t m_weight_before_resume{0};

    SwarmLeaseFence m_authority;
    SwarmDiscover m_discover;
    NifDrain m_drain;
    SwarmHandoff m_handoff;
    IntegerTrainer m_resumed;
    SwarmProgress m_progress;
    SwarmEvidence m_evidence;
    SwarmHostInterp m_interpreters;
    SwarmSandboxFs m_sandbox;
    SwarmManifestOk m_manifest;
    RealmRollout m_updates;
    std::map<std::string, std::string> m_journal;
};

} // namespace modelnet

#endif

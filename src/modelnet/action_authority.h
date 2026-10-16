// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_ACTION_AUTHORITY_H
#define BITCOIN_MODELNET_ACTION_AUTHORITY_H

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace modelnet {

/**
 * One-use local action permit. This is not modelnet::LocalCapabilityGrant
 * (src/modelnet/capability.h). LocalCapabilityGrant remains the existing local
 * authority; ActionPermit only names that grant and binds one effect.
 * Research authority does not grant wallet spend.
 */
struct ActionPermit {
    std::string permit_id;
    /** modelnet::LocalCapabilityGrant::grant_id this permit is issued against. */
    std::string grant_id;
    uint64_t generation{0};
    std::string effect;
    int64_t not_after_ms{0};
    /** Parameter fingerprint bound to this one use. */
    std::string parameter_fingerprint;
};

/** Logical cancellation and physical disposition are independent. */
struct OperationDisposition {
    std::string logical_state;
    std::string physical_state;
    std::string uncertainty;
};

/** Research keys and LocalCapabilityGrant do not authorize wallet spend. */
bool ResearchMaySpend();

class ActionGate {
public:
    ActionGate() = default;
    ActionGate(const ActionGate&) = delete;
    ActionGate& operator=(const ActionGate&) = delete;

    bool Issue(const ActionPermit& permit, std::string& err);
    bool Consume(const std::string& permit_id, const std::string& effect, uint64_t generation, int64_t now_ms,
                 const std::string& fingerprint, std::string& err);
    bool Attenuate(const std::vector<std::string>& parent_effects, const std::vector<std::string>& child_effects,
                   std::string& err) const;
    void Pause();
    /** Clears a pause. A revoked gate stays revoked. */
    void Resume();
    void Revoke();

    /** Sets logical_state to CANCELLED. Does not write physical_state. */
    void CancelLogical(const std::string& op);
    /** Records an observed physical disposition without changing logical_state. */
    void ReportPhysical(const std::string& op, const std::string& physical_state);
    /**
     * Records uncertainty "UNKNOWN". Returns false and does not return a
     * success capability or a LocalCapabilityGrant.
     */
    bool UnknownEffect(const std::string& op);

    OperationDisposition Disposition(const std::string& op) const;

private:
    struct Issued {
        ActionPermit permit;
        bool consumed{false};
    };
    struct Operation {
        std::string logical_state;
        std::string physical_state;
        std::string uncertainty;
    };

    mutable std::mutex m_mu;
    std::unordered_map<std::string, Issued> m_permits;
    std::unordered_map<std::string, Operation> m_ops;
    bool m_paused{false};
    bool m_revoked{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_ACTION_AUTHORITY_H

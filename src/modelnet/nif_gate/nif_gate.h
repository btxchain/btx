// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_GATE_NIF_GATE_H
#define BITCOIN_MODELNET_NIF_GATE_NIF_GATE_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Note refused a kind outside the five evidence kinds. Nothing is stored. */
inline constexpr char NIF_GATE_CLASS[] = "CLASS";

/** Note refused an empty name. Nothing is stored. */
inline constexpr char NIF_GATE_NAME[] = "NAME";

/**
 * NIF-QA-007 and DT-REL-007. The gate records evidence and still refuses
 * release.
 *
 * Note stores one linked name for a kind. kind is gpu, lan, wan, security,
 * or payment. Any other kind is CLASS and stores nothing. An empty name is
 * NAME and stores nothing. A name for which NifDtEngineLinked is false is
 * NIFDT_ENGINE_ABSENT. That name is stored in the absent list and that note
 * does not mark the kind passed. A kind already recorded stays recorded.
 *
 * A linked name records the kind once. A later linked note of the same kind
 * is NIFDT_REPLAY and the first name stays. PassedCount() is the number of
 * kinds recorded with a linked name. It is 0 through 5.
 *
 * Release returns false with NIFDT_UNQUALIFIED even when PassedCount() is 5.
 * It does not clear recorded kinds. release_qualified(), hardware_qualified(),
 * and qualified() stay false.
 *
 * launched(), gpu(), and broadcast() stay false. gpu() is not the gpu
 * evidence kind. automatic_spend() is NIFDT_AUTOMATIC_SPEND ("0").
 * bytes_moved() stays 0. hosts() and physical_hosts() stay 1. This class
 * opens no socket and starts no process.
 */
class NifGate {
public:
    bool Note(const std::string& kind, const std::string& name, std::string& err);
    bool Release(std::string& err);

    int64_t PassedCount() const;
    bool Absent(const std::string& name) const;
    bool kind_passed(const std::string& kind) const;
    std::string noted_name(const std::string& kind) const;

    bool release_qualified() const { return false; }
    bool hardware_qualified() const { return false; }
    bool qualified() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }

private:
    struct KindNote {
        bool passed{false};
        std::string name;
    };

    KindNote* Find(const std::string& kind);
    const KindNote* Find(const std::string& kind) const;

    KindNote m_gpu;
    KindNote m_lan;
    KindNote m_wan;
    KindNote m_security;
    KindNote m_payment;
    std::vector<std::string> m_absent;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_GATE_NIF_GATE_H

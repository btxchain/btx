// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_CONTINUE_NIF_CONTINUE_H
#define BITCOIN_MODELNET_NIF_CONTINUE_NIF_CONTINUE_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/swarm_kvwire/swarm_kvwire.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Exact continuation moves bytes through the local KV wire. Approximate state is not exact. */
class NifContinue {
public:
    bool Bind(const std::string& model_fingerprint, const std::string& runtime_fingerprint, const std::string& realm, NifExactness exactness, std::string& err);
    bool Move(const std::vector<unsigned char>& body, const std::string& model_fingerprint, const std::string& runtime_fingerprint, const std::string& realm, NifExactness exactness, std::string& err);
    bool Remote(const std::string& engine, std::string& err);

    const std::vector<unsigned char>& received() const { return m_wire.received(); }
    int64_t bytes_moved() const { return m_wire.bytes_moved(); }
    bool all_rank_qualified() const { return false; }
    bool approximate_called_exact() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    SwarmKvWire m_wire;
    std::string m_model;
    std::string m_runtime;
    std::string m_realm;
    NifExactness m_exact{NifExactness::ExactReproducible};
    bool m_bound{false};
};

} // namespace modelnet

#endif

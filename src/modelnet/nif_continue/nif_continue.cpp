// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_continue/nif_continue.h>

namespace modelnet {

bool NifContinue::Bind(const std::string& model_fingerprint, const std::string& runtime_fingerprint, const std::string& realm, NifExactness exactness, std::string& err)
{
    if (model_fingerprint.empty() || runtime_fingerprint.empty()) {
        err = "FINGERPRINT";
        return false;
    }
    m_model = model_fingerprint;
    m_runtime = runtime_fingerprint;
    m_realm = realm;
    m_exact = exactness;
    m_bound = true;
    err.clear();
    return true;
}

bool NifContinue::Move(const std::vector<unsigned char>& body, const std::string& model_fingerprint, const std::string& runtime_fingerprint, const std::string& realm, NifExactness exactness, std::string& err)
{
    if (!m_bound) {
        err = "FINGERPRINT";
        return false;
    }
    if (body.empty()) {
        err = "PAGE";
        return false;
    }
    if (exactness != NifExactness::ExactReproducible || m_exact != NifExactness::ExactReproducible) {
        err = "APPROXIMATE";
        return false;
    }
    if (model_fingerprint != m_model || runtime_fingerprint != m_runtime || realm != m_realm) {
        err = "COMPAT";
        return false;
    }
    return m_wire.Transfer(body, err);
}

bool NifContinue::Remote(const std::string& engine, std::string& err)
{
    return m_wire.Remote(engine, err);
}

} // namespace modelnet

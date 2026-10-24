// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_pages/nif_pages.h>

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

bool NifPages::Bind(const std::string& model, const std::string& runtime, const std::string& realm, std::string& err)
{
    if (!m_continue.Bind(model, runtime, realm, NifExactness::ExactReproducible, err)) {
        return false;
    }
    m_model = model;
    m_runtime = runtime;
    m_realm = realm;
    err.clear();
    return true;
}

bool NifPages::Place(int64_t seq, int64_t attention_pos, int64_t window, std::string& err)
{
    if (window < static_cast<int64_t>(1)) {
        err = "WINDOW";
        return false;
    }
    if (attention_pos > seq) {
        err = "POSITION";
        return false;
    }
    m_seq = seq;
    m_attention = attention_pos;
    m_placed = true;
    err.clear();
    return true;
}

bool NifPages::MovePage(const std::vector<unsigned char>& body, std::string& err)
{
    if (body.empty()) {
        err = "PAGE";
        return false;
    }
    if (!m_placed) {
        err = "PAGE";
        return false;
    }
    return m_continue.Move(body, m_model, m_runtime, m_realm, NifExactness::ExactReproducible, err);
}

bool NifPages::Remote(const std::string& engine, const std::vector<unsigned char>& body, std::string& err)
{
    static_cast<void>(body);
    const bool opened = m_continue.Remote(engine, err);
    if (engine == "nixl" || engine == "mooncake" || engine == "rdma") {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    return opened;
}

} // namespace modelnet

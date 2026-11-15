// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_NIF_PAGES_NIF_PAGES_H
#define BITCOIN_MODELNET_NIF_PAGES_NIF_PAGES_H

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/nif_continue/nif_continue.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * One continuation page on this host.
 *
 * Bind stores the model, runtime, and realm and calls NifContinue::Bind
 * with ExactReproducible. An empty model is FINGERPRINT and stores nothing.
 *
 * Place stores a cursor. window below 1 is WINDOW and stores nothing.
 * attention_pos greater than seq is POSITION and stores nothing. cursor()
 * returns seq. attention() returns attention_pos.
 *
 * MovePage calls NifContinue::Move only after a page was placed and only
 * when body is non-empty. An empty body is PAGE and moves nothing.
 * bytes_moved() grows only by what NifContinue reports. A report of zero
 * leaves bytes_moved() at 0.
 *
 * Remote calls NifContinue::Remote. nixl, mooncake, and rdma return
 * NIFDT_ENGINE_ABSENT and leave bytes_moved() unchanged.
 * all_rank_qualified(), launched(), gpu(), and broadcast() stay false.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND. physical_hosts() is 1.
 */
class NifPages {
public:
    bool Bind(const std::string& model, const std::string& runtime, const std::string& realm, std::string& err);
    bool Place(int64_t seq, int64_t attention_pos, int64_t window, std::string& err);
    bool MovePage(const std::vector<unsigned char>& body, std::string& err);
    bool Remote(const std::string& engine, const std::vector<unsigned char>& body, std::string& err);

    int64_t cursor() const { return m_seq; }
    int64_t attention() const { return m_attention; }
    int64_t bytes_moved() const { return m_continue.bytes_moved(); }
    bool all_rank_qualified() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }

private:
    NifContinue m_continue;
    std::string m_model;
    std::string m_runtime;
    std::string m_realm;
    int64_t m_seq{0};
    int64_t m_attention{0};
    bool m_placed{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_NIF_PAGES_NIF_PAGES_H

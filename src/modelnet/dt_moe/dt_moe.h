// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_MOE_DT_MOE_H
#define BITCOIN_MODELNET_DT_MOE_DT_MOE_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Expert count or top_k does not match, or the score length does not match. */
inline constexpr char DT_MOE_SHAPE[] = "SHAPE";

/** The same expert was chosen or contributed twice. The first record stays. */
inline constexpr char DT_MOE_DUPLICATE[] = "DUPLICATE";

/** Apply ran before every selected expert had one contribution. */
inline constexpr char DT_MOE_MISSING[] = "MISSING";

/**
 * Laboratory mixture-of-experts step. This is not a V4.1 claim.
 * qualified_v41() stays false.
 *
 * Configure stores an expert count and a top_k. experts below 1, top_k
 * below 1, or top_k greater than experts is SHAPE and stores nothing.
 *
 * Route selects top_k distinct expert indexes by integer score, highest
 * first. The score vector length must equal the expert count. When top_k
 * is greater than 1, a tie for the slot being filled would repeat an
 * expert under an unmasked argmax: Route returns DUPLICATE and stores
 * nothing. A top_k of 1 keeps the lowest index on a tied maximum, because
 * that single pick does not repeat an expert. token_count() increases by
 * 1 only on a successful route.
 *
 * Contribute records one integer gradient for a selected expert. The
 * optimizer owner is the expert id. A replica id is recorded as a compute
 * replica, and optimizer_owners(expert) stays 1. The same expert again is
 * DUPLICATE and does not add the gradient again.
 *
 * Apply updates owner weights only when every expert selected by the last
 * successful route has exactly one contribution. Otherwise MISSING, and
 * the weights stay. A successful apply adds each gradient once.
 *
 * Rematerialize does not route again, so token_count() stays the same.
 * GpuDispatch returns false with NIFDT_ENGINE_ABSENT and does not change
 * token_count() or weights. gpu(), launched(), and broadcast() stay false.
 * automatic_spend() is NIFDT_AUTOMATIC_SPEND. No process is spawned.
 */
class DtMoe {
public:
    bool Configure(int experts, int top_k, std::string& err);
    bool Route(int64_t token, const std::vector<int64_t>& scores, std::string& err);
    bool Contribute(int expert, int replica, int64_t gradient, std::string& err);
    bool Apply(std::string& err);
    bool Rematerialize(std::string& err);
    bool GpuDispatch(std::string& err);

    bool qualified_v41() const { return false; }
    bool gpu() const { return false; }
    bool launched() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

    int64_t token_count() const { return m_token_count; }
    int experts() const { return m_experts; }
    int top_k() const { return m_top_k; }
    int64_t last_token() const { return m_last_token; }
    const std::vector<int>& selected() const { return m_selected; }

    int optimizer_owners(int expert) const;
    int64_t weight(int expert) const;
    int64_t contribution(int expert) const;
    bool contributed(int expert) const;
    const std::vector<int>& replicas(int expert) const;

private:
    struct Expert {
        int64_t weight{0};
        int64_t gradient{0};
        int contributions{0};
        std::vector<int> replicas;
    };

    bool Known(int expert) const;
    bool InSelection(int expert) const;

    int m_experts{0};
    int m_top_k{0};
    bool m_configured{false};
    bool m_route_open{false};
    int64_t m_token_count{0};
    int64_t m_last_token{0};
    std::vector<Expert> m_table;
    std::vector<int> m_selected;
    std::vector<int> m_no_replicas;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_MOE_DT_MOE_H

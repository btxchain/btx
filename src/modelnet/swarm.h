// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_H
#define BITCOIN_MODELNET_SWARM_H

#include <modelnet/types.h>

#include <map>
#include <string>
#include <vector>

namespace modelnet {

struct PieceNeed {
    uint32_t file_index{0};
    uint32_t piece_index{0};
    uint32_t length{0};
    bool verified{false};
    bool reserved_paid{false};
};

struct SourceOffer {
    std::string peer;
    bool paid{false};
    int64_t price_atoms{0};
    int eta_s{0};
    bool available{true};
    int64_t fee_atoms{0};
    uint32_t file_index{0};
    uint32_t first_piece{0};
    uint32_t piece_count{0}; // 0 = all pieces
    int queue_s{0};
    int conf_s{0};
    int mempool_s{0};
};

struct HybridPlan {
    std::vector<PieceNeed> free_pieces;
    std::vector<PieceNeed> paid_pieces;
    int64_t paid_atoms{0};
    int eta_s{0};
    bool wait_free{false};
    bool unknown_eta{false};
    bool stale_paid{false};
    bool unobserved_missing{false};
};

/** Per-piece free-first planner. Paid only for pieces with no free source.
 *  Honors PieceNeed::reserved_paid (FREE-11): already-reserved missing pieces stay
 *  in paid_pieces without selecting a new SourceOffer or adding cost. Newly selected
 *  paid pieces are marked reserved_paid. outstanding_paid_atoms is prior paid
 *  exposure (FREE-14); default only here. */
HybridPlan PlanRetrieval(const std::vector<PieceNeed>& missing,
                          const std::vector<SourceOffer>& sources,
                          RetrievalMode mode,
                          int64_t budget_atoms,
                          bool approved,
                          int64_t outstanding_paid_atoms = 0);

/** Drop paid ranges that free delivery already verified; zero paid_atoms so the quote is refreshed. */
void InvalidatePaidWhenFreeArrives(HybridPlan& plan, const std::vector<PieceNeed>& newly_verified);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_H

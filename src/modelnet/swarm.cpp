// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm.h>
#include <modelnet/transfer.h>

#include <algorithm>
#include <set>

namespace modelnet {
namespace {

bool SourceCovers(const SourceOffer& s, const PieceNeed& p)
{
    if (!s.available) return false;
    if (s.piece_count == 0) return true;
    if (s.file_index != p.file_index) return false;
    return p.piece_index >= s.first_piece && p.piece_index < s.first_piece + s.piece_count;
}

bool IsMonetary(const SourceOffer& s)
{
    return s.paid && (s.price_atoms > 0 || s.fee_atoms > 0);
}

int64_t SourceCost(const SourceOffer& s)
{
    if (s.price_atoms < 0 || s.fee_atoms < 0) return -1;
    if (s.price_atoms > MAX_MONEY_ATOMS - s.fee_atoms) return MAX_MONEY_ATOMS + 1;
    return s.price_atoms + s.fee_atoms;
}

bool SamePiece(const PieceNeed& a, const PieceNeed& b)
{
    return a.file_index == b.file_index && a.piece_index == b.piece_index;
}

} // namespace

HybridPlan PlanRetrieval(const std::vector<PieceNeed>& missing,
                          const std::vector<SourceOffer>& sources,
                          RetrievalMode mode,
                          int64_t budget_atoms,
                          bool approved,
                          int64_t outstanding_paid_atoms)
{
    HybridPlan plan;
    const bool may_spend = mode != RetrievalMode::FREE_ONLY &&
                           (approved || mode == RetrievalMode::FREE_FIRST_BUDGET);

    bool any_source = false;
    for (const auto& s : sources) {
        if (s.available) any_source = true;
    }

    std::set<size_t> used_paid;
    std::vector<PieceNeed> reserved_in;
    std::vector<PieceNeed> newly_paid;
    for (const auto& p : missing) {
        if (p.verified) continue;
        bool have_free = false;
        for (const auto& s : sources) {
            if (!IsMonetary(s) && SourceCovers(s, p)) {
                have_free = true;
                break;
            }
        }
        if (have_free) {
            plan.free_pieces.push_back(p);
            continue;
        }
        // FREE-11: restart must not select a new paid offer or add cost again.
        if (p.reserved_paid) {
            PieceNeed kept = p;
            kept.reserved_paid = true;
            reserved_in.push_back(kept);
            continue;
        }
        int best = -1;
        int64_t best_cost = -1;
        for (size_t i = 0; i < sources.size(); ++i) {
            const auto& s = sources[i];
            if (!IsMonetary(s) || !SourceCovers(s, p)) continue;
            const int64_t cost = SourceCost(s);
            if (cost < 0) continue;
            if (best < 0 || cost < best_cost) {
                best = static_cast<int>(i);
                best_cost = cost;
            }
        }
        if (best >= 0 && may_spend) {
            PieceNeed selected = p;
            selected.reserved_paid = true;
            newly_paid.push_back(selected);
            used_paid.insert(static_cast<size_t>(best));
        } else {
            plan.wait_free = true;
            plan.unobserved_missing = (best < 0);
            if (best < 0) plan.unknown_eta = true;
        }
    }

    int64_t cost = 0;
    for (size_t i : used_paid) {
        const int64_t c = SourceCost(sources[i]);
        if (c < 0 || cost > MAX_MONEY_ATOMS - c) {
            cost = MAX_MONEY_ATOMS + 1;
            break;
        }
        cost += c;
    }
    int64_t exposure = cost;
    if (outstanding_paid_atoms > 0) {
        if (outstanding_paid_atoms > MAX_MONEY_ATOMS || exposure > MAX_MONEY_ATOMS - outstanding_paid_atoms) {
            exposure = MAX_MONEY_ATOMS + 1;
        } else {
            exposure += outstanding_paid_atoms;
        }
    }
    if (!may_spend || exposure > budget_atoms || exposure > MAX_MONEY_ATOMS) {
        if (!newly_paid.empty()) plan.wait_free = true;
        newly_paid.clear();
        plan.paid_atoms = 0;
    } else {
        plan.paid_atoms = cost;
    }

    if (!any_source) {
        plan.unknown_eta = true;
        plan.wait_free = true;
        plan.unobserved_missing = true;
        newly_paid.clear();
        plan.paid_atoms = 0;
    }

    plan.paid_pieces = std::move(reserved_in);
    plan.paid_pieces.insert(plan.paid_pieces.end(), newly_paid.begin(), newly_paid.end());

    int max_eta = 0;
    for (const auto& s : sources) {
        if (!s.available) continue;
        const int eta = EtaWithFees(s.queue_s != 0 ? s.queue_s : s.eta_s, s.conf_s, s.fee_atoms, s.mempool_s);
        if (eta > max_eta) max_eta = eta;
    }
    plan.eta_s = max_eta;
    return plan;
}

void InvalidatePaidWhenFreeArrives(HybridPlan& plan, const std::vector<PieceNeed>& newly_verified)
{
    const auto should_drop = [&](const PieceNeed& p) {
        for (const auto& v : newly_verified) {
            if (SamePiece(p, v) && v.verified) return true;
        }
        return false;
    };
    const size_t before = plan.paid_pieces.size();
    plan.paid_pieces.erase(std::remove_if(plan.paid_pieces.begin(), plan.paid_pieces.end(), should_drop),
                           plan.paid_pieces.end());
    plan.free_pieces.erase(std::remove_if(plan.free_pieces.begin(), plan.free_pieces.end(), should_drop),
                           plan.free_pieces.end());
    if (plan.paid_pieces.size() != before) {
        plan.stale_paid = true;
        plan.paid_atoms = 0;
    }
}

} // namespace modelnet

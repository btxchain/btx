// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DEFWORK_H
#define BITCOIN_MODELNET_SWARM_DEFWORK_H

#include <modelnet/swarm_defwork/codes.h>
#include <modelnet/swarm_defwork/limits.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>

namespace modelnet {

/**
 * Local effect broker for proposed work.
 *
 * This records proposals, one human approval, one receipt, and a rollback
 * mark. It does not open a socket, scan, or spend. No method sets
 * launched() true.
 *
 * Levels are D0, D1, D2, D3, and D4. Any other level is LEVEL and stores
 * nothing.
 *
 * Propose stores a proposal when case_id, action_id, and asset are
 * non-empty, blast >= 0, and the level is D0, D1, D2, or D3. An empty
 * case, action, or asset is ACTION and stores nothing. blast < 0 is BLAST
 * and stores nothing. D0, D1, and D2 return true. D3 is stored as proposed
 * and returns false with NEED_APPROVAL. D4 is REFUSED and stores nothing.
 * A second propose of a stored action_id is REPLAY and keeps the first
 * case, level, asset, and blast. A refused D4 does not replace a proposal
 * that was already stored.
 *
 * Approve with human false is NEED_APPROVAL and does not approve. Approve
 * with human true approves only a proposed D3 action whose case matches.
 * A second approval of that D3 action is REPLAY and returns true.
 * Approving an already proposed D0, D1, or D2 is REPLAY and returns true.
 * It does not mark that action approved. An unknown action, or a case that
 * does not match, is ACTION.
 *
 * Execute requires the same case, asset, and blast as the proposal. Any
 * mismatch is PRECONDITION and nothing executes. D4 cannot execute. D3
 * without approval is NEED_APPROVAL. Success records one receipt. A second
 * Execute of the same action_id is REPLAY and does not add a receipt.
 * Unknown records an external result, returns false with AMBIGUOUS, and a
 * later Execute returns AMBIGUOUS and does not retry. A rolled-back action
 * that has no receipt does not execute.
 *
 * Rollback with canary_ok false returns false with ROLLBACK and marks the
 * action rolled back. The stored asset and blast stay as proposed.
 * Rollback with canary_ok true returns true when the action is not rolled
 * back and does not change the asset or the blast. An action that is
 * already rolled back stays rolled back. An unknown action is ACTION.
 * Rollback does not erase a receipt.
 *
 * Retaliate always returns false with OUT_OF_SCOPE. It stores nothing and
 * erases nothing.
 *
 * launched(), gpu(), broadcast(), and connected() stay false.
 * automatic_spend() returns "0". atoms_moved() returns 0.
 */
class SwarmDefWork {
public:
    bool Propose(const std::string& case_id, const std::string& action_id, const std::string& level, const std::string& asset, int64_t blast, std::string& err);
    bool Approve(const std::string& case_id, const std::string& action_id, bool human, std::string& err);
    bool Execute(const std::string& case_id, const std::string& action_id, const std::string& asset, int64_t blast, std::string& err);
    bool Unknown(const std::string& action_id, std::string& err);
    bool Rollback(const std::string& action_id, bool canary_ok, std::string& err);
    bool Retaliate(const std::string& target, std::string& err);

    bool proposed(const std::string& action_id) const;
    bool approved(const std::string& action_id) const;
    bool has_receipt(const std::string& action_id) const;
    int64_t receipt_count() const;
    bool rolled_back(const std::string& action_id) const;
    bool ambiguous(const std::string& action_id) const;
    std::string asset_of(const std::string& action_id) const;
    std::string level_of(const std::string& action_id) const;
    int64_t blast_of(const std::string& action_id) const;

    bool launched() const;
    bool gpu() const;
    bool broadcast() const;
    bool connected() const;
    std::string automatic_spend() const;
    int64_t atoms_moved() const;

private:
    struct Action {
        std::string case_id;
        std::string level;
        std::string asset;
        int64_t blast{0};
        bool approved{false};
        bool receipt{false};
        bool rolled_back{false};
    };

    const Action* Find(const std::string& action_id) const;
    Action* Find(const std::string& action_id);

    std::map<std::string, Action> m_actions;
    std::set<std::string> m_ambiguous;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DEFWORK_H

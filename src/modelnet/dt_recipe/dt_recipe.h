// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_RECIPE_DT_RECIPE_H
#define BITCOIN_MODELNET_DT_RECIPE_DT_RECIPE_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** Optimizer name this engine can pin. */
inline constexpr char DT_RECIPE_ADAMW[] = "adamw";

/** Optimizer name this engine can pin. */
inline constexpr char DT_RECIPE_SGD[] = "sgd";

/** Named, but no kernel is linked. Pin does not store it. */
inline constexpr char DT_RECIPE_FP8[] = "fp8";

/** The name is empty or is not an optimizer this engine pins. */
inline constexpr char DT_RECIPE_PROFILE[] = "PROFILE";

/** The kind is not matrix, embedding, or scalar, or that kind was not stored. */
inline constexpr char DT_RECIPE_ROLE[] = "ROLE";

/** A gradient, learning rate, weight, loss, or updated weight was not finite. */
inline constexpr char DT_RECIPE_NONFINITE[] = "NONFINITE";

/** A later pin asked for a different name after the first successful step. */
inline constexpr char DT_RECIPE_FROZEN[] = "FROZEN";

/** One owned weight. Each of the three kinds has its own slot. */
inline constexpr char DT_RECIPE_MATRIX[] = "matrix";

/** One owned weight. Each of the three kinds has its own slot. */
inline constexpr char DT_RECIPE_EMBEDDING[] = "embedding";

/** One owned weight. Each of the three kinds has its own slot. */
inline constexpr char DT_RECIPE_SCALAR[] = "scalar";

/**
 * In-memory optimizer pin. This is not a V4.1 claim.
 * qualified_v41() stays false. backbone_changed() stays false.
 *
 * Pin accepts adamw and sgd. fp8 is not linked: Pin returns false with
 * ENGINE_ABSENT and leaves the pinned name. An empty name, and any other
 * name, returns false with PROFILE and leaves the pinned name.
 *
 * Role stores one finite weight for matrix, embedding, or scalar. Any
 * other kind is ROLE and stores nothing. A second Role of a kind that
 * is already stored returns false with REPLAY and keeps the first weight.
 *
 * Step applies weight = weight - lr * gradient for one stored kind only
 * when a name is pinned and both gradient and lr are finite. A missing
 * kind is ROLE. A non-finite gradient, learning rate, or updated weight
 * is NONFINITE and leaves that weight. A step with no pinned name is
 * PROFILE and does not freeze. The first successful step freezes the
 * name. A later Pin of a different name is FROZEN and keeps the first
 * name. Pin of the same name after that freeze succeeds and keeps it.
 *
 * Draft records one finite loss. It does not change any role weight and
 * does not set backbone_changed().
 *
 * launched(), gpu(), and broadcast() stay false. automatic_spend() is
 * "0". bytes_moved() and atoms_moved() stay 0. No socket is opened and
 * no process is started.
 */
class DtRecipe {
public:
    bool Pin(const std::string& name, std::string& err);
    bool Role(const std::string& kind, double weight, std::string& err);
    bool Step(const std::string& kind, double gradient, double lr, std::string& err);
    bool Draft(double loss, std::string& err);

    const std::string& name() const { return m_name; }
    bool frozen() const { return m_frozen; }
    bool has_role(const std::string& kind) const;
    double weight(const std::string& kind) const;
    bool has_draft() const { return m_has_draft; }
    double draft_loss() const { return m_has_draft ? m_draft : 0.0; }

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified_v41() const { return false; }
    bool backbone_changed() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }
    std::int64_t bytes_moved() const { return static_cast<std::int64_t>(0); }
    std::int64_t atoms_moved() const { return static_cast<std::int64_t>(0); }

private:
    struct RoleSlot {
        bool stored{false};
        double weight{0.0};
    };

    RoleSlot* Find(const std::string& kind);
    const RoleSlot* Find(const std::string& kind) const;

    std::string m_name;
    bool m_frozen{false};
    bool m_has_draft{false};
    double m_draft{0.0};
    RoleSlot m_matrix;
    RoleSlot m_embedding;
    RoleSlot m_scalar;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_RECIPE_DT_RECIPE_H

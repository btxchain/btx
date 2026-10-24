// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_recipe/dt_recipe.h>

#include <cmath>

namespace modelnet {

DtRecipe::RoleSlot* DtRecipe::Find(const std::string& kind)
{
    if (kind == DT_RECIPE_MATRIX) return &m_matrix;
    if (kind == DT_RECIPE_EMBEDDING) return &m_embedding;
    if (kind == DT_RECIPE_SCALAR) return &m_scalar;
    return nullptr;
}

const DtRecipe::RoleSlot* DtRecipe::Find(const std::string& kind) const
{
    if (kind == DT_RECIPE_MATRIX) return &m_matrix;
    if (kind == DT_RECIPE_EMBEDDING) return &m_embedding;
    if (kind == DT_RECIPE_SCALAR) return &m_scalar;
    return nullptr;
}

bool DtRecipe::Pin(const std::string& name, std::string& err)
{
    if (name == DT_RECIPE_FP8) {
        err = NIFDT_ENGINE_ABSENT;
        return false;
    }
    if (name != DT_RECIPE_ADAMW && name != DT_RECIPE_SGD) {
        err = DT_RECIPE_PROFILE;
        return false;
    }
    if (m_frozen && name != m_name) {
        err = DT_RECIPE_FROZEN;
        return false;
    }
    m_name = name;
    err.clear();
    return true;
}

bool DtRecipe::Role(const std::string& kind, double weight, std::string& err)
{
    RoleSlot* slot = Find(kind);
    if (slot == nullptr) {
        err = DT_RECIPE_ROLE;
        return false;
    }
    if (slot->stored) {
        err = NIFDT_REPLAY;
        return false;
    }
    if (!std::isfinite(weight)) {
        err = DT_RECIPE_NONFINITE;
        return false;
    }
    slot->weight = weight;
    slot->stored = true;
    err.clear();
    return true;
}

bool DtRecipe::Step(const std::string& kind, double gradient, double lr, std::string& err)
{
    RoleSlot* slot = Find(kind);
    if (slot == nullptr || !slot->stored) {
        err = DT_RECIPE_ROLE;
        return false;
    }
    if (!std::isfinite(gradient) || !std::isfinite(lr)) {
        err = DT_RECIPE_NONFINITE;
        return false;
    }
    if (m_name.empty()) {
        err = DT_RECIPE_PROFILE;
        return false;
    }
    const double updated = slot->weight - lr * gradient;
    if (!std::isfinite(updated)) {
        err = DT_RECIPE_NONFINITE;
        return false;
    }
    slot->weight = updated;
    // The first successful step locks the optimizer name.
    m_frozen = true;
    err.clear();
    return true;
}

bool DtRecipe::Draft(double loss, std::string& err)
{
    if (!std::isfinite(loss)) {
        err = DT_RECIPE_NONFINITE;
        return false;
    }
    m_draft = loss;
    m_has_draft = true;
    err.clear();
    return true;
}

bool DtRecipe::has_role(const std::string& kind) const
{
    const RoleSlot* slot = Find(kind);
    return slot != nullptr && slot->stored;
}

double DtRecipe::weight(const std::string& kind) const
{
    const RoleSlot* slot = Find(kind);
    if (slot == nullptr || !slot->stored) return 0.0;
    return slot->weight;
}

} // namespace modelnet

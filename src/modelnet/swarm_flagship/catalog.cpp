// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flagship/catalog.h>

#include <cstddef>
#include <optional>
#include <string>

namespace {

constexpr const char* kNames[] = {
    "acquire",
    "join",
    "coordinate",
    "accelerate",
    "experience",
    "train",
    "evolve",
    "evaluate",
    "graduate",
    "adopt",
    "pay",
    "recover",
    "repeat",
};

constexpr bool Spell(const char* left, const char* right)
{
    while (*left != '\0' && *left == *right) {
        ++left;
        ++right;
    }
    return *left == '\0' && *right == '\0';
}

constexpr std::size_t kNameCount = sizeof(kNames) / sizeof(kNames[0]);

static_assert(kNameCount == modelnet::SwarmFlagshipCatalog::count, "thirteen flagship stages");
static_assert(Spell(kNames[0], "acquire"), "stage acquire");
static_assert(Spell(kNames[1], "join"), "stage join");
static_assert(Spell(kNames[2], "coordinate"), "stage coordinate");
static_assert(Spell(kNames[3], "accelerate"), "stage accelerate");
static_assert(Spell(kNames[4], "experience"), "stage experience");
static_assert(Spell(kNames[5], "train"), "stage train");
static_assert(Spell(kNames[6], "evolve"), "stage evolve");
static_assert(Spell(kNames[7], "evaluate"), "stage evaluate");
static_assert(Spell(kNames[8], "graduate"), "stage graduate");
static_assert(Spell(kNames[9], "adopt"), "stage adopt");
static_assert(Spell(kNames[10], "pay"), "stage pay");
static_assert(Spell(kNames[11], "recover"), "stage recover");
static_assert(Spell(kNames[12], "repeat"), "stage repeat");

} // namespace

namespace modelnet {

const char* SwarmFlagshipCatalog::name(std::size_t index)
{
    if (index >= count || index >= kNameCount) {
        return nullptr;
    }
    return kNames[index];
}

std::optional<std::size_t> SwarmFlagshipCatalog::index(const std::string& stage)
{
    for (std::size_t i = 0; i < count; ++i) {
        const char* listed = name(i);
        if (listed != nullptr && stage == listed) {
            return i;
        }
    }
    return std::nullopt;
}

bool SwarmFlagshipCatalog::known(const std::string& stage)
{
    return index(stage).has_value();
}

} // namespace modelnet

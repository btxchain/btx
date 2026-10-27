// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALENGINE_VALIDATION_H
#define BITCOIN_MODELNET_SWARM_EVALENGINE_VALIDATION_H

#include <cstddef>
#include <map>
#include <string>

namespace modelnet {

/**
 * Independent validation of one challenge.
 * Only an independent validation is stored. validated stays true.
 * A second validation does not replace the first. Fitness may move
 * for the plane only after a row exists.
 */
struct SwarmEvaluationValidation {
    std::string id;
    bool independent{false};
    bool validated{false};
};

/**
 * Validations keyed by challenge id.
 * mark stores one independent validation. A second mark keeps the first.
 * A non-independent attempt is not stored. There is no erase.
 */
class SwarmEvaluationValidationBook {
public:
    bool validated(const std::string& id) const;
    bool any() const;
    std::size_t size() const;
    bool mark(const std::string& id);

private:
    std::map<std::string, SwarmEvaluationValidation> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALENGINE_VALIDATION_H

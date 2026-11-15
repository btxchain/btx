// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_descendants/integer_bound.h>

#include <modelnet/training_integer.h>

namespace modelnet {

std::size_t SwarmDescendantIntegerBound::pairs() const
{
    return IntegerDataset().size();
}

const char* SwarmDescendantIntegerBound::profile() const
{
    return INTEGER_PROFILE;
}

bool SwarmDescendantIntegerBound::extends_dataset() const
{
    return false;
}

} // namespace modelnet

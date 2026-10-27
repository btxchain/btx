// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTSEEDER_H
#define BTX_MODELNET_SWARM_NOTSEEDER_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. device_present records whether a device is
 * on the platform. want_train asks this note to train.
 *
 * An absent device note does not launch training. A present device still
 * trains nothing from this note. seeding and training stay false and slots
 * stays 0 on every path.
 */
struct SwarmNotSeeder {
    std::string node_id;
    bool device_present{false};
    bool want_train{false};
};

/**
 * Outcome of noting a seeder claim. seeding and training stay false and
 * slots stays 0 on every path.
 */
struct SwarmNotSeederResult {
    std::string code;
    bool seeding{false};
    bool training{false};
    int slots{0};
};

/**
 * Note a seeder claim without seeding or starting training.
 * Order, first match wins:
 * 1. An empty node_id is NODE. seeding stays false, training stays false,
 *    slots stays 0, and err is NODE.
 * 2. If device_present is false, the note is PUBLIC_SEED even when
 *    want_train is false. seeding stays false, training stays false,
 *    slots stays 0, and err is PUBLIC_SEED. An absent device note does
 *    not launch training.
 * 3. want_train is CPU_ONLY. seeding stays false, training stays false,
 *    slots stays 0, and err is CPU_ONLY. A present device still trains
 *    nothing from this note.
 * 4. Otherwise the note is NOTED. seeding stays false, training stays
 *    false, slots stays 0, and err is cleared.
 * seeding and training stay false and slots stays 0 on every path.
 */
SwarmNotSeederResult SwarmNoteNotSeeder(const SwarmNotSeeder& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTSEEDER_H

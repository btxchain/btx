// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_REGRESS_H
#define BTX_MODELNET_SWARM_REGRESS_H

#include <string>

namespace modelnet {

/**
 * Local regression record for one candidate and one suite.
 * Attaching it does not graduate a model and does not replace SwarmGraduate.
 */
struct SwarmRegressionReport {
    std::string candidate_id;
    std::string suite_id;
    bool safety_regression{false};
    bool broad_regression{false};
    bool blocks_promotion{false};
};

/**
 * Empty candidate_id or suite_id is REGRESSION and leaves blocks_promotion false.
 * Otherwise SwarmSafetyAllowsGraduation decides. A false result sets
 * blocks_promotion and returns REGRESSION. A true result clears err and leaves
 * blocks_promotion false. This function does not graduate a model and does not
 * replace SwarmGraduate.
 */
bool SwarmAttachRegression(SwarmRegressionReport& report, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_REGRESS_H

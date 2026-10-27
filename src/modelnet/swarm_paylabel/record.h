// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PAYLABEL_RECORD_H
#define BITCOIN_MODELNET_SWARM_PAYLABEL_RECORD_H

#include <string>

namespace modelnet {

/**
 * The label stored by a successful Accept.
 * The record holds the label text only. It has no atom field and no spend.
 */
struct SwarmPayLabelRecord {
    std::string label;
};

SwarmPayLabelRecord SwarmPayLabelMakeRecord(const std::string& label);

/** True only when the label is exactly "work-payment". */
bool SwarmPayLabelRecordUsable(const SwarmPayLabelRecord& record);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PAYLABEL_RECORD_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PAYTEMPLATE_H
#define BTX_MODELNET_SWARM_PAYTEMPLATE_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A funding template record. channel_id names the channel. signer is
 * whether a signer is present. want_broadcast asks this record to
 * broadcast. atoms is the funding amount.
 *
 * A funding template record does not broadcast or mine.
 */
struct SwarmPayTemplate {
    std::string channel_id;
    bool signer{false};
    bool want_broadcast{false};
    int64_t atoms{0};
};

/**
 * Outcome of recording a funding template. broadcast, mined, and atoms
 * stay false, false, and 0 on every path.
 */
struct SwarmPayTemplateResult {
    std::string code;
    bool broadcast{false};
    bool mined{false};
    int64_t atoms{0};
};

/**
 * Record a funding template without broadcasting or mining.
 * Order, first match wins: an empty channel_id is CHANNEL. signer false
 * is SIGNER. atoms below 0 is RANGE. want_broadcast is HELD. Otherwise
 * the record is NOTED and err is clear.
 * broadcast, mined, and atoms stay false, false, and 0 on every path.
 * A funding template record does not broadcast or mine.
 */
SwarmPayTemplateResult SwarmRecordFundingTemplate(const SwarmPayTemplate& pay, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PAYTEMPLATE_H

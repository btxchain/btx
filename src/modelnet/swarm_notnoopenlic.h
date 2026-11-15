// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOOPENLIC_H
#define BTX_MODELNET_SWARM_NOTNOOPENLIC_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one inference. infer_id names the inference.
 * open_license marks an open-license local inference. want_tax asks
 * this note to tax it.
 *
 * Open-license local inference is not taxed. This note moves no atoms.
 * taxed stays false and atoms stays 0 on every path.
 */
struct SwarmNotNoOpenLic {
    std::string infer_id;
    bool open_license{false};
    bool want_tax{false};
};

/**
 * Outcome of noting an open-license inference. taxed stays false and
 * atoms stays 0 on every path. Open-license local inference is not
 * taxed. This note moves no atoms.
 */
struct SwarmNotNoOpenLicResult {
    std::string code;
    bool taxed{false};
    int64_t atoms{0};
};

/**
 * Note an open-license inference without taxing it.
 * Order, first match wins: an empty infer_id is INFER.
 * open_license is NOT_TAXED even when want_tax is false. want_tax is
 * NOT_TAXED. Otherwise the note is NOTED and err is clear.
 * taxed stays false and atoms stays 0 on every path.
 * Open-license local inference is not taxed. This note moves no atoms.
 */
SwarmNotNoOpenLicResult SwarmNoteNotNoOpenLic(const SwarmNotNoOpenLic& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOOPENLIC_H

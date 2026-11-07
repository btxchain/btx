// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTSIGSIZE_H
#define BTX_MODELNET_SWARM_NOTSIGSIZE_H

#include <string>

namespace modelnet {

/**
 * A local note that a signature-size check might verify a funding witness.
 * want_verify asks this note to treat a signature-size check as verification.
 *
 * A signature-size check is not a verified funding witness, so this note does
 * not verify one and does not broadcast one. verified and broadcast stay
 * false on every path.
 */
struct SwarmNotSigSize {
    std::string witness_id;
    int sig_bytes{0};
    bool want_verify{false};
};

/**
 * Outcome of noting a signature-size check. verified and broadcast stay
 * false on every path: a signature-size check is not a verified funding
 * witness.
 */
struct SwarmNotSigSizeResult {
    std::string code;
    bool verified{false};
    bool broadcast{false};
};

/**
 * Note that a signature-size check is not a verified funding witness.
 * Order, first match wins: an empty witness_id is WITNESS. A sig_bytes
 * value that is not exactly 0 is SIZE_ONLY even when want_verify is false.
 * want_verify is SIZE_ONLY. Otherwise the note is NOTED and err is clear.
 * verified and broadcast stay false on every path. A signature-size check
 * is not a verified funding witness.
 */
SwarmNotSigSizeResult SwarmNoteNotSigSize(const SwarmNotSigSize& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTSIGSIZE_H

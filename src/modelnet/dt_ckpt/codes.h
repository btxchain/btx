// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_CKPT_CODES_H
#define BITCOIN_MODELNET_DT_CKPT_CODES_H

namespace modelnet {

/** Empty weight bytes. Nothing is stored. */
inline constexpr char kDtCkptWeights[] = "WEIGHTS";

/** The artifact is unknown, or a required slice was dropped. */
inline constexpr char kDtCkptManifest[] = "MANIFEST";

/** Optimizer moments are absent. The export is not an exact resume. */
inline constexpr char kDtCkptPartial[] = "PARTIAL";

/** The body contains the ASCII marker PYTHON_PICKLE. Nothing is stored. */
inline constexpr char kDtCkptPickle[] = "PYTHON_PICKLE";

/** The body contains an executable marker. Nothing is stored. */
inline constexpr char kDtCkptCode[] = "CODE";

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_CKPT_CODES_H

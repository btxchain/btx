// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_MIGRATE_035_H
#define BITCOIN_MODELNET_MIGRATE_035_H

#include <modelnet/types.h>
#include <univalue.h>

#include <string>

namespace modelnet {

/** envelope_version 1 returns false with BTX035_ENVELOPE_VERSION and leaves id unchanged.
 *  envelope_version 2 returns RecordIdV11. EnvelopePreimage is not used. */
bool MigrateEnvelope(const UniValue& body, Digest48& id, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_MIGRATE_035_H

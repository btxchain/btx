// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/migrate_035.h>

#include <modelnet/canonical_codec.h>

#include <exception>

namespace modelnet {

bool MigrateEnvelope(const UniValue& body, Digest48& id, std::string& err)
{
    // Version 1 is refused here and does not call RecordIdV11 or EnvelopePreimage.
    if (!body.isObject() || !body.exists("envelope_version") || !body["envelope_version"].isNum()) {
        err = "BTX035_ENVELOPE_VERSION";
        return false;
    }
    int version = 0;
    try {
        version = body["envelope_version"].getInt<int>();
    } catch (const std::exception&) {
        err = "BTX035_ENVELOPE_VERSION";
        return false;
    }
    if (version != 2) {
        err = "BTX035_ENVELOPE_VERSION";
        return false;
    }
    return RecordIdV11(body, id, err);
}

} // namespace modelnet

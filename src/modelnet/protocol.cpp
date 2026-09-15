// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/protocol.h>

#include <span.h>

namespace modelnet {

bool ParseSendModels(Span<const unsigned char> payload, SendModels& out, std::string& err)
{
    if (payload.size() != SENDMODELS_BYTES) {
        err = "sendmodels size";
        return false;
    }
    DataStream s{payload};
    s >> out;
    if (out.version != MODEL_PROTOCOL_VERSION) {
        err = "sendmodels version";
        return false;
    }
    return true;
}

bool SerializeSendModels(const SendModels& msg, std::vector<unsigned char>& out, std::string& err)
{
    (void)err;
    DataStream s{};
    s << msg;
    out.assign(UCharCast(s.data()), UCharCast(s.data() + s.size()));
    return out.size() == SENDMODELS_BYTES;
}

bool ParseGetMdPeers(Span<const unsigned char> payload, GetMdPeers& out, std::string& err)
{
    if (payload.size() != 17) {
        err = "getmdpeers size";
        return false;
    }
    DataStream s{payload};
    s >> out;
    if (out.requested_count < 1 || out.requested_count > MAX_MDPEERS_HINTS) {
        err = "getmdpeers count";
        return false;
    }
    return true;
}

} // namespace modelnet

// Copyright (c) 2026 The BTX developers. MIT license.
#ifndef BITCOIN_MODELNET_SECURITY_V2_NATIVE_H
#define BITCOIN_MODELNET_SECURITY_V2_NATIVE_H
#include <string>
class UniValue;
namespace modelnet {
/** Owner RPC -> existing supervised guard. Never exposed over ModelNet PQ1.
 * False means unavailable/protocol failure; a valid refusal is a response. */
bool SwarmSecurityRequest(const UniValue& request, UniValue& response, std::string& error);
}
#endif

// Copyright (c) 2026 The BTX developers. MIT license.
#ifndef BITCOIN_MODELNET_SECURITY_V2_PEER_H
#define BITCOIN_MODELNET_SECURITY_V2_PEER_H
#include <modelnet/security_v2/evaluation.h>
namespace modelnet::security {
constexpr size_t MAX_PEER_BYTES=256*1024;
/** Transport must be an already authenticated native PQ1 session. The supplied
 * pin comes from that session, never from the HTTP body/header being checked. */
Json MakePeerRequest(Database& db,const std::string& recipient,int64_t now);
Json HandlePeerRequest(Database& db,const Json& request,const std::string& authenticated_pin,int64_t now);
void AcceptPeerResponse(Database& db,const Json& response,const std::string& authenticated_pin,int64_t now);
/** Explicit owner publication. No private grant, prompt, cache or work product
 * is exposed by discovery or by merely installing a model. */
void PublishEvidenceClosure(Database& db,const std::string& root,int64_t now);
std::vector<std::string> RecordDependencies(const Json& record);
} // namespace modelnet::security
#endif

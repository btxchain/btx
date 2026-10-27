// Copyright (c) 2026 The BTX developers. MIT license.
#ifndef BITCOIN_MODELNET_SECURITY_V2_MESH_H
#define BITCOIN_MODELNET_SECURITY_V2_MESH_H
#include <modelnet/security_v2/peer.h>
namespace modelnet::security {
/** All messages ride the existing btx-modeld PQ1 session. The transport pin
 * MUST be supplied by the authenticated session, never by a wire field.
 * Mesh never carries model bytes, credentials, prompts, tool commands or keys. */
constexpr size_t MAX_MESH_PACKET=256*1024;
void MeshTables(Database& db);
/** Owner-authorized realm publication of a bounded security-evidence closure.
 * Does not make a private composition public and never exports local grants. */
void MeshExport(Database& db,const std::string& id,int64_t now);
Json MeshRequest(Database& db,const std::string& recipient,int64_t now);
Json MeshHandle(Database& db,const Json& message,const std::string& transport_pin,int64_t now);
void MeshAccept(Database& db,const Json& response,const std::string& transport_pin,int64_t now);
/** Run by btxd-owned guard maintenance: issues bounded scheduled challenges,
 * publishes evidence under local consent, and enforces live evidence leases. */
void MeshTick(Database& db,int64_t now);
/** Require fresh independently signed, executed evidence and live peer leases
 * for every gate in an exact composition. Never treats enrollment as proof of
 * physical/organizational independence. */
void MeshRequireLive(Database& db,const Policy& policy,const std::string& capsule,int64_t now);
/** Continuous protection is opt-in only to authorize remote work; once opted in,
 * it is mandatory/fail-closed for protected channel activation and privileged tools.
 * Missing configuration never silently enables privileges. */
bool MeshEnabled(Database& db);
Json MeshStatus(Database& db,int64_t now);
} // namespace modelnet::security
#endif

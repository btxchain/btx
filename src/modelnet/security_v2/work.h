// Copyright (c) 2026 The BTX developers. MIT license.
#ifndef BITCOIN_MODELNET_SECURITY_V2_WORK_H
#define BITCOIN_MODELNET_SECURITY_V2_WORK_H
#include <modelnet/security_v2/evaluation.h>
namespace modelnet::security {
/** Exact, owner-preapproved deterministic task executed on a selected peer.
 * Not a generic shell or unbounded prompt gateway. The worker is restricted to
 * its locally installed, byte-pinned model and native sandbox plan. */
Json ExecuteMeshWork(Database& db,const std::string& work_id,int64_t now);
Json VerifyMeshWorkQuorum(Database& db,const std::string& work_id,int64_t now);
} // namespace modelnet::security
#endif

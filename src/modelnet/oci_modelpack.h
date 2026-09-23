// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_OCI_MODELPACK_H
#define BITCOIN_MODELNET_OCI_MODELPACK_H

#include <modelnet/import_plan.h>
#include <modelnet/verified_manifest.h>
#include <univalue.h>

#include <string>

namespace modelnet {

inline constexpr const char* MODELPACK_MEDIA_TYPE = "application/vnd.cncf.kitops.modelkit.config.v1+json";

/**
 * Map a KitOps/ModelPack config onto an ImportPlan. OCI remains an origin;
 * btx:// / VerifiedManifest remains identity. Does not fetch a registry.
 */
bool ApplyModelPackConfig(const UniValue& config, ImportPlan& plan, std::string& err);

/** KitOps-shaped config from a verified artifact. Digest is sha384, not a tag. */
bool ExportModelPackConfig(const VerifiedManifest& vm, const ImportPlan& plan, UniValue& out, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_OCI_MODELPACK_H

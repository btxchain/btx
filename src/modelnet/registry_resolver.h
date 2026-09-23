// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_REGISTRY_RESOLVER_H
#define BITCOIN_MODELNET_REGISTRY_RESOLVER_H

#include <string>
#include <vector>

namespace modelnet {

/**
 * RegistryResolver turns a vendor locator + immutable revision + relative file
 * into an HTTPS URL. It does not fetch, hash, or name the BTX artifact.
 *
 * Origin type is a delivery mechanism. It is never the model identity, the
 * publisher, or a runtime/accelerator claim.
 */
struct ResolvedRegistryUrl {
    std::string type;
    std::string url;
    std::string revision;
    std::string host;
};

/** Canonical origin types BTX knows how to map. Unknown types can still be HTTP locators. */
std::vector<std::string> KnownRegistryOriginTypes();

bool NormalizeRepoLocator(const std::string& type, const std::string& locator, std::string& ns_name, std::string& err);

/** Percent-encode a single path segment or query value. */
std::string RegistryUrlEncode(const std::string& raw);

/**
 * Map (type, locator, revision, filepath) → GET URL.
 * Hugging Face, hf-mirror, ModelScope, WiseModel, OpenXLab, Modelers, GitCode,
 * Gitee AI, OpenI, and generic HTTP/HTTPS locators. Names are not identities.
 */
bool ResolveRegistryFileUrl(const std::string& type, const std::string& locator, const std::string& revision,
                            const std::string& filepath, ResolvedRegistryUrl& out, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_REGISTRY_RESOLVER_H

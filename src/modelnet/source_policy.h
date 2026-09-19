// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SOURCE_POLICY_H
#define BITCOIN_MODELNET_SOURCE_POLICY_H

#include <string>

namespace modelnet {

/** External workers never receive wallet secrets. Torrent worker never receives S3 credentials. */
bool TorrentWorkerReceivesS3Credentials();
bool SourceFollowsRedirects();
/** Pin/SSRF for HF/HTTP locators. Reuses HuggingFaceLocatorAllowed. */
bool SourceLocatorAllowed(const std::string& kind, const std::string& locator, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SOURCE_POLICY_H

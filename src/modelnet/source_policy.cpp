// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/source_policy.h>

#include <modelnet/source_local.h>

namespace modelnet {

bool TorrentWorkerReceivesS3Credentials()
{
    return false;
}

bool SourceFollowsRedirects()
{
    return false;
}

bool SourceLocatorAllowed(const std::string& kind, const std::string& locator, std::string& err)
{
    if (kind == "LOCAL") {
        if (locator.empty()) {
            err = "locator";
            return false;
        }
        return true;
    }
    return HuggingFaceLocatorAllowed(locator, err);
}

} // namespace modelnet

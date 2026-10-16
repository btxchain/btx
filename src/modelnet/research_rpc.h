// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_RESEARCH_RPC_H
#define BITCOIN_MODELNET_RESEARCH_RPC_H

#include <string>

namespace modelnet {

/** Local lab dispatch. Success writes one non-empty JSON object.
 *  Any other method returns false with BTX035_NOT_IMPLEMENTED and clears response_json. */
bool DispatchLab035(const std::string& method, const std::string& request_json, std::string& response_json, std::string& err);

/** Parse `lab035 <method> <json>` and call DispatchLab035. This is not main(). */
bool Lab035Cli(int argc, const char* const* argv, std::string& out, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_RESEARCH_RPC_H

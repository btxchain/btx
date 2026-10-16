// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/research_rpc.h>

#include <string>

namespace modelnet {

bool Lab035Cli(int argc, const char* const* argv, std::string& out, std::string& err)
{
    out.clear();
    if (argv == nullptr || argc != 3 || argv[0] == nullptr || argv[1] == nullptr || argv[2] == nullptr) {
        err = "BTX035_INVALID_SCHEMA";
        return false;
    }
    const std::string path(argv[0]);
    const size_t slash = path.find_last_of('/');
    const std::string base = slash == std::string::npos ? path : path.substr(slash + 1);
    if (base != "lab035") {
        err = "BTX035_INVALID_SCHEMA";
        return false;
    }
    return DispatchLab035(argv[1], argv[2], out, err);
}

} // namespace modelnet

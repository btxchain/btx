// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MATMUL_BACKEND_CAPABILITIES_H
#define BTX_MATMUL_BACKEND_CAPABILITIES_H

#include <string>
#include <vector>

namespace matmul::backend {

enum class Kind {
    CPU,
    METAL,
    CUDA,
};

struct Capability {
    bool compiled{false};
    bool available{false};
    std::string reason;
};

struct Selection {
    std::string requested_input;
    bool requested_known{true};
    Kind requested{Kind::CPU};
    Kind active{Kind::CPU};
    std::string reason;
};

std::string ToString(Kind kind);
Capability CapabilityFor(Kind kind);
std::vector<std::pair<Kind, Capability>> AllCapabilities();
Selection ResolveRequestedBackend(const std::string& requested);

} // namespace matmul::backend

#endif // BTX_MATMUL_BACKEND_CAPABILITIES_H

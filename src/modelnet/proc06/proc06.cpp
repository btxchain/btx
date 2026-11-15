// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/proc06/proc06.h>

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {
namespace {

bool AlreadyCopied(const std::vector<std::string>& page_ids, const std::string& page_id)
{
    for (const std::string& id : page_ids) {
        if (id == page_id) return true;
    }
    return false;
}

} // namespace

bool Proc06::Exchange(const std::string& page_id, const std::string& fingerprint_a, const std::vector<unsigned char>& page, const std::string& fingerprint_b, std::string& err)
{
    if (page_id.empty()) {
        err = "KV";
        return false;
    }
    if (page.empty()) {
        err = "EMPTY";
        return false;
    }
    if (fingerprint_a.empty() || fingerprint_b.empty() || fingerprint_a != fingerprint_b) {
        err = "INCOMPATIBLE";
        return false;
    }
    if (AlreadyCopied(m_page_ids, page_id)) {
        err = "REPLAY";
        return false;
    }
    m_received = page;
    m_bytes = static_cast<int64_t>(page.size());
    m_page_ids.push_back(page_id);
    err.clear();
    return true;
}

} // namespace modelnet

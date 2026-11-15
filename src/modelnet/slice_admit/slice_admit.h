// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SLICE_ADMIT_SLICE_ADMIT_H
#define BITCOIN_MODELNET_SLICE_ADMIT_SLICE_ADMIT_H

#include <modelnet/admission_routes.h>
#include <modelnet/model_admission.h>
#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Slice admission gate.
 * Pass calls LivePathAllowed("slice-admit-open", false, code). That returns
 * true and code is empty. Then Quarantine("slice-admit-hold").
 * LivePathAllowed("slice-admit-hold", false, code) returns false and code is
 * BTX035_QUARANTINE.
 * hosts() and physical_hosts() stay 1. bytes_moved() stays 0.
 * passed(), launched(), gpu(), broadcast(), qualified(), and
 * release_qualified() stay false.
 * Release returns false with NIFDT_UNQUALIFIED.
 * Spend returns false with NIFDT_AUTOMATIC_SPEND.
 * This class opens no socket and starts no process.
 */
class SliceAdmit {
public:
    bool Pass(std::string& err);
    bool Release(std::string& err);
    bool Spend(std::string& err);

    bool passed() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }

};

} // namespace modelnet

#endif

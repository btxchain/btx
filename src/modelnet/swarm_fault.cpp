// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault.h>

namespace modelnet {
namespace {

SwarmFaultOutcome Refuse(const char* code, std::string& err)
{
    SwarmFaultOutcome out;
    out.recovered = false;
    out.stale_committed = false;
    out.bytes_moved = false;
    out.code = code;
    err = code;
    return out;
}

} // namespace

SwarmFaultOutcome SwarmRecoverFault(SwarmFaultKind kind, bool durable_claim, bool stale_epoch, std::string& err)
{
    if (stale_epoch) return Refuse("STALE_EPOCH", err);

    switch (kind) {
    case SwarmFaultKind::CoordinatorGone:
        if (durable_claim) {
            SwarmFaultOutcome out;
            out.recovered = true;
            out.stale_committed = false;
            out.bytes_moved = false;
            out.code = "DURABLE";
            err.clear();
            return out;
        }
        return Refuse("LOST", err);
    case SwarmFaultKind::StaleEpoch:
        return Refuse("STALE_EPOCH", err);
    case SwarmFaultKind::TruncatedCache:
        return Refuse("INCOMPLETE", err);
    case SwarmFaultKind::PartialPiece:
        return Refuse("PIECE", err);
    case SwarmFaultKind::CollateralReuse:
        return Refuse("COLLATERAL_REUSE", err);
    case SwarmFaultKind::RevokedCache:
        return Refuse("REVOKED", err);
    case SwarmFaultKind::FalseCompatibility:
        return Refuse("FAMILY_NOT_COMPAT", err);
    }
    err.clear();
    return {};
}

} // namespace modelnet

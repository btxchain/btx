// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DISABLED_STUB_H
#define BITCOIN_MODELNET_DISABLED_STUB_H

// Monetary-only (WITH_MODELNET=OFF) compile stub.
// cmake/bitcoin-build-config.h.in uses `#cmakedefine ENABLE_MODELNET 1`, so an
// OFF configure leaves ENABLE_MODELNET unset (cmake writes `/* #undef ... */`).
// Include this header only from contrib/modelnet/check-with-modelnet-off.sh.

#ifdef ENABLE_MODELNET
#error "src/modelnet/disabled_stub.h is for WITH_MODELNET=OFF (ENABLE_MODELNET unset)"
#endif

inline constexpr bool MODELNET_COMPILED = false;

#endif // BITCOIN_MODELNET_DISABLED_STUB_H

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_LAB_GUARD_CLIENT_H
#define BITCOIN_MODELNET_LAB_GUARD_CLIENT_H

#include <modelnet/guard_machine.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Send one guard protocol line to 127.0.0.1:`port` and read one reply line.
 * Any other host, or port 0, is BTX035_SCOPE_DENIED.
 */
bool GuardClientExchange(const std::string& host, uint16_t port, const std::string& line, std::string& reply, std::string& err);

bool GuardClientPrepare(const std::string& host, uint16_t port, const std::string& effect, const std::string& fingerprint,
                        uint64_t generation, GuardPermit& out, std::string& err);
bool GuardClientExecute(const std::string& host, uint16_t port, const std::string& secret, std::string& receipt_id, std::string& err);
bool GuardClientPause(const std::string& host, uint16_t port, std::string& err);
bool GuardClientResume(const std::string& host, uint16_t port, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_LAB_GUARD_CLIENT_H

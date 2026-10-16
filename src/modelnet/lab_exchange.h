// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_LAB_EXCHANGE_H
#define BITCOIN_MODELNET_LAB_EXCHANGE_H

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

struct ExchangeObject {
    std::string kind;
    std::string digest;
    std::string content;
};

/**
 * Write `objects` as a manifest the receiver can verify without the sender's
 * process. Each digest is the Git object digest of kind and content.
 * A later import of different bytes under the same digest fails closed.
 */
bool WriteExchangeManifest(const std::vector<ExchangeObject>& objects, std::string& manifest_json, std::string& err);

/** Verify every object and return the accepted rows. Does not trust the claimed digest. */
bool VerifyExchangeManifest(const std::string& manifest_json, std::vector<ExchangeObject>& objects, std::string& err);

/**
 * Ask 127.0.0.1:`port` for lab.snapshot_export over JSON-RPC and verify the
 * manifest it returns. Any other host is BTX035_SCOPE_DENIED.
 */
bool PullExchangeLoopback(const std::string& host, uint16_t port, const std::string& rpc_user,
                          const std::string& rpc_password, const std::string& repository_id,
                          std::string& manifest_json, std::string& err);

/**
 * One JSON-RPC lab035 call to 127.0.0.1. Any other host is BTX035_SCOPE_DENIED.
 * result_json is the inner result object.
 */
bool LabCallLoopback(const std::string& host, uint16_t port, const std::string& rpc_user,
                     const std::string& rpc_password, const std::string& method,
                     const std::string& params_json, std::string& result_json, std::string& err);

/**
 * POST `body_json` to `http://127.0.0.1:port/btx-model/3/` + `route`.
 * A non-200 body that is a BTX035_* code is returned in `err`.
 */
bool PeerRouteLoopback(const std::string& host, uint16_t port, const std::string& rpc_user,
                       const std::string& rpc_password, const std::string& route,
                       const std::string& body_json, std::string& result_json, std::string& err);

struct LoopbackPeer {
    std::string host;
    uint16_t port;
    std::string user;
    std::string password;
};

/** Loopback only. Does not dial DNS or any host other than 127.0.0.1. */
bool LoopbackPeers(std::vector<LoopbackPeer>& peers, bool& configured, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_LAB_EXCHANGE_H

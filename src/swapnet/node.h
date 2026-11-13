// Copyright (c) 2026 The BTX developers. MIT license.
#ifndef BTX_SWAPNET_NODE_H
#define BTX_SWAPNET_NODE_H
#include <swapnet/transport.h>
#include <functional>
#include <string>
#include <vector>
#include <univalue.h>
class ArgsManager;
class JSONRPCRequest;
namespace node { struct NodeContext; }
namespace swapnet {
void SetupArgs(ArgsManager& args);
bool StartNode(node::NodeContext& node);
void StopNode();
void PeerReady(PeerId peer);
void PeerClosed(PeerId peer);
bool Receive(PeerId peer, const std::string& command, const std::string& payload);
std::vector<Frame> Drain(PeerId peer);
UniValue ExecuteRPC(const JSONRPCRequest& request, const std::string& method, const UniValue& params);
using WalletBridge = std::function<UniValue(const JSONRPCRequest&)>;
void SetWalletBridge(WalletBridge bridge);
}
#endif

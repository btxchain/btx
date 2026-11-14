// Copyright (c) 2026 The BTX developers. MIT license.
#ifndef BTX_SWAPNET_EMBED_H
#define BTX_SWAPNET_EMBED_H
#include <functional>
#include <memory>
#include <string>
#include <cstdint>
namespace swapnet {
struct Callbacks {
    std::function<std::string(const std::string&,const std::string&,const std::string&)> core;
    std::function<bool(std::int64_t,const std::string&,const std::string&)> send;
};
// All methods must be called on the worker thread that constructed the engine.
// The native callback never exposes private PQ keys or a general remote RPC proxy.
class Engine {
public:
    Engine(const std::string& config,Callbacks callbacks);
    ~Engine();
    Engine(const Engine&)=delete; Engine& operator=(const Engine&)=delete;
    std::string Rpc(const std::string& principal,bool owner,const std::string& wallet,
                    const std::string& method,const std::string& params);
    void Peer(std::int64_t id,bool connected);
    void Message(std::int64_t id,const std::string& command,const std::string& payload);
    void Tick();
private:
    struct Impl; std::unique_ptr<Impl> m;
};
}
#endif

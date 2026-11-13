// Copyright (c) 2026 The BTX developers. MIT license.
#ifndef BTX_SWAPNET_RUNTIME_H
#define BTX_SWAPNET_RUNTIME_H
#include <swapnet/embed.h>
#include <swapnet/transport.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <future>
#include <mutex>
#include <set>
#include <thread>
namespace swapnet {
struct Auth { std::string principal;bool owner{false};std::string wallet; };
class Runtime {
public:
    Runtime(std::string network,std::string config,Callbacks callbacks);
    ~Runtime();
    void Start();
    void Stop();
    std::string Call(const Auth& auth,const std::string& method,const std::string& params);
    Transport& Wire(){return m_wire;}
    std::string LastError() const;
    static constexpr std::size_t MAX_REQUESTS=128;
private:
    struct Request {Auth auth;std::string method,params;std::promise<std::string> result;std::atomic<bool> cancelled{false};};
    void Work(std::promise<void> initialized);
    Transport m_wire;std::string m_config;Callbacks m_callbacks;
    mutable std::mutex m_mutex;std::condition_variable m_cv;
    std::deque<std::shared_ptr<Request>> m_requests;std::thread m_thread;
    bool m_stopping{false};bool m_started{false};std::string m_error;
};
}
#endif

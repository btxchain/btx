// Copyright (c) 2026 The BTX developers. MIT license.
#include <swapnet/runtime.h>
#include <logging.h>
#include <stdexcept>
#include <algorithm>
namespace swapnet {
Runtime::Runtime(std::string network,std::string config,Callbacks callbacks):m_wire(std::move(network)),m_config(std::move(config)),m_callbacks(std::move(callbacks)) {
    m_callbacks.send=[this](std::int64_t peer,const std::string& command,const std::string& payload){return m_wire.Send(peer,command,payload);};
}
Runtime::~Runtime(){Stop();}
void Runtime::Start(){
    std::unique_lock<std::mutex> lock(m_mutex);
    if(m_started)throw std::runtime_error("SwapNet runtime already started");
    m_started=true;m_stopping=false;
    std::promise<void> initialized;auto ready=initialized.get_future();
    m_thread=std::thread(&Runtime::Work,this,std::move(initialized));lock.unlock();
    try{ready.get();}catch(...){Stop();throw;}
}
void Runtime::Stop(){
    {std::lock_guard<std::mutex> lock(m_mutex);m_stopping=true;}
    m_cv.notify_all();if(m_thread.joinable())m_thread.join();m_wire.SetEnabled(false);
}
std::string Runtime::Call(const Auth& auth,const std::string& method,const std::string& params){
    if(auth.principal.empty()||auth.principal.size()>128||method.size()>64||params.size()>65536)
        throw std::runtime_error("SwapNet RPC bounds exceeded");
    auto request=std::make_shared<Request>();request->auth=auth;request->method=method;request->params=params;
    auto result=request->result.get_future();
    {std::lock_guard<std::mutex> lock(m_mutex);
        if(!m_started||m_stopping)throw std::runtime_error("SwapNet runtime is not available");
        if(m_requests.size()>=MAX_REQUESTS)throw std::runtime_error("SwapNet RPC queue is full");
        m_requests.push_back(request);}
    m_cv.notify_one();
    if(result.wait_for(std::chrono::seconds(60))!=std::future_status::ready){
        request->cancelled=true;
        throw std::runtime_error("SwapNet RPC timed out; inspect durable operation status before retrying");
    }
    return result.get();
}
std::string Runtime::LastError()const{std::lock_guard<std::mutex> lock(m_mutex);return m_error;}
void Runtime::Work(std::promise<void> initialized){
    bool announced=false;
    try{
        Engine engine(m_config,m_callbacks);initialized.set_value();announced=true;
        std::set<PeerId> admitted;auto next_tick=std::chrono::steady_clock::now();
        for(;;){
            std::shared_ptr<Request> request;
            {std::unique_lock<std::mutex> lock(m_mutex);
                m_cv.wait_for(lock,std::chrono::milliseconds(20),[this]{return m_stopping||!m_requests.empty();});
                if(m_stopping)break;
                if(!m_requests.empty()){request=m_requests.front();m_requests.pop_front();}}
            if(request&&!request->cancelled){
                try{request->result.set_value(engine.Rpc(request->auth.principal,request->auth.owner,request->auth.wallet,request->method,request->params));}
                catch(...){request->result.set_exception(std::current_exception());}}
            auto ids=m_wire.AdmittedPeers();std::set<PeerId> current(ids.begin(),ids.end());
            // A peer frame, including swprov "[]" or a non-UTF-8 byte, must not
            // leave the worker stopped. Startup failure is still fatal above.
            auto peer_guard=[](const char* what,auto&& fn){
                try { fn(); }
                catch(const std::exception& e){ LogPrintf("SwapNet: ignored peer fault during %s (%s)\n", what, e.what()); }
                catch(...){ LogPrintf("SwapNet: ignored peer fault during %s\n", what); }
            };
            for(auto id:current)if(!admitted.count(id))peer_guard("peer join",[&]{engine.Peer(id,true);});
            for(auto id:admitted)if(!current.count(id))peer_guard("peer leave",[&]{engine.Peer(id,false);});
            admitted=std::move(current);
            for(unsigned n=0;n<16;++n){auto frame=m_wire.TakeInbound();if(!frame)break;
                if(admitted.count(frame->peer))peer_guard("message",[&]{engine.Message(frame->peer,frame->command,frame->payload);});}
            if(std::chrono::steady_clock::now()>=next_tick){
                const auto hello_ms=std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                peer_guard("hello",[&]{m_wire.RetryHellos(hello_ms);});
                peer_guard("tick",[&]{engine.Tick();});
                next_tick=std::chrono::steady_clock::now()+std::chrono::seconds(1);}
        }
    }catch(...){
        if(!announced){initialized.set_exception(std::current_exception());}
        std::lock_guard<std::mutex> lock(m_mutex);m_error="SwapNet engine stopped after an internal error; recovery journal retained";m_stopping=true;
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    for(auto& request:m_requests){try{request->result.set_exception(std::make_exception_ptr(std::runtime_error("SwapNet shutdown")));}catch(...) {}}
    m_requests.clear();
}
}

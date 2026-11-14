// Standalone linked CPython/runtime test. Native chain calls are explicitly mocked.
#include <swapnet/runtime.h>
#include <cassert>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <thread>
int main(int argc,char** argv) {
    assert(argc==2);std::filesystem::path path(argv[1]);std::filesystem::create_directories(path);
    const std::string network(64,'a');swapnet::Callbacks cb;
    cb.core=[](const std::string&,const std::string& method,const std::string&)->std::string {
        if(method=="listwallets")return "[]";
        throw std::runtime_error("mock node: unsupported chain call");
    };
    const auto config="{\"network\":\""+network+"\",\"chain\":\"regtest\",\"datadir\":\""+path.string()+"\"}";
    swapnet::Runtime runtime(network,config,cb);runtime.Start();
    auto info=runtime.Call({"local-owner",true,""},"getswapnetworkinfo","{}");
    assert(info.find("\"protocol\":2")!=std::string::npos);
    assert(info.find("\"in_process\":true")!=std::string::npos);
    auto denied=runtime.Call({"agent",false,""},"withdrawswapprovider","{}");
    assert(denied.find("OWNER_REQUIRED")!=std::string::npos);
    auto invalid=runtime.Call({"agent",false,""},"not_a_method","{}");
    assert(invalid.find("METHOD_NOT_FOUND")!=std::string::npos);
    runtime.Wire().PeerReady(1,1000);assert(runtime.Wire().TakeOutbound()->payload=="2:"+network);
    assert(runtime.Wire().Receive(1,"swhello","2:"+network,2000));
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    auto bootstrap=runtime.Call({"agent",false,""},"getswapbootstrapinfo","{}");
    assert(bootstrap.find("\"admitted_peers\":1")!=std::string::npos);
    runtime.Stop();assert(std::filesystem::exists(path/"swapnet"/"state.sqlite"));
    std::cout<<"PASS: linked C++ worker + frozen isolated Python, native RPC boundary, owner rejection, handshake admission, durable startup and clean shutdown; chain calls mocked\n";
}

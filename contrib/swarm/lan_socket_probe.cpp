// Copyright (c) 2026 The BTX developers. Distributed under the MIT license.
// Standalone same-host socket regression; never a physical LAN qualification.
#include <modelnet/native_discovery.h>
#include <chrono>
#include <iostream>
#include <set>
#include <thread>

int main(int argc, char** argv)
{
    if (argc != 2) return 2;
    int port = 0;
    try { port = std::stoi(argv[1]); } catch (...) { return 2; }
    if (port < 1024 || port > 65535) return 2;
    modelnet::NativeLanDiscovery discovery;
    std::string err;
    if (!discovery.Open("regtest", "0.0.0.0", static_cast<uint16_t>(port), err)) {
        std::cout << "{\"status\":\"BLOCKED\",\"reason\":\"" << err << "\"}\n";
        return 2;
    }
    const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(12);
    std::set<std::string> observed;
    std::set<std::string> other_ports;
    while (std::chrono::steady_clock::now() < end) {
        discovery.Tick();
        const auto peers = discovery.Endpoints();
        for (const auto& peer : peers) {
            observed.insert(peer);
            other_ports.insert(peer.substr(peer.rfind(':') + 1));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    if (other_ports.size() >= 2) {
        std::cout << "{\"status\":\"PASS_LOCAL_SOCKET\",\"physical_hosts\":1,\"authenticated\":false,\"peers\":[";
        size_t i = 0;
        for (const auto& peer : observed) std::cout << (i++ ? "," : "") << '"' << peer << '"';
        std::cout << "]}\n";
        return 0;
    }
    std::cout << "{\"status\":\"FAIL\",\"reason\":\"DISCOVERY_TIMEOUT\"}\n";
    return 1;
}

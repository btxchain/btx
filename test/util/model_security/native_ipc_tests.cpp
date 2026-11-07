// Copyright (c) 2026 The BTX developers. MIT license.
#include <modelnet/guard_supervisor.h>
#include <modelnet/security_v2/common.h>
#include <atomic>
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>
#ifndef _WIN32
#include <signal.h>
#include <unistd.h>
#endif
using namespace modelnet::security;
int main(int argc, char** argv)
{
    if (argc != 2) return 2;
    unsigned passed = 0;
    const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) / ("btx-native-security-" + Hex(RandomBytes(16)));
    try {
        EnsurePrivateDirectory(root);
        const auto exe = ::fs::PathFromString(argv[1]);
        const auto state = ::fs::PathFromString((root / "security").string());
        modelnet::GuardSupervisor supervisor;
        std::string error, reply;
        Require(supervisor.Start(exe, state, error), "TEST_NATIVE_START"); ++passed;
        Require(supervisor.Snapshot().ready, "TEST_NATIVE_READY"); ++passed;
        Require(supervisor.Exchange("PING", reply, error) && reply == "READY BTX_GUARD/1", "TEST_NATIVE_PING"); ++passed;
        Json status = Object(); status.pushKV("op", "status");
        Json response;
        Require(supervisor.SecurityExchange(status, response, error) && response.isObject(), "TEST_NATIVE_SECURITY_STATUS"); ++passed;
        // Oversized but bounded request exercises hundreds of private pipe
        // fragments without giving arbitrary fields any action authority.
        Json large = Object(); large.pushKV("op", "unknown"); large.pushKV("padding", std::string(180000, 'x'));
        Require(supervisor.SecurityExchange(large, response, error) && !response["ok"].get_bool(), "TEST_NATIVE_LARGE_REFUSAL"); ++passed;
        Require(supervisor.Snapshot().ready, "TEST_NATIVE_NOT_KILLED_BY_REFUSAL"); ++passed;
        // A request the canonical encoder refuses (a float, here) never reaches the
        // guard. It is a caller error: the guard, its boot id and its permits stay.
        const auto pid = supervisor.Snapshot().pid;
        Require(supervisor.SecurityExchange(status, response, error), "TEST_NATIVE_STATUS_BEFORE_SCHEMA_REFUSAL");
        const auto boot_before = response["guard_boot"].get_str();
        Json fractional = Object(); fractional.pushKV("op", "status"); fractional.pushKV("x", 1.5);
        Require(!supervisor.SecurityExchange(fractional, response, error) && error == "SEC_JSON_INTEGER", "TEST_NATIVE_NONCANONICAL_REFUSED"); ++passed;
        Require(supervisor.Snapshot().ready && supervisor.Snapshot().pid == pid, "TEST_NATIVE_NOT_KILLED_BY_SCHEMA_REFUSAL"); ++passed;
        Require(supervisor.SecurityExchange(status, response, error) && response["guard_boot"].get_str() == boot_before, "TEST_NATIVE_SAME_BOOT_AFTER_SCHEMA_REFUSAL"); ++passed;
        std::atomic<unsigned> successful{0};
        std::vector<std::thread> threads;
        for (unsigned i = 0; i < 4; ++i) threads.emplace_back([&] {
            for (unsigned j = 0; j < 8; ++j) {
                Json result; std::string failure;
                if (supervisor.SecurityExchange(status, result, failure) && result.isObject()) ++successful;
            }
        });
        for (auto& t : threads) t.join();
        Require(successful == 32, "TEST_NATIVE_CONCURRENT_FRAME_ISOLATION"); ++passed;
        supervisor.Stop();
        Require(!supervisor.Snapshot().ready && supervisor.Snapshot().pid == -1, "TEST_NATIVE_REAPED"); ++passed;
        Require(!supervisor.SecurityExchange(status, response, error), "TEST_NATIVE_STOPPED_DENIES"); ++passed;
        // Restart keeps private durable state but replaces the permit boot.
        Require(supervisor.Start(exe, state, error), "TEST_NATIVE_RESTART"); ++passed;
        Require(supervisor.SecurityExchange(status, response, error), "TEST_NATIVE_RESTART_STATUS"); ++passed;
        supervisor.Stop();
        Require(supervisor.Start(exe, error), "TEST_NATIVE_LEGACY_START"); ++passed;
        Require(supervisor.Exchange("PING", reply, error), "TEST_NATIVE_LEGACY_HEALTH"); ++passed;
        Require(!supervisor.SecurityExchange(status, response, error), "TEST_NATIVE_LEGACY_NO_V2_AUTHORITY"); ++passed;
        supervisor.Stop();
#ifndef _WIN32
        // A datadir reached through a symlinked ancestor (~/.btx -> /mnt/ssd/btx, or
        // /var -> /private/var on macOS) must not keep the guard down. A symlink at the
        // security directory itself is still refused.
        const auto real = root / "real";
        EnsurePrivateDirectory(real);
        std::filesystem::create_directory_symlink(real, root / "link");
        Require(supervisor.Start(exe, ::fs::PathFromString((root / "link" / "security").string()), error), "TEST_NATIVE_SYMLINKED_ANCESTOR"); ++passed;
        Require(supervisor.SecurityExchange(status, response, error) && response["ok"].get_bool(), "TEST_NATIVE_SYMLINKED_ANCESTOR_STATUS"); ++passed;
        supervisor.Stop();
        Require(std::filesystem::is_regular_file(real / "security" / "security.sqlite3"), "TEST_NATIVE_SYMLINKED_ANCESTOR_STORE"); ++passed;
        std::filesystem::create_directory_symlink(real / "security", root / "security-link");
        Require(!supervisor.Start(exe, ::fs::PathFromString((root / "security-link").string()), error), "TEST_NATIVE_SYMLINKED_SECURITY_DIRECTORY_REFUSED"); ++passed;
        supervisor.Stop();
#endif
        std::filesystem::remove_all(root);
        std::cout << "{\"suite\":\"native-private-guard-ipc\",\"passed\":" << passed
                  << ",\"failed\":0,\"physical_hosts\":1,\"full_daemon\":\"NOT_RUN\"}\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAILED " << e.what() << " after " << passed << " checks\n";
        std::filesystem::remove_all(root);
        return 1;
    }
}

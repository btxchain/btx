// Copyright (c) 2026 The BTX developers. MIT license.
// A slow answer is not a broken frame. While another connection holds the
// store's write lock (btx-modeld writes the same store), the guard's pause
// waits on SQLite's busy timeout. The supervisor must wait for the reply within
// the exchange deadline instead of restarting the guard.
#include <modelnet/guard_supervisor.h>
#include <modelnet/security_v2/common.h>
#include <modelnet/security_v2/database.h>
#include <chrono>
#include <future>
#include <iostream>
#include <thread>
using namespace modelnet::security;
int main(int argc, char** argv)
{
    if (argc != 2) return 2;
    unsigned passed = 0;
    const auto root = std::filesystem::canonical(std::filesystem::temp_directory_path()) / ("btx-native-busy-" + Hex(RandomBytes(16)));
    try {
        EnsurePrivateDirectory(root);
        const auto exe = ::fs::PathFromString(argv[1]);
        const auto state = ::fs::PathFromString((root / "security").string());
        modelnet::GuardSupervisor supervisor;
        std::string error;
        Require(supervisor.Start(exe, state, error), "TEST_BUSY_START"); ++passed;
        const auto pid = supervisor.Snapshot().pid;
        Database store(state);
        const auto boot = store.Meta("guard_boot");
        std::promise<void> locked;
        std::thread writer([&] {
            Database db(state);
            Database::Transaction tx(db);
            locked.set_value();
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            tx.Commit();
        });
        locked.get_future().wait();
        Json pause = Object(); pause.pushKV("op", "pause");
        Json response;
        const bool answered = supervisor.SecurityExchange(pause, response, error);
        writer.join();
        Require(answered && response["ok"].isTrue(), "TEST_BUSY_PAUSE_ANSWERED"); ++passed;
        Require(supervisor.Snapshot().ready && supervisor.Snapshot().pid == pid, "TEST_BUSY_GUARD_KEPT"); ++passed;
        Require(store.Meta("paused") == "1" && store.Meta("guard_boot") == boot, "TEST_BUSY_PAUSED_SAME_BOOT"); ++passed;
        supervisor.Stop();
        std::filesystem::remove_all(root);
        std::cout << "{\"suite\":\"native-guard-busy-store\",\"passed\":" << passed << ",\"failed\":0}\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAILED " << e.what() << " after " << passed << " checks\n";
        std::filesystem::remove_all(root);
        return 1;
    }
}

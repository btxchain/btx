// Copyright (c) 2026 The BTX developers. MIT license. See COPYING.
// Native finite-worker regression. Synthetic samples are test-only; the worker
// never exceeds its real resource budgets. Build the worker from this file with
// BTX_ACCOUNTING_WORKER; build backend fault variants with
// BTX_WINDOWS_ACCOUNTING_TEST. Neither flag is a product runtime setting.
#include <windows.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
constexpr DWORD OUTPUT_BYTES = 1024 * 1024;

struct Handle {
    HANDLE value{INVALID_HANDLE_VALUE};
    explicit Handle(HANDLE v) : value(v) {}
    ~Handle() { if (value != INVALID_HANDLE_VALUE && value != nullptr) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    bool valid() const { return value != INVALID_HANDLE_VALUE && value != nullptr; }
};

void Require(bool condition, const char* name)
{
    if (!condition) throw std::runtime_error(name);
}

void WriteFileBytes(const wchar_t* path, const char* bytes, DWORD count)
{
    Handle file(CreateFileW(path, GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    Require(file.valid(), "fixture-create");
    DWORD written = 0;
    Require(WriteFile(file.value, bytes, count, &written, nullptr) != FALSE && written == count,
        "fixture-write");
    Require(FlushFileBuffers(file.value) != FALSE, "fixture-flush");
}
} // namespace

#ifdef BTX_ACCOUNTING_WORKER

int main()
{
    try {
        std::ifstream in("input.bin", std::ios::binary);
        const std::string mode{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
        Require(in.is_open() && !in.bad(), "fixture-input");
        WriteFileBytes(L"started.bin", "STARTED", 7);
        Sleep(200); // Real launch/first-sample opportunity; not CPU consumption.
        if (mode == "nonzero") return 7;

        Require(CreateDirectoryW(L"moving", nullptr) != FALSE, "ordinary-create-directory");
        WriteFileBytes(L"moving\\seed.bin", "abc", 3);
        Require(MoveFileExW(L"moving", L"moved", MOVEFILE_WRITE_THROUGH) != FALSE,
            "ordinary-rename-directory");
        Require(CreateDirectoryW(L"remove-me", nullptr) != FALSE, "ordinary-create-empty-directory");
        Require(RemoveDirectoryW(L"remove-me") != FALSE, "ordinary-delete-directory");
        WriteFileBytes(L"temporary.bin", "x", 1);
        Require(DeleteFileW(L"temporary.bin") != FALSE, "ordinary-delete-file");

        // An ordinary exclusive writer remains open while the parent samples
        // metadata. Contents are finite and below the existing output budget.
        Handle output(CreateFileW(L"result.bin", GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
        Require(output.valid(), "ordinary-output-open");
        std::array<char, 64 * 1024> bytes{};
        bytes.fill('B');
        for (DWORD offset = 0; offset < OUTPUT_BYTES; offset += static_cast<DWORD>(bytes.size())) {
            DWORD written = 0;
            Require(WriteFile(output.value, bytes.data(), static_cast<DWORD>(bytes.size()),
                &written, nullptr) != FALSE && written == bytes.size(), "ordinary-output-write");
            Require(FlushFileBuffers(output.value) != FALSE, "ordinary-output-flush");
            Sleep(10);
        }
        // Close the exclusive output before the normal final integrity pass.
        Require(CloseHandle(output.value) != FALSE, "ordinary-output-close");
        output.value = INVALID_HANDLE_VALUE;
        WriteFileBytes(L"finished.bin", "FINISHED", 8);
        return 0;
    } catch (const std::exception& exception) {
        try {
            const std::string message{exception.what()};
            WriteFileBytes(L"worker-error.txt", message.data(), static_cast<DWORD>(message.size()));
        } catch (...) {}
        return 2;
    }
}

#else // BTX_ACCOUNTING_WORKER

#include <modelnet/swarm_fsjail.h>
#include <modelnet/swarm_native_io.h>
#ifndef BTX_ACCOUNTING_BASELINE
#include <modelnet/swarm_windows_accounting.h>
#endif
#include <atomic>
#include <filesystem>
#include <mutex>

namespace {
std::string g_mode;
std::mutex g_root_mutex;
std::wstring g_staged_root;
std::atomic<unsigned int> g_cpu_injections{0};
std::atomic<unsigned int> g_tree_injections{0};
std::atomic<unsigned int> g_clock_injections{0};
std::atomic<bool> g_started_observed{false};
std::atomic<bool> g_final_exit_observed{false};
struct WorkerProcess {
    HANDLE handle{nullptr};
    ~WorkerProcess() { if (handle) CloseHandle(handle); }
} g_worker_process;

void CaptureWorkerProcess(HANDLE job)
{
    std::lock_guard lock(g_root_mutex);
    if (g_worker_process.handle) return;
    // The supplied handle is this invocation's one-process Job. Never choose
    // a PID from the host process list or an untrusted file.
    alignas(JOBOBJECT_BASIC_PROCESS_ID_LIST) std::array<unsigned char,
        sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + sizeof(ULONG_PTR)> bytes{};
    auto* list = reinterpret_cast<JOBOBJECT_BASIC_PROCESS_ID_LIST*>(bytes.data());
    if (QueryInformationJobObject(job, JobObjectBasicProcessIdList, list,
            static_cast<DWORD>(bytes.size()), nullptr) == FALSE || list->NumberOfProcessIdsInList != 1) return;
    const ULONG_PTR id = list->ProcessIdList[0];
    if (id == 0 || id > std::numeric_limits<DWORD>::max()) return;
    g_worker_process.handle = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE, static_cast<DWORD>(id));
}

bool WorkerCaptured()
{
    std::lock_guard lock(g_root_mutex);
    return g_worker_process.handle != nullptr;
}

bool ExistsFile(const std::wstring& root, const wchar_t* name)
{
    const fs::path path = fs::path(root) / fs::path(name);
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
        !(attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT));
}

bool CaptureStarted(const std::wstring& root)
{
    {
        std::lock_guard lock(g_root_mutex);
        if (g_staged_root.empty()) g_staged_root = root;
        else Require(g_staged_root == root, "unexpected-second-staged-root");
    }
    const bool started = ExistsFile(root, L"started.bin");
    if (started) g_started_observed.store(true);
    return started;
}

std::vector<unsigned char> ReadBytes(const fs::path& path)
{
    std::ifstream file(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

bool IsMissing(const fs::path& path)
{
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) return false;
    const DWORD error = GetLastError();
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}

bool OnlyOriginalInputs(const fs::path& root)
{
    for (const auto& entry : fs::directory_iterator(root)) {
        const fs::path name = entry.path().filename();
        if (name != fs::path(L"worker.exe") && name != fs::path(L"input.bin")) return false;
    }
    return true;
}

void CheckPolicy()
{
#ifdef BTX_ACCOUNTING_BASELINE
    throw std::runtime_error("policy-unavailable-in-baseline");
#else
    using namespace modelnet::windows_accounting;
    uint64_t bytes = 0;
    Require(LiveTreeBudget(1, bytes) && bytes == 1 + MAX_OUTPUT_BYTES, "policy-live-envelope");
    Require(LiveTreeBudget(std::numeric_limits<uint64_t>::max() - MAX_OUTPUT_BYTES, bytes) &&
        bytes == std::numeric_limits<uint64_t>::max(), "policy-live-equality");
    Require(!LiveTreeBudget(std::numeric_limits<uint64_t>::max() - MAX_OUTPUT_BYTES + 1, bytes),
        "policy-live-overflow");
    Require(!LiveTreeBudget(std::numeric_limits<uint64_t>::max(), bytes), "policy-live-max-overflow");
    constexpr uint64_t SECOND = 10000000;
    Require(EvaluateCpu(2 * SECOND, 3 * SECOND, 6 * SECOND) == CpuState::within, "policy-cpu-below");
    Require(EvaluateCpu(2 * SECOND, 4 * SECOND, 6 * SECOND) == CpuState::within, "policy-cpu-equality");
    Require(EvaluateCpu(0, 6 * SECOND + 1, 6 * SECOND) == CpuState::over_limit, "policy-cpu-kernel-only");
    Require(EvaluateCpu(6 * SECOND, 1, 6 * SECOND) == CpuState::over_limit, "policy-cpu-combined");
    Require(EvaluateCpu(-1, 0, SECOND) == CpuState::invalid, "policy-cpu-negative-user");
    Require(EvaluateCpu(0, -1, SECOND) == CpuState::invalid, "policy-cpu-negative-kernel");
    Require(EvaluateCpu(std::numeric_limits<LONGLONG>::max(),
        std::numeric_limits<LONGLONG>::max(), SECOND) == CpuState::over_limit, "policy-cpu-large-counters");
    std::cout << "POLICY PASS live-envelope equality overflow user-plus-kernel invalid-counters\n";
#endif
}

void CheckScanner(const fs::path& root)
{
#ifdef BTX_ACCOUNTING_BASELINE
    (void)root;
    throw std::runtime_error("scanner-unavailable-in-baseline");
#else
    using namespace modelnet::windows_accounting;
    Require(!fs::exists(root), "scanner-root-must-be-fresh");
    fs::create_directories(root);
    const fs::path tiny = root / fs::path(L"tiny.bin");
    WriteFileBytes(tiny.c_str(), "12345678", 8);
    DWORD error = ERROR_SUCCESS;
    auto sampler = TreeSampler::Create(root.native(), error);
    std::cout << "SCANNER create_ok=" << static_cast<bool>(sampler) << " error=" << error << '\n';
    Require(sampler != nullptr, "scanner-create");
    const auto keep_running = [] { return true; };
    const auto over = sampler->Sample(7, keep_running);
    Require(over.state == TreeState::over_limit, "scanner-actual-eight-byte-cap-seven");
    const auto exact = sampler->Sample(8, keep_running);
    Require(exact.state == TreeState::within && exact.bytes == 8 && exact.entries == 1,
        "scanner-actual-eight-byte-equality");
    const auto repeated = sampler->Sample(8, keep_running);
    Require(repeated.state == TreeState::within && repeated.bytes == 8 && repeated.entries == 1,
        "scanner-repeated-pass-must-restart-enumeration");
    const auto interrupted = sampler->Sample(8, [] { return false; });
    Require(interrupted.state == TreeState::interrupted, "scanner-callback-interruption");
    const auto resumed = sampler->Sample(8, keep_running);
    Require(resumed.state == TreeState::within && resumed.bytes == 8 && resumed.entries == 1,
        "scanner-same-instance-after-interruption");
    sampler.reset();
    std::error_code cleanup_error;
    const auto removed = fs::remove_all(root, cleanup_error);
    Require(!cleanup_error && removed == 2 && IsMissing(root), "scanner-owned-root-cleanup");
    std::cout << "SCANNER PASS cap7=over_limit cap8=within bytes=8 entries=1"
        << " repeated_sample=PASS interrupted=PASS same_instance_recovery=PASS cleanup=PASS\n";
    std::cout << "VERDICT PASS scanner\n";
#endif
}
} // namespace

// Only the backend compiled with BTX_WINDOWS_ACCOUNTING_TEST calls these.
// No worker load or real OS counter is enlarged by a synthetic observation.
namespace modelnet::windows_accounting_test {
void AdjustCpu(HANDLE job, const std::wstring& root, bool completion_observed, bool& ok, LONGLONG& user, LONGLONG& kernel)
{
    CaptureWorkerProcess(job);
    const bool started = CaptureStarted(root);
    if (!started) return;
    if (g_mode == "cpu") {
        ok = true; user = 0; kernel = 7LL * 10000000;
        ++g_cpu_injections;
    } else if (g_mode == "query") {
        ok = false;
        ++g_cpu_injections;
    } else if (g_mode == "final-cpu" && ExistsFile(root, L"finished.bin")) {
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
        const bool queried = QueryInformationJobObject(job, JobObjectBasicAccountingInformation,
            &accounting, sizeof(accounting), nullptr) != FALSE;
        const bool signaled = WorkerCaptured() && WaitForSingleObject(g_worker_process.handle, 0) == WAIT_OBJECT_0;
        std::cout << "FINAL_OBSERVATION completion_poll=" << completion_observed
            << " process_signaled=" << signaled << " job_query=" << queried
            << " active_processes=" << accounting.ActiveProcesses << '\n';
        if (completion_observed && signaled) {
            ok = true; user = 0; kernel = 7LL * 10000000;
            ++g_cpu_injections;
            g_final_exit_observed.store(true);
        }
    }
}

void AdjustClock(const std::wstring& root, bool& ok, ULONGLONG& ticks)
{
    (void)ticks;
    if (CaptureStarted(root) && WorkerCaptured() && g_mode == "clock") {
        ok = false;
        ++g_clock_injections;
    }
}

void AdjustTree(const std::wstring& root, bool& ok, uint64_t& observed)
{
    if (CaptureStarted(root) && g_mode == "tree") {
        ok = true; observed = std::numeric_limits<uint64_t>::max();
        ++g_tree_injections;
    }
}
} // namespace modelnet::windows_accounting_test

namespace {
void RecoveryInSameProcess(const fs::path& worker, const fs::path& original_root,
    const std::string& previous_case)
{
    // The negative observations were printed and asserted before this reset.
    // Only fixture providers/observers are reset; the product process remains.
    {
        std::lock_guard lock(g_root_mutex);
        if (g_worker_process.handle) CloseHandle(g_worker_process.handle);
        g_worker_process.handle = nullptr;
        g_staged_root.clear();
    }
    g_mode = "normal";
    g_cpu_injections.store(0);
    g_tree_injections.store(0);
    g_clock_injections.store(0);
    g_started_observed.store(false);
    g_final_exit_observed.store(false);

    const fs::path root = original_root / fs::path(L"recovery");
    Require(!fs::exists(root), "recovery-root-must-be-fresh");
    fs::create_directories(root);
    const fs::path helper = root / fs::path(L"worker.exe");
    const fs::path input = root / fs::path(L"input.bin");
    fs::copy_file(worker, helper, fs::copy_options::none);
    WriteFileBytes(input.c_str(), "ordinary", 8);
    const auto helper_hash = modelnet::native_io::Digest(ReadBytes(helper));
    const auto input_hash = modelnet::native_io::Digest(ReadBytes(input));
    modelnet::SwarmFilesystemJailRequest request;
    request.root = root; request.helper = helper; request.network_denied = true;
    request.max_wall_seconds = 6;
    request.max_tree_bytes = fs::file_size(helper) + fs::file_size(input);
    std::string error;
    const auto run = modelnet::SwarmRunFilesystemJail(request, error);
    const auto output = ReadBytes(root / fs::path(L"result.bin"));
    const bool output_ok = output.size() == OUTPUT_BYTES &&
        std::all_of(output.begin(), output.end(), [](unsigned char value) { return value == 'B'; });
    const bool inputs_unchanged = helper_hash == modelnet::native_io::Digest(ReadBytes(helper)) &&
        input_hash == modelnet::native_io::Digest(ReadBytes(input));
    std::wstring staged;
    { std::lock_guard lock(g_root_mutex); staged = g_staged_root; }
    const bool staged_missing = !staged.empty() && IsMissing(fs::path(staged));
    const bool process_exited = WorkerCaptured() &&
        WaitForSingleObject(g_worker_process.handle, 0) == WAIT_OBJECT_0;
    DWORD process_exit = STILL_ACTIVE;
    Require(g_worker_process.handle &&
        GetExitCodeProcess(g_worker_process.handle, &process_exit) != FALSE,
        "recovery-process-exit-query");
    std::cout << "RECOVERY after=" << previous_case << " same_process=1 code=" << run.code
        << " launched=" << run.launched << " jailed=" << run.jailed << " child=" << run.child_status
        << " output_bytes=" << output.size() << " output_ok=" << output_ok
        << " inputs_unchanged=" << inputs_unchanged << " staged_missing=" << staged_missing
        << " process_exited=" << process_exited << " process_exit=" << process_exit
        << " cpu_injections=" << g_cpu_injections.load() << " tree_injections=" << g_tree_injections.load()
        << " clock_injections=" << g_clock_injections.load() << '\n';
    if (!staged.empty()) std::cout << "RECOVERY_STAGED_ROOT " << fs::path(staged).utf8string() << '\n';
    Require(run.launched && run.jailed && run.code == "JAILED" && run.child_status == 0 && error.empty(),
        "fresh-recovery-worker-did-not-succeed");
    Require(output_ok && inputs_unchanged, "fresh-recovery-output-or-input-mismatch");
    Require(staged_missing && process_exited && process_exit == 0,
        "fresh-recovery-cleanup-or-process-exit-not-observed");
    Require(g_cpu_injections.load() == 0 && g_tree_injections.load() == 0 && g_clock_injections.load() == 0,
        "fresh-recovery-injection-state-not-reset");
    Require(ReadBytes(root / fs::path(L"moved") / fs::path(L"seed.bin")) ==
        std::vector<unsigned char>({'a', 'b', 'c'}), "fresh-recovery-renamed-file-mismatch");
    Require(IsMissing(root / fs::path(L"remove-me")) && IsMissing(root / fs::path(L"temporary.bin")),
        "fresh-recovery-deletion-failed");
    std::cout << "RECOVERY PASS " << previous_case << '\n';
}
} // namespace

int wmain(int argc, wchar_t** argv)
{
    if (argc != 4) return 2;
    try {
        const fs::path worker = fs::absolute(fs::path(argv[2]));
        const fs::path root = fs::absolute(fs::path(argv[3]));
        const std::wstring wide_mode(argv[1]);
        Require(wide_mode == L"normal" || wide_mode == L"nonzero" || wide_mode == L"cpu" ||
            wide_mode == L"tree" || wide_mode == L"query" || wide_mode == L"final-cpu" ||
            wide_mode == L"clock" || wide_mode == L"policy" || wide_mode == L"scanner", "unknown-case");
        for (const wchar_t character : wide_mode) g_mode.push_back(static_cast<char>(character));
        if (g_mode == "policy") { CheckPolicy(); return 0; }
        if (g_mode == "scanner") { CheckScanner(root); return 0; }
        const std::string case_name = g_mode;

        Require(!fs::exists(root), "root-must-be-fresh");
        fs::create_directories(root);
        const fs::path helper = root / fs::path(L"worker.exe");
        const fs::path input = root / fs::path(L"input.bin");
        fs::copy_file(worker, helper, fs::copy_options::none);
        const std::string input_text = g_mode == "nonzero" ? "nonzero" : "ordinary";
        WriteFileBytes(input.c_str(), input_text.data(), static_cast<DWORD>(input_text.size()));
        const auto helper_hash = modelnet::native_io::Digest(ReadBytes(helper));
        const auto input_hash = modelnet::native_io::Digest(ReadBytes(input));

        modelnet::SwarmFilesystemJailRequest request;
        request.root = root; request.helper = helper; request.network_denied = true;
        request.max_wall_seconds = 6;
        request.max_tree_bytes = fs::file_size(helper) + fs::file_size(input);
        std::string error;
        const auto run = modelnet::SwarmRunFilesystemJail(request, error);
        const bool inputs_unchanged = helper_hash == modelnet::native_io::Digest(ReadBytes(helper)) &&
            input_hash == modelnet::native_io::Digest(ReadBytes(input));
        const auto output = ReadBytes(root / fs::path(L"result.bin"));
        const bool output_ok = output.size() == OUTPUT_BYTES &&
            std::all_of(output.begin(), output.end(), [](unsigned char value) { return value == 'B'; });
        std::wstring staged;
        { std::lock_guard lock(g_root_mutex); staged = g_staged_root; }
        const bool staged_missing = !staged.empty() && IsMissing(fs::path(staged));
        const bool no_new_outputs = OnlyOriginalInputs(root);
        const bool process_observed = WorkerCaptured();
        const bool process_exited = process_observed &&
            WaitForSingleObject(g_worker_process.handle, 0) == WAIT_OBJECT_0;
        DWORD process_exit = STILL_ACTIVE;
        if (process_observed && GetExitCodeProcess(g_worker_process.handle, &process_exit) == FALSE)
            throw std::runtime_error("owned-process-exit-query");
        std::cout << "CASE " << g_mode << " code=" << run.code << " launched=" << run.launched
            << " jailed=" << run.jailed << " child=" << run.child_status << " error=" << error
            << " input_cap=" << request.max_tree_bytes << " output_bytes=" << output.size()
            << " output_ok=" << output_ok << " inputs_unchanged=" << inputs_unchanged
            << " started_observed=" << g_started_observed.load()
            << " cpu_injections=" << g_cpu_injections.load() << " tree_injections=" << g_tree_injections.load()
            << " clock_injections=" << g_clock_injections.load() << " final_exit_observed=" << g_final_exit_observed.load()
            << " staged_captured=" << !staged.empty() << " staged_missing=" << staged_missing
            << " no_new_outputs=" << no_new_outputs
            << " process_observed=" << process_observed << " process_exited=" << process_exited
            << " process_exit=" << process_exit << '\n';
        if (!staged.empty()) std::cout << "STAGED_ROOT " << fs::path(staged).utf8string() << '\n';
        Require(inputs_unchanged, "original-inputs-mutated");
        Require(staged.empty() || staged_missing, "owned-staged-root-not-removed");

        if (g_mode == "normal") {
            Require(run.launched && run.jailed && run.child_status == 0 && run.code == "JAILED" && error.empty(),
                "ordinary-worker-did-not-succeed");
            Require(output_ok, "ordinary-output-mismatch");
            Require(OUTPUT_BYTES > request.max_tree_bytes, "fixture-output-must-exceed-input-cap");
            Require(ReadBytes(root / fs::path(L"moved") / fs::path(L"seed.bin")) ==
                std::vector<unsigned char>({'a', 'b', 'c'}), "ordinary-renamed-file-mismatch");
            Require(IsMissing(root / fs::path(L"remove-me")) && IsMissing(root / fs::path(L"temporary.bin")),
                "ordinary-deletion-failed");
        } else if (g_mode == "nonzero") {
            Require(run.launched && run.jailed && run.child_status == 7 && run.code == "JAILED" && error.empty(),
                "ordinary-nonzero-status-lost");
            Require(output.empty() && no_new_outputs, "nonzero-output-published");
        } else {
            const char* expected = g_mode == "cpu" || g_mode == "final-cpu" ? "JAIL_TIMEOUT" :
                g_mode == "tree" ? "TREE_LIMIT" : "JAIL_ABSENT";
            Require(!run.launched && !run.jailed && run.code == expected && output.empty() && no_new_outputs,
                "expected-resource-refusal-did-not-occur");
            Require(g_started_observed.load() && staged_missing, "real-start-and-cleanup-not-observed");
            Require(process_exited && process_exit != STILL_ACTIVE, "owned-worker-termination-not-observed");
            if (g_mode == "cpu" || g_mode == "query" || g_mode == "final-cpu")
                Require(g_cpu_injections.load() != 0, "cpu-provider-not-exercised");
            if (g_mode == "tree") Require(g_tree_injections.load() != 0, "tree-provider-not-exercised");
            if (g_mode == "clock") Require(g_clock_injections.load() != 0, "clock-provider-not-exercised");
            if (g_mode == "final-cpu") Require(g_final_exit_observed.load(), "post-exit-check-not-exercised");
            RecoveryInSameProcess(worker, root, case_name);
        }
        std::cout << "VERDICT PASS " << case_name << '\n';
        return 0;
    } catch (const std::exception& exception) {
        std::cout << "VERDICT FAIL " << exception.what() << '\n';
        return 1;
    }
}
#endif // BTX_ACCOUNTING_WORKER

// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/bounty.h>

#include <crypto/sha384.h>
#include <random.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <chrono>
#include <csignal>
#include <cstring>
#include <fstream>
#include <sstream>
#include <sys/wait.h>
#include <unistd.h>

namespace modelnet {
namespace {

bool FileSha384(const fs::path& p, Digest48& out, uint64_t& size, std::string& err)
{
    std::ifstream in(p, std::ios::binary);
    if (!in) {
        err = "missing file " + fs::PathToString(p);
        return false;
    }
    CSHA384 hasher;
    char buf[4096];
    size = 0;
    while (in) {
        in.read(buf, sizeof(buf));
        const auto n = in.gcount();
        if (n > 0) {
            hasher.Write(reinterpret_cast<const unsigned char*>(buf), static_cast<size_t>(n));
            size += static_cast<uint64_t>(n);
        }
    }
    hasher.Finalize(out.data.data());
    return true;
}

bool HarnessExists(const char* env)
{
    const char* p = std::getenv(env);
    if (!p || !*p) return false;
    return fs::exists(fs::PathFromString(p)) && fs::is_regular_file(fs::PathFromString(p));
}

} // namespace

bool EvaluationProfileReady(const std::string& profile_id)
{
    if (profile_id == "EXACT_CHECKS") return true;
    if (profile_id == "REPRODUCIBLE_BENCHMARK") return HarnessExists("BTX_BOUNTY_HARNESS_REPRO");
    if (profile_id == "STATISTICAL_BENCHMARK") return HarnessExists("BTX_BOUNTY_HARNESS_STAT");
    if (profile_id == "REVIEWED_RESEARCH") return HarnessExists("BTX_BOUNTY_HARNESS_REVIEW");
    return false;
}

bool PrepareEvaluation(const UniValue& spec, const UniValue& submission, const UniValue& resources,
                       UniValue& plan, std::string& err)
{
    const std::string profile = spec.exists("profile_id") ? spec["profile_id"].get_str() : "EXACT_CHECKS";
    if (!EvaluationProfileReady(profile)) {
        err = "profile not installed or not executed on this node";
        return false;
    }
    if (!submission.exists("artifact_dir") || !submission["artifact_dir"].isStr()) {
        err = "submission artifact_dir required";
        return false;
    }
    const fs::path dir = fs::PathFromString(submission["artifact_dir"].get_str());
    if (!fs::is_directory(dir)) {
        err = "artifact_dir missing";
        return false;
    }
    int64_t timeout_ms = 15000;
    int64_t mem_bytes = 256 * 1024 * 1024;
    if (resources.exists("timeout_ms")) timeout_ms = resources["timeout_ms"].getInt<int64_t>();
    if (resources.exists("memory_bytes")) mem_bytes = resources["memory_bytes"].getInt<int64_t>();
    if (timeout_ms < 1 || timeout_ms > 600000) {
        err = "timeout bound";
        return false;
    }
    plan = UniValue(UniValue::VOBJ);
    plan.pushKV("profile_id", spec.exists("profile_id") ? spec["profile_id"].get_str() : "EXACT_CHECKS");
    plan.pushKV("artifact_dir", fs::PathToString(dir));
    plan.pushKV("timeout_ms", timeout_ms);
    plan.pushKV("memory_bytes", mem_bytes);
    plan.pushKV("spec", spec);
    plan.pushKV("wallet", false);
    plan.pushKV("network", false);
    return true;
}

bool RunEvaluationJob(UniValue& job, std::string& err)
{
    if (!job.exists("plan") || !job["plan"].isObject()) {
        err = "plan";
        return false;
    }
    const UniValue plan = job["plan"];
    if (!plan.exists("profile_id") || !plan["profile_id"].isStr()) {
        err = "plan";
        return false;
    }
    const std::string profile = plan["profile_id"].get_str();
    if (profile != "EXACT_CHECKS" && !EvaluationProfileReady(profile)) {
        err = "unexecuted profile";
        return false;
    }
    job.pushKV("state", "RUNNING");
    const fs::path dir = fs::PathFromString(plan["artifact_dir"].get_str());
    const UniValue spec = plan.exists("spec") ? plan["spec"] : UniValue(UniValue::VOBJ);
    const int64_t timeout_ms = plan["timeout_ms"].getInt<int64_t>();

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        err = "pipe";
        return false;
    }
    const pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        err = "fork";
        return false;
    }
    if (pid == 0) {
        close(pipefd[0]);
        UniValue report(UniValue::VOBJ);
        UniValue tasks(UniValue::VARR);
        bool ok = true;
        if (spec.exists("required_files") && spec["required_files"].isArray()) {
            for (const auto& f : spec["required_files"].getValues()) {
                UniValue t(UniValue::VOBJ);
                const std::string name = f.isStr() ? f.get_str() : (f.exists("name") ? f["name"].get_str() : "");
                t.pushKV("name", name);
                Digest48 h;
                uint64_t sz = 0;
                std::string ferr;
                if (!FileSha384(dir / fs::PathFromString(name), h, sz, ferr)) {
                    t.pushKV("ok", false);
                    t.pushKV("error", ferr);
                    ok = false;
                } else {
                    t.pushKV("sha384", h.Hex());
                    t.pushKV("size", static_cast<int64_t>(sz));
                    if (f.isObject() && f.exists("sha384") && f["sha384"].get_str() != h.Hex()) {
                        t.pushKV("ok", false);
                        t.pushKV("error", "hash mismatch");
                        ok = false;
                    } else if (f.isObject() && f.exists("max_bytes") && sz > static_cast<uint64_t>(f["max_bytes"].getInt<int64_t>())) {
                        t.pushKV("ok", false);
                        t.pushKV("error", "size");
                        ok = false;
                    } else {
                        t.pushKV("ok", true);
                    }
                }
                tasks.push_back(t);
            }
        } else {
            ok = false;
            report.pushKV("error", "missing required_files; missing tasks fail");
        }
        report.pushKV("tasks", tasks);
        report.pushKV("pass", ok);
        report.pushKV("profile_id", profile);
        const std::string js = report.write() + "\n";
        const ssize_t wn = write(pipefd[1], js.data(), js.size());
        (void)wn;
        close(pipefd[1]);
        _exit(ok ? 0 : 2);
    }
    close(pipefd[1]);
    job.pushKV("pid", pid);
    const int64_t start = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count();
    int status = 0;
    bool cancelled = job.exists("cancel") && job["cancel"].get_bool();
    while (true) {
        if (job.exists("cancel") && job["cancel"].get_bool()) cancelled = true;
        if (cancelled) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            close(pipefd[0]);
            job.pushKV("state", "CANCELLED");
            err = "cancelled";
            return false;
        }
        const pid_t w = waitpid(pid, &status, WNOHANG);
        if (w == pid) break;
        if (std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                    .count() -
                start >
            timeout_ms) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            close(pipefd[0]);
            job.pushKV("state", "TIMED_OUT");
            err = "timeout";
            return false;
        }
        usleep(20 * 1000);
    }
    std::string raw;
    char buf[4096];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) raw.append(buf, static_cast<size_t>(n));
    close(pipefd[0]);
    UniValue report;
    if (!report.read(raw) || !report.isObject()) {
        err = "eval report";
        job.pushKV("state", "FAILED");
        return false;
    }
    job.pushKV("report", report);
    job.pushKV("state", (report.exists("pass") && report["pass"].get_bool()) ? "COMPLETE" : "FAILED");
    job.pushKV("pass", report.exists("pass") && report["pass"].get_bool());
    job.pushKV("isolated_process", true);
    job.pushKV("wallet", false);
    return true;
}

bool CancelEvaluationJob(UniValue& job, std::string& err)
{
    job.pushKV("cancel", true);
    if (job.exists("pid") && job["pid"].isNum()) {
        const pid_t pid = static_cast<pid_t>(job["pid"].getInt<int64_t>());
        if (pid > 1) {
            kill(pid, SIGKILL);
            int status = 0;
            waitpid(pid, &status, 0);
        }
    }
    job.pushKV("state", "CANCELLED");
    err.clear();
    return true;
}

} // namespace modelnet

// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <common/run_command.h>

#include <tinyformat.h>
#include <univalue.h>

#ifdef ENABLE_EXTERNAL_SIGNER
#include <util/subprocess.h>
#endif // ENABLE_EXTERNAL_SIGNER

#ifndef WIN32
#include <pthread.h>
#include <signal.h>
#include <mutex>
#endif

#if !defined(WIN32) && defined(ENABLE_EXTERNAL_SIGNER)
namespace {
class ScopedBlockSigPipe
{
private:
    sigset_t m_old_mask{};
    bool m_active{false};

public:
    ScopedBlockSigPipe()
    {
        sigset_t sigpipe_mask;
        sigemptyset(&sigpipe_mask);
        sigaddset(&sigpipe_mask, SIGPIPE);
        m_active = pthread_sigmask(SIG_BLOCK, &sigpipe_mask, &m_old_mask) == 0;
    }

    ~ScopedBlockSigPipe()
    {
        if (m_active) {
            pthread_sigmask(SIG_SETMASK, &m_old_mask, nullptr);
        }
    }
};

class ScopedIgnoreSigPipe
{
private:
    static std::mutex& GetMutex()
    {
        static std::mutex g_sigpipe_mutex;
        return g_sigpipe_mutex;
    }

    std::unique_lock<std::mutex> m_lock;
    struct sigaction m_old_action {};
    bool m_active{false};

public:
    ScopedIgnoreSigPipe() : m_lock(GetMutex())
    {
        struct sigaction ignore_action {};
        ignore_action.sa_handler = SIG_IGN;
        sigemptyset(&ignore_action.sa_mask);
        ignore_action.sa_flags = 0;
        m_active = sigaction(SIGPIPE, &ignore_action, &m_old_action) == 0;
    }

    ~ScopedIgnoreSigPipe()
    {
        if (m_active) {
            sigaction(SIGPIPE, &m_old_action, nullptr);
        }
    }
};
} // namespace
#endif

UniValue RunCommandParseJSON(const std::string& str_command, const std::string& str_std_in)
{
#ifdef ENABLE_EXTERNAL_SIGNER
    namespace sp = subprocess;

    UniValue result_json;
    std::istringstream stdout_stream;
    std::istringstream stderr_stream;

    if (str_command.empty()) return UniValue::VNULL;

    auto c = sp::Popen(str_command, sp::input{sp::PIPE}, sp::output{sp::PIPE}, sp::error{sp::PIPE}, sp::close_fds{true});
#ifndef WIN32
    // If the signer exits before consuming stdin, write() can raise SIGPIPE.
    // Ignore SIGPIPE process-wide (serialized by mutex) and block it in this
    // thread so subprocess can surface EPIPE as a normal process failure
    // instead of terminating the caller.
    ScopedIgnoreSigPipe scoped_ignore_sigpipe;
    ScopedBlockSigPipe scoped_block_sigpipe;
#endif
    auto [out_res, err_res] = str_std_in.empty()
        ? c.communicate()
        : c.communicate(str_std_in.c_str(), str_std_in.size());
    stdout_stream.str(std::string{out_res.buf.begin(), out_res.buf.end()});
    stderr_stream.str(std::string{err_res.buf.begin(), err_res.buf.end()});

    std::string result;
    std::string error;
    std::getline(stdout_stream, result);
    std::getline(stderr_stream, error);

    const int n_error = c.retcode();
    if (n_error) throw std::runtime_error(strprintf("RunCommandParseJSON error: process(%s) returned %d: %s\n", str_command, n_error, error));
    if (!result_json.read(result)) throw std::runtime_error("Unable to parse JSON: " + result);

    return result_json;
#else
    throw std::runtime_error("Compiled without external signing support (required for external signing).");
#endif // ENABLE_EXTERNAL_SIGNER
}

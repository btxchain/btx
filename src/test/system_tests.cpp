// Copyright (c) 2019-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//

#include <bitcoin-build-config.h> // IWYU pragma: keep
#include <test/util/setup_common.h>
#include <common/run_command.h>
#include <univalue.h>

#ifdef ENABLE_EXTERNAL_SIGNER
#include <util/subprocess.h>
#endif // ENABLE_EXTERNAL_SIGNER

#ifndef WIN32
#include <array>

#include <fcntl.h>
#include <unistd.h>
#endif

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(system_tests, BasicTestingSetup)

#ifdef ENABLE_EXTERNAL_SIGNER

BOOST_AUTO_TEST_CASE(run_command)
{
    {
        const UniValue result = RunCommandParseJSON("");
        BOOST_CHECK(result.isNull());
    }
    {
#ifdef WIN32
        const UniValue result = RunCommandParseJSON("cmd.exe /c echo {\"success\": true}");
#else
        const UniValue result = RunCommandParseJSON("echo {\"success\": true}");
#endif
        BOOST_CHECK(result.isObject());
        const UniValue& success = result.find_value("success");
        BOOST_CHECK(!success.isNull());
        BOOST_CHECK_EQUAL(success.get_bool(), true);
    }
    {
        // An invalid command is handled by cpp-subprocess
#ifdef WIN32
        const std::string expected{"CreateProcess failed: "};
#else
        const std::string expected{"execve failed: "};
#endif
        BOOST_CHECK_EXCEPTION(RunCommandParseJSON("invalid_command"), subprocess::CalledProcessError, HasReason(expected));
    }
    {
        // Return non-zero exit code, no output to stderr
#ifdef WIN32
        const std::string command{"cmd.exe /c exit 1"};
#else
        const std::string command{"false"};
#endif
        BOOST_CHECK_EXCEPTION(RunCommandParseJSON(command), std::runtime_error, [&](const std::runtime_error& e) {
            const std::string what{e.what()};
            BOOST_CHECK(what.find(strprintf("RunCommandParseJSON error: process(%s) returned 1: \n", command)) != std::string::npos);
            return true;
        });
    }
    {
        // Return non-zero exit code, with error message for stderr
#ifdef WIN32
        const std::string command{"cmd.exe /c \"echo err 1>&2 && exit 1\""};
#else
        const std::string command{"sh -c 'echo err 1>&2 && false'"};
#endif
        const std::string expected{"err"};
        BOOST_CHECK_EXCEPTION(RunCommandParseJSON(command), std::runtime_error, [&](const std::runtime_error& e) {
            const std::string what(e.what());
            BOOST_CHECK(what.find(strprintf("RunCommandParseJSON error: process(%s) returned", command)) != std::string::npos);
            BOOST_CHECK(what.find(expected) != std::string::npos);
            return true;
        });
    }
    {
        // Unable to parse JSON
#ifdef WIN32
        const std::string command{"cmd.exe /c echo {"};
#else
        const std::string command{"echo {"};
#endif
        BOOST_CHECK_EXCEPTION(RunCommandParseJSON(command), std::runtime_error, HasReason("Unable to parse JSON: {"));
    }
#ifndef WIN32
    {
        // Test stdin
        const UniValue result = RunCommandParseJSON("cat", "{\"success\": true}");
        BOOST_CHECK(result.isObject());
        const UniValue& success = result.find_value("success");
        BOOST_CHECK(!success.isNull());
        BOOST_CHECK_EQUAL(success.get_bool(), true);
    }
    {
        // If the child exits before consuming stdin, do not terminate the
        // caller with SIGPIPE; surface a regular runtime error instead.
        const std::string command{"false"};
        BOOST_CHECK_EXCEPTION(RunCommandParseJSON(command, "{\"success\": true}"), std::runtime_error, [&](const std::runtime_error& e) {
            const std::string what{e.what()};
            BOOST_CHECK(what.find(strprintf("RunCommandParseJSON error: process(%s) returned 1: \n", command)) != std::string::npos);
            return true;
        });
    }
#endif
}

#ifndef WIN32
BOOST_AUTO_TEST_CASE(subprocess_cleanup_closes_parent_fds_once)
{
    // When the child cannot exec, Popen calls cleanup_fds() and the streams
    // are destroyed afterwards. The parent pipe ends are owned by FILE*s after
    // setup_comm_channels(), so each must be closed exactly once. Otherwise a
    // descriptor number reused in between (for example by another thread) is
    // closed as well.
    int in[2], out[2], err[2];
    BOOST_REQUIRE_EQUAL(pipe(in), 0);
    BOOST_REQUIRE_EQUAL(pipe(out), 0);
    BOOST_REQUIRE_EQUAL(pipe(err), 0);
    const std::array<int, 3> parent_ends{in[1], out[0], err[0]};
    {
        subprocess::detail::Streams streams;
        streams.read_from_parent_ = in[0];
        streams.write_to_child_ = in[1];
        streams.read_from_child_ = out[0];
        streams.write_to_parent_ = out[1];
        streams.err_read_ = err[0];
        streams.err_write_ = err[1];
        streams.setup_comm_channels();
        streams.close_child_fds();
        streams.cleanup_fds();

        // Reuse each parent descriptor number before the streams go away.
        for (const int fd : parent_ends) {
            const int other{open("/dev/null", O_RDONLY)};
            BOOST_REQUIRE(other != -1);
            if (other != fd) {
                BOOST_REQUIRE_EQUAL(dup2(other, fd), fd);
                BOOST_REQUIRE_EQUAL(close(other), 0);
            }
        }
    }
    for (const int fd : parent_ends) {
        BOOST_CHECK_MESSAGE(fcntl(fd, F_GETFD) != -1, "descriptor " << fd << " was closed twice");
        close(fd);
    }
}
#endif // WIN32
#endif // ENABLE_EXTERNAL_SIGNER

BOOST_AUTO_TEST_SUITE_END()

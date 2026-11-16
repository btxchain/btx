// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/security_v2/artifacts.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#ifndef WIN32
#include <pthread.h>
#endif

#include <exception>
#include <filesystem>
#include <fstream>
#include <string>

namespace {
// SHA-384 of "btx".
const std::string BTX_SHA384{"77eb09f871f9381f89b950e444188497a656bb1eb92cd11f21282b8793eeae0cb17f4d203bb357f54b879f9dfb5dfd4c"};

std::filesystem::path WriteArtifact(const fs::path& root)
{
    // The artifact checks refuse symlinked path components, so resolve /var -> /private/var.
    const std::filesystem::path file{std::filesystem::canonical(root) / "artifact.bin"};
    std::ofstream out{file, std::ios::binary};
    out << "btx";
    return file;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(modelnet_security_artifacts_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(file_digest_hashes_a_plain_file)
{
    const auto file{WriteArtifact(m_path_root)};
    BOOST_CHECK_EQUAL(modelnet::security::FileDigest(file, 3), BTX_SHA384);
}

#ifndef WIN32
BOOST_AUTO_TEST_CASE(file_digest_fits_a_small_thread_stack)
{
    // btx-guardd hashes resident artifacts (FileDigest, VerifyResident, ResidentFrame) on
    // its worker and maintenance threads. On macOS a non-main thread gets only a 512 KiB
    // stack by default, so the 1 MiB read buffer must not live on the stack. Hash one small
    // file on a 512 KiB stack and require it to complete rather than overflow and crash.
    struct Ctx { std::filesystem::path file; std::string digest; std::string err; };
    Ctx ctx{WriteArtifact(m_path_root), {}, {}};
    pthread_attr_t attr;
    BOOST_REQUIRE_EQUAL(pthread_attr_init(&attr), 0);
    BOOST_REQUIRE_EQUAL(pthread_attr_setstacksize(&attr, 512 * 1024), 0);
    size_t stack_size{0};
    BOOST_REQUIRE_EQUAL(pthread_attr_getstacksize(&attr, &stack_size), 0);
    BOOST_REQUIRE_EQUAL(stack_size, 512U * 1024U);
    pthread_t thread;
    auto entry = [](void* arg) -> void* {
        auto* c = static_cast<Ctx*>(arg);
        try {
            c->digest = modelnet::security::FileDigest(c->file, 3);
        } catch (const std::exception& e) {
            c->err = e.what();
        }
        return nullptr;
    };
    BOOST_REQUIRE_EQUAL(pthread_create(&thread, &attr, entry, &ctx), 0);
    BOOST_REQUIRE_EQUAL(pthread_join(thread, nullptr), 0);
    pthread_attr_destroy(&attr);
    BOOST_CHECK_EQUAL(ctx.err, "");
    BOOST_CHECK_EQUAL(ctx.digest, BTX_SHA384);
}
#endif

BOOST_AUTO_TEST_SUITE_END()

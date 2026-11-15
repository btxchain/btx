// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_TEST_UTIL_ENVIRONMENT_H
#define BITCOIN_TEST_UTIL_ENVIRONMENT_H

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <optional>
#include <string>

namespace test {

// Return the platform API result: zero is success on both platforms.
inline int SetEnv(const char* name, const char* value)
{
#if defined(_WIN32)
    return _putenv_s(name, value);
#else
    return setenv(name, value, 1);
#endif
}

inline int UnsetEnv(const char* name)
{
#if defined(_WIN32)
    return _putenv_s(name, "");
#else
    return unsetenv(name);
#endif
}

// Environment variables are process-global; callers must coordinate mutations.
class ScopedEnvVar
{
public:
    explicit ScopedEnvVar(const char* name) : m_name(name)
    {
        if (const char* current = std::getenv(name)) {
            m_original = current;
        }
    }

    ScopedEnvVar(const char* name, const char* value) : ScopedEnvVar(name)
    {
        Set(value);
    }

    ScopedEnvVar(const ScopedEnvVar&) = delete;
    ScopedEnvVar& operator=(const ScopedEnvVar&) = delete;

    ~ScopedEnvVar() noexcept
    {
        // Report restoration errors without aborting stack unwinding.
        const int result = m_original ? SetEnv(m_name.c_str(), m_original->c_str())
                                      : UnsetEnv(m_name.c_str());
        BOOST_CHECK_EQUAL(result, 0);
    }

    void Set(const char* value)
    {
        const int result = value != nullptr ? SetEnv(m_name.c_str(), value)
                                           : UnsetEnv(m_name.c_str());
        BOOST_REQUIRE_EQUAL(result, 0);
    }

private:
    const std::string m_name;
    std::optional<std::string> m_original;
};

} // namespace test

#endif // BITCOIN_TEST_UTIL_ENVIRONMENT_H

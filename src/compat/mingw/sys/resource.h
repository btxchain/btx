#pragma once
#include <cerrno>

#define RUSAGE_SELF 0

struct rusage {
    long ru_maxrss;
};

inline int getrusage(int, struct rusage* ru)
{
    if (ru != nullptr) ru->ru_maxrss = 0;
    errno = ENOSYS;
    return -1;
}

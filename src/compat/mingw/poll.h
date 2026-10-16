#pragma once
#include <winsock2.h>

inline int poll(struct pollfd* fds, unsigned long nfds, int timeout)
{
    return WSAPoll(fds, nfds, timeout);
}

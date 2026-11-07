/* Copyright (c) 2026 The BTX developers. MIT license. See COPYING.
 * This executable is a native escape/operation probe, not a shell script.
 * Linux builds are static so the filesystem jail needs no host libraries. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

int main(void)
{
    /* A fake "sandbox unavailable" path cannot produce these output bytes. */
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd >= 0) { close(fd); return 10; }
    if (getenv("BTX_NATIVE_SECRET_SENTINEL") != NULL) return 11;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(9);
        dest.sin_addr.s_addr = htonl(0xc0000201U); /* TEST-NET-1, no bytes sent */
        if (connect(sock, (struct sockaddr*)&dest, sizeof(dest)) == 0) { close(sock); return 12; }
        close(sock);
    }
    fd = open("probe-result.txt", O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return 13;
    const char result[] = "filesystem-denied network-denied environment-clean native-executed\n";
    if (write(fd, result, sizeof(result) - 1) != (ssize_t)(sizeof(result) - 1)) { close(fd); return 14; }
    if (fsync(fd) != 0 || close(fd) != 0) return 15;
    return 0;
}

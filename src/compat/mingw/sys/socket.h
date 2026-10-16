#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#ifndef SHUT_RD
#define SHUT_RD SD_RECEIVE
#define SHUT_WR SD_SEND
#define SHUT_RDWR SD_BOTH
#endif

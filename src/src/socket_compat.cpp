#include "socket_compat.h"
#include <cstdio>
#include <cstring>
#include <cerrno>

#ifdef _WIN32
#pragma comment(lib, "Ws2_32.lib")
#endif

void socket_startup() {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
}

void socket_cleanup() {
#ifdef _WIN32
    WSACleanup();
#endif
}

// ---------- UDP (existing) ----------
native_socket_t socket_udp_open_and_bind(int port) {
    native_socket_t s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#ifdef _WIN32
    if (s == INVALID_SOCKET) return -1;
#else
    if (s < 0) return -1;
#endif

    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    int r = bind(s, (struct sockaddr*)&addr, sizeof(addr));
    if (r != 0) {
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
        return -1;
    }
    return s;
}

int send_udp_to(native_socket_t fd, uint32_t ipv4_nbo, uint16_t port, const void* data, int len) {
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ipv4_nbo;
    dest.sin_port = htons(port);

    int sent = sendto(fd, (const char*)data, len, 0, (struct sockaddr*)&dest, sizeof(dest));
#ifdef _WIN32
    if (sent == SOCKET_ERROR) return -1;
#else
    if (sent < 0) return -1;
#endif
    return sent;
}

int recv_udp_with_timeout(native_socket_t fd, void* buf, int maxlen, int timeout_us) {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);
    struct timeval tv;
    tv.tv_sec = timeout_us / 1000000;
    tv.tv_usec = timeout_us % 1000000;

    int nfds = (int)(fd + 1);
    int r = select(nfds, &readfds, nullptr, nullptr, &tv);
    if (r <= 0) return -1;
    struct sockaddr_in src;
    socklen_t slen = sizeof(src);
    int recvd = recvfrom(fd, (char*)buf, maxlen, 0, (struct sockaddr*)&src, &slen);
    if (recvd < 0) return -1;
    return recvd;
}

//int recv_udp_from(native_socket_t fd, void* buf, int maxlen, int timeout_us, uint32_t* out_ip_nbo, uint16_t* out_port) {
//    if (fd == (native_socket_t)-1) return -1;
//    fd_set readfds;
//    FD_ZERO(&readfds);
//    FD_SET(fd, &readfds);
//    struct timeval tv;
//    tv.tv_sec = timeout_us / 1000000;
//    tv.tv_usec = timeout_us % 1000000;
//
//    int nfds = (int)(fd + 1);
//    int sel = select(nfds, &readfds, nullptr, nullptr, (timeout_us >= 0) ? &tv : nullptr);
//    if (sel <= 0) return -1; // timeout or error
//
//    struct sockaddr_in src;
//    socklen_t slen = sizeof(src);
//    int recvd = recvfrom(fd, (char*)buf, maxlen, 0, (struct sockaddr*)&src, &slen);
//    if (recvd < 0) return -1;
//    if (out_ip_nbo) *out_ip_nbo = src.sin_addr.s_addr;
//    if (out_port) *out_port = ntohs(src.sin_port);
//    return recvd;
//}

// new: recv_udp_from
int recv_udp_from(native_socket_t fd, void* buf, int maxlen, int timeout_us, uint32_t* out_ip_nbo, uint16_t* out_port) {
    if (fd == (native_socket_t)-1) return -1;
    if (!buf || maxlen <= 0) return -1;

#ifdef _WIN32
    // On Windows, native_socket_t likely is SOCKET
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);
    struct timeval tv;
    tv.tv_sec = timeout_us / 1000000;
    tv.tv_usec = timeout_us % 1000000;

    int sel = select((int)fd + 1, &readfds, NULL, NULL, (timeout_us >= 0) ? &tv : NULL);
    if (sel <= 0) return -1;

    struct sockaddr_in src;
    int slen = sizeof(src);
    int recvd = recvfrom(fd, (char*)buf, maxlen, 0, (struct sockaddr*)&src, &slen);
    if (recvd <= 0) return -1;
    if (out_ip_nbo) *out_ip_nbo = src.sin_addr.s_addr;
    if (out_port) *out_port = ntohs(src.sin_port);
    return recvd;
#else
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);
    struct timeval tv;
    tv.tv_sec = timeout_us / 1000000;
    tv.tv_usec = timeout_us % 1000000;

    int nfds = fd + 1;
    struct timeval* tvp = (timeout_us >= 0) ? &tv : NULL;
    int sel = select(nfds, &readfds, NULL, NULL, tvp);
    if (sel <= 0) return -1;

    struct sockaddr_in src;
    socklen_t slen = sizeof(src);
    int recvd = recvfrom(fd, (char*)buf, (size_t)maxlen, 0, (struct sockaddr*)&src, &slen);
    if (recvd <= 0) return -1;
    if (out_ip_nbo) *out_ip_nbo = src.sin_addr.s_addr;
    if (out_port) *out_port = ntohs(src.sin_port);
    return recvd;
#endif
}

void closesocket_native(native_socket_t fd) {
#ifdef _WIN32
    closesocket(fd);
#else
    close(fd);
#endif
}

// ---------- TCP helpers (new) ----------
native_socket_t socket_tcp_create() {
    native_socket_t s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#ifdef _WIN32
    if (s == INVALID_SOCKET) return -1;
#else
    if (s < 0) return -1;
#endif
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
    return s;
}

int socket_tcp_bind(native_socket_t s, uint16_t port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    int r = bind(s, (struct sockaddr*)&addr, sizeof(addr));
    return (r == 0) ? 0 : -1;
}

int socket_tcp_listen(native_socket_t s, int backlog) {
    int r = listen(s, backlog);
    return (r == 0) ? 0 : -1;
}

native_socket_t socket_tcp_accept(native_socket_t s, uint32_t* out_ip_nbo, uint16_t* out_port) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    native_socket_t ns = accept(s, (struct sockaddr*)&addr, &len);
#ifdef _WIN32
    if (ns == INVALID_SOCKET) return -1;
#else
    if (ns < 0) return -1;
#endif
    if (out_ip_nbo) *out_ip_nbo = addr.sin_addr.s_addr;
    if (out_port) *out_port = ntohs(addr.sin_port);
    return ns;
}

// connect with timeout using non-blocking + select
int socket_tcp_connect(native_socket_t s, uint32_t dest_ip_nbo, uint16_t port, int timeout_ms) {
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = dest_ip_nbo;
    dest.sin_port = htons(port);

    // set non-blocking
#ifdef _WIN32
    unsigned long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);
#else
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);
#endif

    int r = connect(s, (struct sockaddr*)&dest, sizeof(dest));
#ifdef _WIN32
    if (r == 0) {
        unsigned long mode2 = 0;
        ioctlsocket(s, FIONBIO, &mode2);
        return 0;
    }
    int err = WSAGetLastError();
    if (err == WSAEWOULDBLOCK || err == WSAEINPROGRESS) {
        // wait
    }
    else {
        return -1;
    }
#else
    if (r == 0) {
        // connected immediately
        int flags2 = fcntl(s, F_GETFL, 0);
        fcntl(s, F_SETFL, flags2 & ~O_NONBLOCK);
        return 0;
    }
    else {
        if (errno != EINPROGRESS) return -1;
    }
#endif

    // Wait for writable or timeout
    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(s, &wset);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int nfds = (int)(s + 1);
    int sel = select(nfds, nullptr, &wset, nullptr, (timeout_ms >= 0) ? &tv : nullptr);
    if (sel <= 0) return -1;

    // check for socket error
    int so_error = 0;
    socklen_t len = sizeof(so_error);
    getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);
    if (so_error != 0) return -1;

    // restore blocking mode
#ifdef _WIN32
    unsigned long mode3 = 0;
    ioctlsocket(s, FIONBIO, &mode3);
#else
    int flags3 = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags3 & ~O_NONBLOCK);
#endif

    return 0;
}

int socket_send(native_socket_t s, const void* data, int len) {
    int sent = send(s, (const char*)data, len, 0);
#ifdef _WIN32
    if (sent == SOCKET_ERROR) return -1;
#else
    if (sent < 0) return -1;
#endif
    return sent;
}

int socket_recv(native_socket_t s, void* buf, int len, int flags) {
    int r = recv(s, (char*)buf, len, flags);
#ifdef _WIN32
    if (r == SOCKET_ERROR) return -1;
#else
    if (r < 0) return -1;
#endif
    return r;
}

int set_socket_nonblocking(native_socket_t s, int nonblock) {
#ifdef _WIN32
    u_long mode = nonblock ? 1 : 0;
    return ioctlsocket(s, FIONBIO, &mode);
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0) return -1;
    if (nonblock) flags |= O_NONBLOCK;
    else flags &= ~O_NONBLOCK;
    return fcntl(s, F_SETFL, flags);
#endif
}

int socket_set_timeout(native_socket_t s, int which, int timeout_ms) {
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int opt = (which == 0) ? SO_RCVTIMEO : SO_SNDTIMEO;
    setsockopt(s, SOL_SOCKET, opt, (char*)&tv, sizeof(tv));
    return 0;
}

int socket_shutdown_recv(native_socket_t s) {
#ifdef _WIN32
    return shutdown(s, SD_RECEIVE);
#else
    return shutdown(s, SHUT_RD);
#endif
}

int socket_close(native_socket_t s) {
#ifdef _WIN32
    return closesocket(s);
#else
    return close(s);
#endif
}

int socket_errno() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

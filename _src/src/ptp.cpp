// src/ptp.cpp
// PTP (TCP) manager ported from PPSSPP sceNetAdhoc (partial, focused on core PTP functions).
#include "socket_compat.h"
#include "kernel_shim.h"
#include <cstdint>
#include <cstring>
#include <vector>
#include <mutex>
#include <map>
#include <string>
#include <chrono>
#include <algorithm>
#include <cstdio>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

// forward declare global SceNetEtherAddr (from adhoc_core)
struct SceNetEtherAddr { uint8_t data[6]; };

enum PTPState {
    ADHOC_PTP_STATE_CLOSED = 0,
    ADHOC_PTP_STATE_SYN_SENT,
    ADHOC_PTP_STATE_ESTABLISHED
};

struct PtpSlot {
    bool used = false;
    native_socket_t fd = (native_socket_t)-1;
    int lport = 0;
    uint32_t peer_ip_nbo = 0;
    uint16_t peer_port = 0;
    SceNetEtherAddr peer_mac;
    int buffer_size = 0;
    bool nonblocking = false;
    bool isClient = false;
    PTPState state = ADHOC_PTP_STATE_CLOSED;
    int retry_interval_ms = 1000;
    int retry_count = 3;
    int attemptCount = 0;
    double internalLastAttempt = 0.0; // timestamp seconds
};

static const int MAX_PTP = 128;
static PtpSlot g_ptp_slots[MAX_PTP];
static std::mutex g_ptp_lock;

// Helper: find free PTP slot
static int find_free_ptp_slot() {
    for (int i = 0; i < MAX_PTP; ++i) if (!g_ptp_slots[i].used) return i;
    return -1;
}

// Helper: get local port
static int get_socket_local_port(native_socket_t s) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    if (getsockname(s, (struct sockaddr*)&addr, &len) == 0) return ntohs(addr.sin_port);
    return 0;
}

// Open PTP socket (similar args to sceNetAdhocPtpOpen in PPSSPP)
// srcMac: local mac (6 bytes) or nullptr, srcPort: local port (0 for ephemeral), destMac: if non-null then acting as client (we'll try to connect)
// dport: destination port when connecting
int NetAdhocPtp_Open(const SceNetEtherAddr* srcMac, uint16_t srcPort,
    const SceNetEtherAddr* destMac, uint16_t dport,
    int bufsize, int rexmt_int_ms, int rexmt_cnt, int queue, int flag, bool isClient)
{
    std::lock_guard<std::mutex> lk(g_ptp_lock);
    int slot = find_free_ptp_slot();
    if (slot < 0) return -1;

    native_socket_t s = socket_tcp_create();
    if (s == (native_socket_t)-1) return -2;

    // Bind to srcPort if given (0 -> ephemeral)
    if (srcPort != 0) {
        if (socket_tcp_bind(s, srcPort) != 0) {
            socket_close(s);
            return -3;
        }
    }

    // set non-blocking temporarily if we will attempt non-blocking connect behavior later
    set_socket_nonblocking(s, 1);

    // store
    g_ptp_slots[slot].used = true;
    g_ptp_slots[slot].fd = s;
    g_ptp_slots[slot].lport = get_socket_local_port(s);
    g_ptp_slots[slot].buffer_size = bufsize;
    g_ptp_slots[slot].nonblocking = (flag != 0);
    g_ptp_slots[slot].isClient = isClient;
    g_ptp_slots[slot].retry_interval_ms = rexmt_int_ms > 0 ? rexmt_int_ms : 1000;
    g_ptp_slots[slot].retry_count = rexmt_cnt > 0 ? rexmt_cnt : 3;
    g_ptp_slots[slot].attemptCount = 0;
    if (srcMac) memcpy(g_ptp_slots[slot].peer_mac.data, srcMac->data, 6);
    if (destMac) memcpy(g_ptp_slots[slot].peer_mac.data, destMac->data, 6);

    // If destMac provided, try to resolve IP (we assume external resolveMAC helper exists somewhere).
    // We'll try to convert first 4 bytes of destMac to IP (common in our test harness).
    if (destMac) {
        uint32_t ip_nbo = 0;
        memcpy(&ip_nbo, destMac->data, 4); // caller must provide nbo (inet_addr)
        g_ptp_slots[slot].peer_ip_nbo = ip_nbo;
        g_ptp_slots[slot].peer_port = dport;
        // Attempt connect immediately in a non-blocking manner
        int cres = socket_tcp_connect(s, ip_nbo, dport, 0);
        if (cres == 0) {
            // Connected
            g_ptp_slots[slot].state = ADHOC_PTP_STATE_ESTABLISHED;
        }
        else {
            // in progress -> mark SYN_SENT
            g_ptp_slots[slot].state = ADHOC_PTP_STATE_SYN_SENT;
            // keep fd non-blocking for async connect
        }
    }
    else {
        // server/listen mode or unconnected client
        g_ptp_slots[slot].state = ADHOC_PTP_STATE_CLOSED;
    }

    // Return slot id as PSP-style id (slot + 1)
    return slot + 1;
}

// Close PTP
int NetAdhocPtp_Close(int id) {
    std::lock_guard<std::mutex> lk(g_ptp_lock);
    int idx = id - 1;
    if (idx < 0 || idx >= MAX_PTP) return -1;
    if (!g_ptp_slots[idx].used) return -2;
    socket_shutdown_recv(g_ptp_slots[idx].fd);
    socket_close(g_ptp_slots[idx].fd);
    g_ptp_slots[idx] = PtpSlot();
    return 0;
}

// Listen (bind & listen)
int NetAdhocPtp_Listen(int id, uint16_t port, int backlog) {
    std::lock_guard<std::mutex> lk(g_ptp_lock);
    int idx = id - 1;
    if (idx < 0 || idx >= MAX_PTP) return -1;
    if (!g_ptp_slots[idx].used) return -2;
    native_socket_t s = g_ptp_slots[idx].fd;
    // bind to specific port
    if (socket_tcp_bind(s, port) != 0) return -3;
    if (socket_tcp_listen(s, backlog) != 0) return -4;
    // set non-blocking for accept polling
    set_socket_nonblocking(s, 1);
    g_ptp_slots[idx].lport = get_socket_local_port(s);
    return 0;
}

// Accept: blocks until a new connection arrives or returns WOULD_BLOCK equivalent
// returns new socket id (>0) or negative error
int NetAdhocPtp_Accept(int id, SceNetEtherAddr* outPeerMac, uint16_t* outPeerPort, int timeout_ms) {
    int idx = id - 1;
    if (idx < 0 || idx >= MAX_PTP) return -1;
    if (!g_ptp_slots[idx].used) return -2;
    native_socket_t listen_fd = g_ptp_slots[idx].fd;

    // Use select to wait for connection
    fd_set rf;
    FD_ZERO(&rf);
    FD_SET(listen_fd, &rf);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int nfds = (int)(listen_fd + 1);
    int sel = select(nfds, &rf, nullptr, nullptr, (timeout_ms >= 0) ? &tv : nullptr);
    if (sel <= 0) return -3; // timeout or error

    uint32_t ip_nbo = 0;
    uint16_t peer_port = 0;
    native_socket_t ns = socket_tcp_accept(listen_fd, &ip_nbo, &peer_port);
    if (ns == (native_socket_t)-1) return -4;

    // Make accepted socket blocking by default (or follow parent's nonblocking)
    set_socket_nonblocking(ns, 0);

    // Create new slot for accepted socket
    std::lock_guard<std::mutex> lk(g_ptp_lock);
    int newslot = find_free_ptp_slot();
    if (newslot < 0) {
        socket_close(ns);
        return -5;
    }
    g_ptp_slots[newslot].used = true;
    g_ptp_slots[newslot].fd = ns;
    g_ptp_slots[newslot].lport = get_socket_local_port(ns);
    g_ptp_slots[newslot].peer_ip_nbo = ip_nbo;
    g_ptp_slots[newslot].peer_port = peer_port;
    g_ptp_slots[newslot].state = ADHOC_PTP_STATE_ESTABLISHED;

    // Fill peer MAC if caller wants (best-effort: derive from ip -> local mapping)
    if (outPeerPort) *outPeerPort = peer_port;
    if (outPeerMac) {
        // best-effort: first 4 bytes = ip
        memset(outPeerMac->data, 0, 6);
        memcpy(outPeerMac->data, &ip_nbo, 4);
    }

    return newslot + 1;
}

// Connect (blocking or non-blocking)
// If nonblocking flag set on socket, return WOULD_BLOCK (simulate).
int NetAdhocPtp_Connect(int id, int timeout_us, int flag, bool allowForcedConnect) {
    int idx = id - 1;
    if (idx < 0 || idx >= MAX_PTP) return -1;
    std::lock_guard<std::mutex> lk(g_ptp_lock);
    if (!g_ptp_slots[idx].used) return -2;

    PtpSlot& slot = g_ptp_slots[idx];
    if (slot.peer_ip_nbo == 0 || slot.peer_port == 0) return -3;

    // If already established, return success
    if (slot.state == ADHOC_PTP_STATE_ESTABLISHED) return 0;

    // Try connect with timeout (convert microseconds to ms)
    int timeout_ms = (timeout_us <= 0) ? 0 : (timeout_us / 1000);

    // Ensure socket is non-blocking for connect attempt (we may use blocking connect for simplicity)
    set_socket_nonblocking(slot.fd, 1);
    int cres = socket_tcp_connect(slot.fd, slot.peer_ip_nbo, slot.peer_port, timeout_ms);
    if (cres == 0) {
        slot.state = ADHOC_PTP_STATE_ESTABLISHED;
        set_socket_nonblocking(slot.fd, slot.nonblocking ? 1 : 0);
        return 0;
    }
    else {
        // connect in progress or failed
        // if nonblocking requested, return WOULD_BLOCK
        if (slot.nonblocking || flag) {
            return -100 /* WOULD_BLOCK equivalent */;
        }
        // else blocking behaviour: try again repeatedly up to timeout using select
        // Here we implement a fallback: wait on socket writable until timeout
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(slot.fd, &wset);
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        int nfds = (int)(slot.fd + 1);
        int sel = select(nfds, nullptr, &wset, nullptr, (timeout_ms >= 0) ? &tv : nullptr);
        if (sel <= 0) {
            // timeout
            return -2; // timed out
        }
        // check err
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        getsockopt(slot.fd, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);
        if (so_error == 0) {
            slot.state = ADHOC_PTP_STATE_ESTABLISHED;
            set_socket_nonblocking(slot.fd, slot.nonblocking ? 1 : 0);
            return 0;
        }
        else {
            // reconnect/fallback logic: close and recreate socket once (PPSSPP does more)
            socket_close(slot.fd);
            native_socket_t ns = socket_tcp_create();
            if (ns == (native_socket_t)-1) return -3;
            slot.fd = ns;
            set_socket_nonblocking(ns, 1);
            int cres2 = socket_tcp_connect(ns, slot.peer_ip_nbo, slot.peer_port, timeout_ms);
            if (cres2 == 0) {
                slot.state = ADHOC_PTP_STATE_ESTABLISHED;
                set_socket_nonblocking(slot.fd, slot.nonblocking ? 1 : 0);
                return 0;
            }
            else {
                return -4;
            }
        }
    }
}

// Send data over PTP
int NetAdhocPtp_Send(int id, const void* data, int* len_ptr, int timeout_us, int flag) {
    if (!len_ptr || *len_ptr <= 0) return -1;
    int idx = id - 1;
    if (idx < 0 || idx >= MAX_PTP) return -1;
    std::lock_guard<std::mutex> lk(g_ptp_lock);
    if (!g_ptp_slots[idx].used) return -2;
    PtpSlot& slot = g_ptp_slots[idx];
    if (slot.state != ADHOC_PTP_STATE_ESTABLISHED && slot.state != ADHOC_PTP_STATE_SYN_SENT) {
        return -3; // not connected
    }

    int tosend = *len_ptr;
    // if nonblocking and would block, return WOULD_BLOCK
    int sent = socket_send(slot.fd, data, tosend);
    if (sent >= 0) {
        *len_ptr = sent;
        return sent;
    }

    int serr = socket_errno();
#ifdef EAGAIN
    if (serr == EAGAIN || serr == EWOULDBLOCK) {
        if (slot.nonblocking || flag) {
            return -100; // WOULD_BLOCK
        }
        // emulate blocking: wait until writable until timeout
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(slot.fd, &wset);
        struct timeval tv;
        tv.tv_sec = timeout_us / 1000000;
        tv.tv_usec = timeout_us % 1000000;
        int nfds = (int)(slot.fd + 1);
        int sel = select(nfds, nullptr, &wset, nullptr, (timeout_us >= 0) ? &tv : nullptr);
        if (sel <= 0) return -2; // timeout
        sent = socket_send(slot.fd, data, tosend);
        if (sent >= 0) { *len_ptr = sent; return sent; }
        return -3;
    }
#endif
    return -4; // other error
}

// Recv data over PTP
int NetAdhocPtp_Recv(int id, void* buf, int* len_ptr, int timeout_us, int flag) {
    if (!len_ptr || *len_ptr <= 0) return -1;
    int idx = id - 1;
    if (idx < 0 || idx >= MAX_PTP) return -1;
    std::lock_guard<std::mutex> lk(g_ptp_lock);
    if (!g_ptp_slots[idx].used) return -2;
    PtpSlot& slot = g_ptp_slots[idx];
    if (slot.state != ADHOC_PTP_STATE_ESTABLISHED) return -3;

    // Try recv
    int recvd = socket_recv(slot.fd, buf, *len_ptr, 0);
    if (recvd >= 0) { *len_ptr = recvd; return recvd; }

    int serr = socket_errno();
#ifdef EAGAIN
    if (serr == EAGAIN || serr == EWOULDBLOCK) {
        if (slot.nonblocking || flag) {
            return -100; // WOULD_BLOCK
        }
        // emulate blocking with select
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(slot.fd, &rset);
        struct timeval tv;
        tv.tv_sec = timeout_us / 1000000;
        tv.tv_usec = timeout_us % 1000000;
        int nfds = (int)(slot.fd + 1);
        int sel = select(nfds, &rset, nullptr, nullptr, (timeout_us >= 0) ? &tv : nullptr);
        if (sel <= 0) return -2; // timeout
        recvd = socket_recv(slot.fd, buf, *len_ptr, 0);
        if (recvd >= 0) { *len_ptr = recvd; return recvd; }
        return -3;
    }
#endif
    return -4;
}

// Simple flush: ensure all data is sent (no-op for now)
int NetAdhocPtp_Flush(int id, int timeout_ms, int flag) {
    (void)id; (void)timeout_ms; (void)flag;
    // Could call shutdown(SHUT_WR) and wait for close; implement later if needed
    return 0;
}

int NetAdhocGetPtpStat(int id, void* statBuf, int statBufSize) {
    (void)id; (void)statBuf; (void)statBufSize;
    return -1;
}

// Set peer (attach dest MAC -> ip, port to existing ptp slot)
int NetAdhocPtp_SetPeer(int id, const SceNetEtherAddr* destMac, uint16_t port) {
    if (!destMac) return -1;
    int idx = id - 1;
    if (idx < 0 || idx >= MAX_PTP) return -1;
    std::lock_guard<std::mutex> lk(g_ptp_lock);
    if (!g_ptp_slots[idx].used) return -2;
    // Use simple heuristic: first 4 bytes of MAC-like buffer -> ipv4 in network byte order
    uint32_t ip_nbo;
    memcpy(&ip_nbo, destMac->data, 4);
    g_ptp_slots[idx].peer_ip_nbo = ip_nbo;
    g_ptp_slots[idx].peer_port = port;
    return 0;
}


// C wrappers
extern "C" {

    int NetAdhocPtp_Open_Wrap(const SceNetEtherAddr* srcMac, uint16_t srcPort,
        const SceNetEtherAddr* destMac, uint16_t dport,
        int bufsize, int rexmt_int_ms, int rexmt_cnt, int queue, int flag, int isClient) {
        return NetAdhocPtp_Open(srcMac, srcPort, destMac, dport, bufsize, rexmt_int_ms, rexmt_cnt, queue, flag, isClient != 0);
    }
    int NetAdhocPtp_Close_Wrap(int id) { return NetAdhocPtp_Close(id); }
    int NetAdhocPtp_Listen_Wrap(int id, uint16_t port, int backlog) { return NetAdhocPtp_Listen(id, port, backlog); }
    int NetAdhocPtp_Accept_Wrap(int id, SceNetEtherAddr* outMac, uint16_t* outPort, int timeout_ms) { return NetAdhocPtp_Accept(id, outMac, outPort, timeout_ms); }
    int NetAdhocPtp_Connect_Wrap(int id, int timeout_us, int flag) { return NetAdhocPtp_Connect(id, timeout_us, flag, true); }
    int NetAdhocPtp_Send_Wrap(int id, const void* data, int* len, int timeout_us, int flag) { return NetAdhocPtp_Send(id, data, len, timeout_us, flag); }
    int NetAdhocPtp_Recv_Wrap(int id, void* buf, int* len, int timeout_us, int flag) { return NetAdhocPtp_Recv(id, buf, len, timeout_us, flag); }
    int NetAdhocPtp_Flush_Wrap(int id, int timeout_ms, int flag) { return NetAdhocPtp_Flush(id, timeout_ms, flag); }
    int NetAdhocGetPtpStat_Wrap(int id, void* statBuf, int statBufSize) { return NetAdhocGetPtpStat(id, statBuf, statBufSize); }
    int NetAdhocPtp_SetPeer_Wrap(int id, const void* destMac, uint16_t port) {
        return NetAdhocPtp_SetPeer(id, reinterpret_cast<const SceNetEtherAddr*>(destMac), port);
    }

} // extern "C"

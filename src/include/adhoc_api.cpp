#include "ppsspp_adhoc.h"
#include "socket_compat.h"
#include "kernel_shim.h"
#include <mutex>
#include <cstring>
#include <array>

static bool g_inited = false;
static std::mutex g_lock;

struct PDP_Socket {
    native_socket_t fd;
    int port;
    int bufsz;
    bool used;
    uint8_t mac[6];
};

static const int MAX_PDP = 64;
static PDP_Socket g_pdps[MAX_PDP];

static int find_free_pdp() {
    for (int i = 0; i < MAX_PDP; i++) if (!g_pdps[i].used) return i;
    return -1;
}

extern "C" {

    ADHOCPP_API int sceNetAdhocInit() {
        std::lock_guard<std::mutex> lk(g_lock);
        if (g_inited) return 0;
        socket_startup();
        for (int i = 0; i < MAX_PDP; i++) {
            g_pdps[i].used = false;
            g_pdps[i].fd = (native_socket_t)-1;
        }
        g_inited = true;
        LOG("[adhoc] init");
        return 0;
    }

    ADHOCPP_API int sceNetAdhocTerm() {
        std::lock_guard<std::mutex> lk(g_lock);
        if (!g_inited) return 0;
        for (int i = 0; i < MAX_PDP; i++) {
            if (g_pdps[i].used) {
                closesocket_native(g_pdps[i].fd);
                g_pdps[i].used = false;
            }
        }
        socket_cleanup();
        g_inited = false;
        LOG("[adhoc] term");
        return 0;
    }

    ADHOCPP_API int sceNetAdhocPdpCreate(const uint8_t mac[6], int port, int bufferSize, uint32_t flag) {
        if (!g_inited) return -1;
        std::lock_guard<std::mutex> lk(g_lock);
        int slot = find_free_pdp();
        if (slot < 0) return -2;
        native_socket_t fd = socket_udp_open_and_bind(port);
        if (fd == (native_socket_t)-1) return -3;
        g_pdps[slot].fd = fd;
        g_pdps[slot].port = port;
        g_pdps[slot].bufsz = bufferSize;
        g_pdps[slot].used = true;
        if (mac) memcpy(g_pdps[slot].mac, mac, 6);
        else memset(g_pdps[slot].mac, 0, 6);
        LOG("[adhoc] pdp create slot=%d port=%d", slot, port);
        return slot + 1; // PSP-style positive ID
    }

    ADHOCPP_API int sceNetAdhocPdpDelete(int socketId) {
        if (!g_inited) return -1;
        int idx = socketId - 1;
        if (idx < 0 || idx >= MAX_PDP) return -2;
        std::lock_guard<std::mutex> lk(g_lock);
        if (!g_pdps[idx].used) return -3;
        closesocket_native(g_pdps[idx].fd);
        g_pdps[idx].used = false;
        LOG("[adhoc] pdp delete id=%d", socketId);
        return 0;
    }

    // NOTE: For initial phase destMac expected to contain IPv4 in first 4 bytes (network byte order).
    ADHOCPP_API int sceNetAdhocPdpSend(int socketId, const uint8_t destMac[6], uint16_t port, const void* data, int* len, uint32_t flag) {
        if (!g_inited) return -1;
        if (!len || *len <= 0) return -2;
        int idx = socketId - 1;
        if (idx < 0 || idx >= MAX_PDP) return -3;
        if (!g_pdps[idx].used) return -4;
        uint32_t ip_nbo = 0;
        if (destMac) {
            // interpret first 4 bytes as IPv4 (network byte order)
            memcpy(&ip_nbo, destMac, 4);
        }
        else {
            return -5;
        }
        int sent = send_udp_to(g_pdps[idx].fd, ip_nbo, port, data, *len);
        if (sent < 0) return -6;
        *len = sent;
        return sent;
    }

    ADHOCPP_API int sceNetAdhocPdpRecv(int socketId, void* buf, int* len, int timeout_us, uint32_t flag) {
        if (!g_inited) return -1;
        if (!len || *len <= 0) return -2;
        int idx = socketId - 1;
        if (idx < 0 || idx >= MAX_PDP) return -3;
        if (!g_pdps[idx].used) return -4;
        int recvd = recv_udp_with_timeout(g_pdps[idx].fd, buf, *len, timeout_us);
        if (recvd < 0) return -5;
        *len = recvd;
        return recvd;
    }

    ADHOCPP_API int sceNetAdhocGetPdpStat(int socketId, void* statBuf, int statBufSize) {
        (void)socketId; (void)statBuf; (void)statBufSize;
        return -1; // not implemented yet
    }

    // Stub implementations for other APIs (to be ported from PPSSPP)
    ADHOCPP_API int sceNetAdhocPtpOpen(const char* name, int mode, int flags) { (void)name; (void)mode; (void)flags; return -1; }
    ADHOCPP_API int sceNetAdhocPtpClose(int ptpId) { (void)ptpId; return -1; }
    ADHOCPP_API int sceNetAdhocPtpSend(int ptpId, const void* data, int len, int* sent, int flags) { (void)ptpId; (void)data; (void)len; (void)sent; (void)flags; return -1; }
    ADHOCPP_API int sceNetAdhocPtpRecv(int ptpId, void* buf, int* len, int timeout_us, int flags) { (void)ptpId; (void)buf; (void)len; (void)timeout_us; (void)flags; return -1; }
    ADHOCPP_API int sceNetAdhocPtpConnect(int ptpId, const uint8_t destMac[6], uint16_t port, int timeout_ms) { (void)ptpId; (void)destMac; (void)port; (void)timeout_ms; return -1; }
    ADHOCPP_API int sceNetAdhocPtpListen(int ptpId, int backlog) { (void)ptpId; (void)backlog; return -1; }
    ADHOCPP_API int sceNetAdhocPtpAccept(int ptpId, uint8_t outMac[6], uint16_t* outPort) { (void)ptpId; (void)outMac; (void)outPort; return -1; }

    ADHOCPP_API int sceNetAdhocctlInit() { return -1; }
    ADHOCPP_API int sceNetAdhocctlTerm() { return -1; }
    ADHOCPP_API int sceNetAdhocctlConnect() { return -1; }
    ADHOCPP_API int sceNetAdhocctlDisconnect() { return -1; }

    ADHOCPP_API int sceNetAdhocMatchingCreate() { return -1; }
    ADHOCPP_API int sceNetAdhocMatchingTerm() { return -1; }
    ADHOCPP_API int sceNetAdhocMatchingAdd(int matchingId, const void* params) { (void)matchingId; (void)params; return -1; }
    ADHOCPP_API int sceNetAdhocMatchingUpdate(int matchingId, const void* params) { (void)matchingId; (void)params; return -1; }

    ADHOCPP_API int sceNetAdhocDiscoverStart() { return -1; }
    ADHOCPP_API int sceNetAdhocDiscoverStop() { return -1; }

    ADHOCPP_API const char* adhoc_version() {
        return "ppsspp-adhoc-lib skeleton v0.1";
    }

} // extern "C"

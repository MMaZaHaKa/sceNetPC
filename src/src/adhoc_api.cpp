// src/adhoc_api.cpp
#include "ppsspp_adhoc.h"
#include "socket_compat.h"
#include "kernel_shim.h"
#include <mutex>
#include <cstring>

static bool g_inited = false;
static std::mutex g_init_lock;

#ifdef __cplusplus
extern "C" {
#endif

    // Low-level wrappers implemented in other translation units
    int NetAdhocPdp_Create_Wrap(const char* mac, int port, int bufsz, uint32_t flag);
    int NetAdhocPdp_Delete_Wrap(int socketId);
    int NetAdhocPdp_Send_Wrap(int socketId, const char* destMac, uint16_t port, const void* data, int* len, uint32_t flag);
    int NetAdhocPdp_Recv_Wrap(int socketId, void* buf, int* len, int timeout_us);

    int NetAdhocPtp_Open_Wrap(const void* srcMac, uint16_t srcPort, const void* destMac, uint16_t dport,
        int bufsize, int rexmt_int_ms, int rexmt_cnt, int queue, int flag, int isClient);
    int NetAdhocPtp_Close_Wrap(int id);
    int NetAdhocPtp_Listen_Wrap(int id, uint16_t port, int backlog);
    int NetAdhocPtp_Accept_Wrap(int id, void* outMac, uint16_t* outPort, int timeout_ms);
    int NetAdhocPtp_SetPeer_Wrap(int id, const void* destMac, uint16_t port);
    int NetAdhocPtp_Connect_Wrap(int id, int timeout_us, int flag);
    int NetAdhocPtp_Send_Wrap(int id, const void* data, int* len, int timeout_us, int flag);
    int NetAdhocPtp_Recv_Wrap(int id, void* buf, int* len, int timeout_us, int flag);
    int NetAdhocPtp_Flush_Wrap(int id, int timeout_ms, int flag);

    // Utility wrappers from adhoc_core
    int NetAdhoc_GetLocalMac_Wrap(uint8_t outMac[6]);
    int NetAdhoc_MacToStr_Wrap(const uint8_t mac[6], char* outStr, int outLen);

    // Extended PDP recv: returns payload + source info
    int NetAdhocPdp_RecvFrom_Wrap(int socketId, void* buf, int* len, int timeout_us, uint8_t outMac[6], uint16_t* outPort, uint32_t* outIp);

#ifdef __cplusplus
}
#endif

extern "C" {

    // Basic network init/term (generic wrappers)
    ADHOCPP_API int sceNetInit() {
        socket_startup();
        return 0;
    }
    ADHOCPP_API int sceNetTerm() {
        socket_cleanup();
        return 0;
    }

    // WLAN state
    ADHOCPP_API int sceWlanGetSwitchState() {
        // best-effort: assume ON
        return 1;
    }

    // Local ether addr helper
    ADHOCPP_API int sceNetGetLocalEtherAddr(uint8_t outMac[6]) {
        if (!outMac) return -1;
        return NetAdhoc_GetLocalMac_Wrap(outMac);
    }

    ADHOCPP_API int sceNetEtherNtostr(const uint8_t mac[6], char* outStr, int outLen) {
        return NetAdhoc_MacToStr_Wrap(mac, outStr, outLen);
    }

    // Helpers for random mac/nick (thin wrappers to kernel_shim)
    ADHOCPP_API int sceNetGenerateRandomMac(uint8_t outMac[6]) {
        if (!outMac) return -1;
        ks_generate_random_mac(outMac);
        return 0;
    }
    ADHOCPP_API int sceNetGenerateRandomNickname(char* out, int out_len) {
        if (!out || out_len <= 0) return -1;
        ks_generate_random_nick(out, out_len);
        return 0;
    }

    // Keep PDP/PTP APIs (unchanged)
    ADHOCPP_API int sceNetAdhocInit() {
        std::lock_guard<std::mutex> lk(g_init_lock);
        if (g_inited) return 0;
        socket_startup();
        g_inited = true;
        LOG("[adhoc-api] sceNetAdhocInit");
        return 0;
    }

    ADHOCPP_API int sceNetAdhocTerm() {
        std::lock_guard<std::mutex> lk(g_init_lock);
        if (!g_inited) return 0;
        socket_cleanup();
        g_inited = false;
        LOG("[adhoc-api] sceNetAdhocTerm");
        return 0;
    }

    // PDP wrappers
    ADHOCPP_API int sceNetAdhocPdpCreate(const uint8_t mac[6], int port, int bufferSize, uint32_t flag) {
        if (!g_inited) return -1;
        const char* macptr = (mac) ? reinterpret_cast<const char*>(mac) : nullptr;
        return NetAdhocPdp_Create_Wrap(macptr, port, bufferSize, flag);
    }
    ADHOCPP_API int sceNetAdhocPdpDelete(int socketId) { if (!g_inited) return -1; return NetAdhocPdp_Delete_Wrap(socketId); }
    ADHOCPP_API int sceNetAdhocPdpSend(int socketId, const uint8_t destMac[6], uint16_t port, const void* data, int* len, uint32_t flag) {
        if (!g_inited) return -1;
        const char* macptr = (destMac) ? reinterpret_cast<const char*>(destMac) : nullptr;
        return NetAdhocPdp_Send_Wrap(socketId, macptr, port, data, len, flag);
    }
    ADHOCPP_API int sceNetAdhocPdpRecv(int socketId, void* buf, int* len, int timeout_us, uint32_t flag) {
        (void)flag;
        if (!g_inited) return -1;
        return NetAdhocPdp_Recv_Wrap(socketId, buf, len, timeout_us);
    }
    ADHOCPP_API int sceNetAdhocGetPdpStat(int socketId, void* statBuf, int statBufSize) {
        (void)socketId; (void)statBuf; (void)statBufSize; return -1;
    }

    // PTP wrappers
    ADHOCPP_API int sceNetAdhocPtpOpen(const char* name, int mode, int flags) {
        (void)name;
        return NetAdhocPtp_Open_Wrap(nullptr, 0, nullptr, 0, 4096, 1000, 3, 0, flags, mode);
    }
    ADHOCPP_API int sceNetAdhocPtpClose(int ptpId) { return NetAdhocPtp_Close_Wrap(ptpId); }
    ADHOCPP_API int sceNetAdhocPtpSend(int ptpId, const void* data, int len, int* sent, int flags) {
        int L = len;
        int r = NetAdhocPtp_Send_Wrap(ptpId, data, &L, 2000000, flags);
        if (sent) *sent = (r >= 0) ? L : 0;
        return r;
    }
    ADHOCPP_API int sceNetAdhocPtpRecv(int ptpId, void* buf, int* len, int timeout_us, int flags) {
        return NetAdhocPtp_Recv_Wrap(ptpId, buf, len, timeout_us, flags);
    }
    ADHOCPP_API int sceNetAdhocPtpConnect(int ptpId, const uint8_t destMac[6], uint16_t port, int timeout_ms) {
        if (!destMac) return -1;
        int r = NetAdhocPtp_SetPeer_Wrap(ptpId, destMac, port);
        if (r != 0) return r;
        return NetAdhocPtp_Connect_Wrap(ptpId, timeout_ms * 1000, 0);
    }
    ADHOCPP_API int sceNetAdhocPtpListen(int ptpId, int backlog) {
        return NetAdhocPtp_Listen_Wrap(ptpId, 0, backlog);
    }
    ADHOCPP_API int sceNetAdhocPtpAccept(int ptpId, uint8_t outMac[6], uint16_t* outPort) {
        return NetAdhocPtp_Accept_Wrap(ptpId, outMac ? reinterpret_cast<void*>(outMac) : nullptr, outPort, 5000);
    }
    ADHOCPP_API int sceNetAdhocPtpFlush(int ptpId, int timeout_ms, int flags) {
        return NetAdhocPtp_Flush_Wrap(ptpId, timeout_ms, flags);
    }
    ADHOCPP_API int sceNetAdhocGetPtpStat(int ptpId, void* statBuf, int statBufSize) {
        (void)ptpId; (void)statBuf; (void)statBufSize; return -1;
    }

    // NOTE: sceNetAdhocctl* implemented in adhocctl.cpp
    // NOTE: sceNetAdhocMatching* implemented in matching.cpp
    // NOTE: Discover will be implemented in discover.cpp

    ADHOCPP_API const char* adhoc_version() {
        return "ppsspp-adhoc-lib bridge v0.4";
    }

    ADHOCPP_API int sceNetAdhocPdpRecvFrom(int socketId, void* buf, int* len, int timeout_us, uint8_t outMac[6], uint16_t* outPort, uint32_t* outIp) {
        if (!g_inited) return -1;
        return NetAdhocPdp_RecvFrom_Wrap(socketId, buf, len, timeout_us, outMac, outPort, outIp);
    }


} // extern "C"

#pragma once
#define ADHOCPP_EXPORT
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <cstdint>

#ifdef _WIN32
#ifdef ADHOCPP_EXPORT
#define ADHOCPP_API __declspec(dllexport)
#else
#define ADHOCPP_API __declspec(dllimport)
#endif
#else
#define ADHOCPP_API
#endif

extern "C" {

    // Init / Term
    ADHOCPP_API int sceNetAdhocInit();
    ADHOCPP_API int sceNetAdhocTerm();

    // PDP (Peer Data Protocol) - basic operations
    // socketId returned >0 on success (PSP-style), <=0 error codes
    ADHOCPP_API int sceNetAdhocPdpCreate(const uint8_t mac[6], int port, int bufferSize, uint32_t flag);
    ADHOCPP_API int sceNetAdhocPdpDelete(int socketId);
    ADHOCPP_API int sceNetAdhocPdpSend(int socketId, const uint8_t destMac[6], uint16_t port, const void* data, int* len, uint32_t flag);
    ADHOCPP_API int sceNetAdhocPdpRecv(int socketId, void* buf, int* len, int timeout_us, uint32_t flag);
    ADHOCPP_API int sceNetAdhocGetPdpStat(int socketId, void* statBuf, int statBufSize);

    // PTP (Peer-to-peer Transport) - prototypes (stubs for now)
    ADHOCPP_API int sceNetAdhocPtpOpen(const char* name, int mode, int flags);
    ADHOCPP_API int sceNetAdhocPtpClose(int ptpId);
    ADHOCPP_API int sceNetAdhocPtpSend(int ptpId, const void* data, int len, int* sent, int flags);
    ADHOCPP_API int sceNetAdhocPtpRecv(int ptpId, void* buf, int* len, int timeout_us, int flags);
    ADHOCPP_API int sceNetAdhocPtpConnect(int ptpId, const uint8_t destMac[6], uint16_t port, int timeout_ms);
    ADHOCPP_API int sceNetAdhocPtpListen(int ptpId, int backlog);
    ADHOCPP_API int sceNetAdhocPtpAccept(int ptpId, uint8_t outMac[6], uint16_t* outPort);

    // AdhocCtl / Matching / Discover (prototypes — to implement)
    ADHOCPP_API int sceNetAdhocctlInit();
    ADHOCPP_API int sceNetAdhocctlTerm();
    ADHOCPP_API int sceNetAdhocctlConnect();
    ADHOCPP_API int sceNetAdhocctlDisconnect();

    ADHOCPP_API int sceNetAdhocMatchingCreate();
    ADHOCPP_API int sceNetAdhocMatchingTerm();
    ADHOCPP_API int sceNetAdhocMatchingAdd(int matchingId, const void* params);
    ADHOCPP_API int sceNetAdhocMatchingUpdate(int matchingId, const void* params);

    ADHOCPP_API int sceNetAdhocDiscoverStart();
    ADHOCPP_API int sceNetAdhocDiscoverStop();

    // Utility
    ADHOCPP_API const char* adhoc_version();

} // extern "C"

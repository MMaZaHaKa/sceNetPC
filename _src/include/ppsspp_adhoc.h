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

//#define MAX_PEERS 16
#define MAX_PEERS 64

struct PeerInfoEmuLocal {
    uint32_t next;
    uint8_t mac[6];
    uint8_t pad[2];
    uint32_t ip_addr;
    uint32_t flags;
    uint64_t last_recv;
    char nickname[32];
};

#ifdef __cplusplus
extern "C" {
#endif

    // Basic net init/term
    ADHOCPP_API int sceNetInit();
    ADHOCPP_API int sceNetTerm();

    // WLAN
    ADHOCPP_API int sceWlanGetSwitchState(); // return 1 = on, 0 = off

    // Low-level ether utilities
    ADHOCPP_API int sceNetGetLocalEtherAddr(uint8_t outMac[6]); // fill mac (network/local format as library uses)
    ADHOCPP_API int sceNetEtherNtostr(const uint8_t mac[6], char* outStr, int outLen); // convert mac -> human string

    // Helpers (not PSP standard, convenient)
    ADHOCPP_API int sceNetGenerateRandomMac(uint8_t outMac[6]);
    ADHOCPP_API int sceNetGenerateRandomNickname(char* out, int out_len);

    // Adhoc init/term
    ADHOCPP_API int sceNetAdhocInit();
    ADHOCPP_API int sceNetAdhocTerm();

    // PDP (Peer Data Protocol)
    ADHOCPP_API int sceNetAdhocPdpCreate(const uint8_t mac[6], int port, int bufferSize, uint32_t flag);
    ADHOCPP_API int sceNetAdhocPdpDelete(int socketId);
    ADHOCPP_API int sceNetAdhocPdpSend(int socketId, const uint8_t destMac[6], uint16_t port, const void* data, int* len, uint32_t flag);
    ADHOCPP_API int sceNetAdhocPdpRecv(int socketId, void* buf, int* len, int timeout_us, uint32_t flag);
    ADHOCPP_API int sceNetAdhocGetPdpStat(int socketId, void* statBuf, int statBufSize);

    // PTP (Peer-to-peer Transport)
    ADHOCPP_API int sceNetAdhocPtpOpen(const char* name, int mode, int flags);
    ADHOCPP_API int sceNetAdhocPtpClose(int ptpId);
    ADHOCPP_API int sceNetAdhocPtpSend(int ptpId, const void* data, int len, int* sent, int flags);
    ADHOCPP_API int sceNetAdhocPtpRecv(int ptpId, void* buf, int* len, int timeout_us, int flags);
    ADHOCPP_API int sceNetAdhocPtpConnect(int ptpId, const uint8_t destMac[6], uint16_t port, int timeout_ms);
    ADHOCPP_API int sceNetAdhocPtpListen(int ptpId, int backlog);
    ADHOCPP_API int sceNetAdhocPtpAccept(int ptpId, uint8_t outMac[6], uint16_t* outPort);
    ADHOCPP_API int sceNetAdhocPtpFlush(int ptpId, int timeout_ms, int flags);
    ADHOCPP_API int sceNetAdhocGetPtpStat(int ptpId, void* statBuf, int statBufSize);

    // AdhocCtl (control)
    ADHOCPP_API int sceNetAdhocctlInit(int stackSize, int prio, uint32_t productAddr);
    ADHOCPP_API int sceNetAdhocctlTerm();
    ADHOCPP_API int sceNetAdhocctlConnect(const char* groupName);
    ADHOCPP_API int sceNetAdhocctlDisconnect();
    ADHOCPP_API int sceNetAdhocctlGetState(uint32_t ptrToStatus);
    ADHOCPP_API int sceNetAdhocctlGetPeerList(void* outBuf, int maxEntries);
    ADHOCPP_API int sceNetAdhocctlScan(); // stub
    ADHOCPP_API int sceNetAdhocctlAddHandler(void* handler); // stub
    ADHOCPP_API int sceNetAdhocctlJoin(const char* groupName); // stub
    ADHOCPP_API int sceNetAdhocctlGetScanInfo(void* out, int size); // stub
    ADHOCPP_API int sceNetAdhocctlGetNameByAddr(const uint8_t mac[6], char* out, int out_len); // best-effort

    // Matching API (lots of names exist in PPSSPP)
    ADHOCPP_API int sceNetAdhocMatchingInit(); // maps to sceNetAdhocMatchingCreate or alias
    ADHOCPP_API int sceNetAdhocMatchingCreate();
    ADHOCPP_API int sceNetAdhocMatchingDelete(int matchingId);
    ADHOCPP_API int sceNetAdhocMatchingTerm();
    ADHOCPP_API int sceNetAdhocMatchingStart(int matchingId);
    ADHOCPP_API int sceNetAdhocMatchingStop(int matchingId);
    ADHOCPP_API int sceNetAdhocMatchingSetHelloOpt(int matchingId, int opt);
    ADHOCPP_API int sceNetAdhocMatchingSelectTarget(int matchingId, const uint8_t mac[6]);
    ADHOCPP_API int sceNetAdhocMatchingCancelTarget(int matchingId);
    ADHOCPP_API int sceNetAdhocMatchingAdd(int matchingId, const void* params);
    ADHOCPP_API int sceNetAdhocMatchingUpdate(int matchingId, const void* params);

    // Discover API (stubs / to implement in discover.cpp)
    ADHOCPP_API int sceNetAdhocDiscoverStart();
    ADHOCPP_API int sceNetAdhocDiscoverStop();

    // Additional utilities
    ADHOCPP_API const char* adhoc_version();

    // Extended recv: returns source mac/ip/port info as out parameters.
    // outMac can be nullptr; outPort/outIp can be nullptr.
    ADHOCPP_API int sceNetAdhocPdpRecvFrom(int socketId, void* buf, int* len, int timeout_us, uint8_t outMac[6], uint16_t* outPort, uint32_t* outIp);


#ifdef __cplusplus
}
#endif

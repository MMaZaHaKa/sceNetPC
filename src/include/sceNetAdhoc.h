// File: include/sceNetAdhoc.h
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

#ifdef _WIN32
#pragma comment(lib, "Ws2_32.lib")
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET native_socket_t;
#define close closesocket
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
typedef int native_socket_t;
#endif

// PSP-like types
typedef uint8_t SceNetEtherAddr[6];
typedef int SceNetAdhocctlHandlerUid;
typedef int SceNetAdhocMatchingContextId;

// Adhocctl peer info (updated from provided headers)
struct SceNetAdhocctlPeerInfo {
    SceNetAdhocctlPeerInfo* next;
    char nickname[128];
    unsigned char mac[6];
    unsigned char unknown[6];
    unsigned long timestamp;
};

// Adhocctl scan info (updated)
struct SceNetAdhocctlScanInfo {
    SceNetAdhocctlScanInfo* next;
    int channel;
    char name[8];
    unsigned char bssid[6];
    unsigned char unknown[2];
    int unknown2;
};

// For simplicity, use a flat array for scan results in GetScanInfo
struct SceNetAdhocctlScanInfoList {
    int num_results;
    SceNetAdhocctlScanInfo results[32]; // max
};

// Matching hello opt
struct SceNetAdhocMatchingHelloOpt {
    uint32_t size;
    uint8_t data[256];
};

// Return codes
#define SCE_NET_ERROR_OK 0
#define SCE_NET_ERROR_ADHOC_INIT -1
#define SCE_NET_ERROR_INVALID_ID -2
#define SCE_NET_ERROR_TIMEOUT -3
#define SCE_NET_ERROR_NOT_CONNECTED -4
#define SCE_NET_ERROR_OUT_OF_MEMORY -5

// Function declarations (updated with more from headers)
extern "C" {
    int sceNetInit(int poolsize, int calloutprio, int calloutstack, int netintrprio, int netintrstack);
    int sceNetTerm(void);
    int sceNetGetLocalEtherAddr(SceNetEtherAddr addr);
    void sceNetEtherNtostr(const SceNetEtherAddr mac, char* name);

    int sceNetAdhocInit(void);
    int sceNetAdhocTerm(void);

    int sceNetAdhocPdpCreate(const SceNetEtherAddr mac_addr, uint16_t port, int buf_size, int unk1);
    int sceNetAdhocPdpDelete(int id, int unk1);
    int sceNetAdhocPdpSend(int id, const SceNetEtherAddr dest_mac, uint16_t port, const void* data, int len, int timeout_us, int nonblock);
    int sceNetAdhocPdpRecv(int id, SceNetEtherAddr src_mac, uint16_t* port, void* data, int* data_len, int timeout_us, int nonblock);

    int sceNetAdhocPtpOpen(const SceNetEtherAddr src_mac, uint16_t src_port, const SceNetEtherAddr dest_mac, uint16_t dest_port, int buf_size, int delay_us, int count, int unk1);
    int sceNetAdhocPtpConnect(int id, int timeout_us, int nonblock);
    int sceNetAdhocPtpListen(const SceNetEtherAddr src_mac, uint16_t src_port, int buf_size, int delay_us, int count, int queue, int unk1);
    int sceNetAdhocPtpAccept(int id, SceNetEtherAddr* mac, uint16_t* port, int timeout_us, int nonblock);
    int sceNetAdhocPtpSend(int id, const void* data, int* data_size, int timeout_us, int nonblock);
    int sceNetAdhocPtpRecv(int id, void* data, int* data_size, int timeout_us, int nonblock);
    int sceNetAdhocPtpClose(int id, int unk1);

    int sceNetAdhocctlInit(int stacksize, int priority, void* product);
    int sceNetAdhocctlTerm(void);
    int sceNetAdhocctlConnect(const char* name);
    int sceNetAdhocctlDisconnect(void);
    int sceNetAdhocctlGetState(int* event);
    int sceNetAdhocctlCreate(const char* name);
    int sceNetAdhocctlJoin(const SceNetAdhocctlScanInfo* scaninfo);
    int sceNetAdhocctlGetPeerList(int* length, void* buf);
    int sceNetAdhocctlGetPeerInfo(const SceNetEtherAddr mac, int size, SceNetAdhocctlPeerInfo* peerinfo);
    int sceNetAdhocctlScan(void);
    int sceNetAdhocctlGetScanInfo(int* length, void* buf);
    int sceNetAdhocctlAddHandler(void (*handler)(int flag, int error, void* unknown), void* unknown);
    int sceNetAdhocctlDelHandler(int id);
    int sceNetAdhocctlGetNameByAddr(const SceNetEtherAddr mac, char* nickname);
    int sceNetAdhocctlGetAddrByName(const char* nickname, int* length, void* buf);

    int sceNetAdhocMatchingInit(int memsize);
    int sceNetAdhocMatchingTerm(void);
    int sceNetAdhocMatchingCreate(int mode, int maxpeers, uint16_t port, int bufsize, uint32_t hellodelay, uint32_t pingdelay, int initcount, uint32_t msgdelay, void* callback);
    int sceNetAdhocMatchingDelete(int matchingid);
    int sceNetAdhocMatchingStart(int matchingid, int evthpri, int evthstack, int inthpri, int inthstack, int optlen, void* optdata);
    int sceNetAdhocMatchingStop(int matchingid);
    int sceNetAdhocMatchingSelectTarget(int matchingid, const SceNetEtherAddr mac, int optlen, void* optdata);
    int sceNetAdhocMatchingCancelTarget(int matchingid, const SceNetEtherAddr mac);
    int sceNetAdhocMatchingSetHelloOpt(int matchingid, int optlen, void* optdata);
}

// Custom functions for PC
extern "C" {
    int sceNetSetNickname(const char* nick);
    int sceNetSetMacAddr(const SceNetEtherAddr mac);
    int sceNetSetRandomMacAddr(SceNetEtherAddr out_mac);
}
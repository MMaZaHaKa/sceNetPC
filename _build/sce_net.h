#ifndef SCE_NET_H
#define SCE_NET_H


#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


	// Basic network init/term
	int sceNetInit();
	int sceNetTerm();


	// MAC / nick helpers
	int sceNetGetLocalEtherAddr(uint8_t out[6]);
	int sceNetEtherNtostr(const uint8_t mac[6], char* outStr, int outLen);
	int sceNetSetNickname(const char* nick);
	int sceNetSetMacAddr(const uint8_t mac[6]);
	int sceNetSetRandomMacAddr(uint8_t outMac[6]);


	// sceNetAdhocctl API (subset)
	int sceNetAdhocctlInit();
	int sceNetAdhocctlTerm();


	// handler: callback signature (event, code, data, user)
	typedef void (*SceAdhocctlHandler)(int event, int code, void* data, void* user);
	int sceNetAdhocctlAddHandler(SceAdhocctlHandler h, void* user);
	int sceNetAdhocctlCreate();
	int sceNetAdhocctlConnect(const uint8_t mac[6]);
	int sceNetAdhocctlDisconnect();
	int sceNetAdhocctlScan(int maxPeers); // returns number of peers filled
	int sceNetAdhocctlGetNameByAddr(const uint8_t mac[6], char* out, int outLen);
	int sceNetAdhocctlGetScanInfo(int index, uint8_t outMac[6], char outName[64]);


	// Adhoc init/term (higher-level)
	int sceNetAdhocInit();
	int sceNetAdhocTerm();


	// PDP (simple wrappers)
	int sceNetAdhocPdpCreate(int port); // returns socket or -1
	int sceNetAdhocPdpDelete(int sock);
	int sceNetAdhocPdpSend(int sock, const void* buf, int len, const uint8_t destMac[6]);
	int sceNetAdhocPdpRecv(int sock, void* buf, int len);


	// PTP (connection oriented)
	int sceNetAdhocPtpAccept(int listenSock);
	int sceNetAdhocPtpClose(int sock);
	int sceNetAdhocPtpRecv(int sock, void* buf, int len);


	// Matching API (minimal)
	int sceNetAdhocMatchingInit();
	int sceNetAdhocMatchingTerm();
	int sceNetAdhocMatchingCreate();
	int sceNetAdhocMatchingDelete();
	int sceNetAdhocMatchingStart();
	int sceNetAdhocMatchingStop();


#ifdef __cplusplus
}
#endif


#endif // SCE_NET_H
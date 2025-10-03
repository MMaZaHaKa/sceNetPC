// src/main.cpp
#include "ppsspp_adhoc.h"
#include "socket_compat.h"
#include "kernel_shim.h"
#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>

#ifdef __cplusplus
extern "C" {
#endif
    int NetAdhocPtp_Open_Wrap(const void* srcMac, uint16_t srcPort, const void* destMac, uint16_t dport,
        int bufsize, int rexmt_int_ms, int rexmt_cnt, int queue, int flag, int isClient);
    int NetAdhocPtp_Listen_Wrap(int id, uint16_t port, int backlog);
    int NetAdhocPtp_Accept_Wrap(int id, void* outMac, uint16_t* outPort, int timeout_ms);
    int NetAdhocPtp_SetPeer_Wrap(int id, const void* destMac, uint16_t port);
    int NetAdhocPtp_Connect_Wrap(int id, int timeout_us, int flag);
    int NetAdhocPtp_Send_Wrap(int id, const void* data, int* len, int timeout_us, int flag);
    int NetAdhocPtp_Recv_Wrap(int id, void* buf, int* len, int timeout_us, int flag);
    int NetAdhocPtp_Close_Wrap(int id);

    int NetAdhocPdp_Create_Wrap(const char* mac, int port, int bufsz, uint32_t flag);
    int NetAdhocPdp_Delete_Wrap(int socketId);
    int NetAdhocPdp_Send_Wrap(int socketId, const char* destMac, uint16_t port, const void* data, int* len, uint32_t flag);
    int NetAdhocPdp_Recv_Wrap(int socketId, void* buf, int* len, int timeout_us);

    // peer-list add
    int NetAdhoc_AddFriend_Wrap(const uint8_t* mac, uint32_t ip_nbo, const char* nick);

#ifdef __cplusplus
}
#endif

int main() {
    printf("adhoc test start\n");

    // core network init
    if (sceNetInit() != 0) {
        printf("sceNetInit failed\n");
        return 1;
    }

    // generate random nickname and macs (helpers)
    uint8_t mac1[6], mac2[6];
    char nick[64];
    sceNetGenerateRandomMac(mac1);
    sceNetGenerateRandomMac(mac2);
    sceNetGenerateRandomNickname(nick, sizeof(nick));
    printf("Local nick: %s\n", nick);

    char macstr[32];
    sceNetEtherNtostr(mac1, macstr, sizeof(macstr));
    printf("Local MAC1: %s\n", macstr);
    sceNetEtherNtostr(mac2, macstr, sizeof(macstr));
    printf("Local MAC2: %s\n", macstr);

    // init adhoc subsystem
    if (sceNetAdhocInit() != 0) {
        printf("sceNetAdhocInit failed\n");
        sceNetTerm();
        return 2;
    }

    // init adhocctl (start internal friend-finder / control thread if implemented)
    sceNetAdhocctlInit(0, 0, 0);

    // Start discovery — advertise our nick and listen for peers
    sceNetAdhocDiscoverStart();

    // Create a matching slot and ask it to import current peers (nullptr)
    int mid = sceNetAdhocMatchingCreate();
    if (mid > 0) {
        sceNetAdhocMatchingAdd(mid, nullptr);
    }
    else {
        printf("sceNetAdhocMatchingCreate failed -> %d\n", mid);
    }

    // Wait a little to allow discover/matching to run and exchange nicknames
    // (discover and matching send messages periodically — 2-3 seconds enough for local tests)
    ks_sleep_ms(2500);

    // Print peer list via control API
    //const int MAX_PEERS = 32;
    /*struct*/ PeerInfoEmuLocal/* {
        uint32_t next;
        uint8_t mac[6];
        uint8_t pad[2];
        uint32_t ip_addr;
        uint32_t flags;
        uint64_t last_recv;
        char nickname[32];
    }*/ peers_buf[MAX_PEERS];

    int got = sceNetAdhocctlGetPeerList(peers_buf, MAX_PEERS);
    printf("Peer list count: %d\n", got);
    for (int i = 0; i < got; ++i) {
        auto& p = peers_buf[i];
        char macs[32] = { 0 };
        sceNetEtherNtostr(p.mac, macs, sizeof(macs));
        printf("Peer %d: MAC %s ip=%s nick=%s last_recv_us=%llu\n", i,
            macs,
            inet_ntoa(*(struct in_addr*)&p.ip_addr),
            p.nickname,
            (unsigned long long)p.last_recv);
    }

    // --- PDP UDP quick test (send/receive) ---
    // create two PDP sockets (send & recv)
    int recvPort = 10010;
    int sendPort = 10011;

    int rcv = sceNetAdhocPdpCreate(mac1, recvPort, 1500, 0);
    if (rcv <= 0) {
        printf("pdp create recv failed %d\n", rcv);
    }
    else {
        printf("rcv id=%d\n", rcv);
    }

    int snd = sceNetAdhocPdpCreate(mac2, sendPort, 1500, 0);
    if (snd <= 0) {
        printf("pdp create snd failed %d\n", snd);
    }
    else {
        printf("snd id=%d\n", snd);
    }

    if (rcv > 0 && snd > 0) {
        // prepare dest mac = 127.0.0.1 packed into first 4 bytes
        uint32_t ip_nbo = inet_addr("127.0.0.1");
        uint8_t destMac[6];
        memcpy(destMac, &ip_nbo, 4);
        destMac[4] = 0; destMac[5] = 0;

        const char* msg = "hello adhoc UDP (from main)";
        int len = (int)strlen(msg) + 1;
        int send_len = len;
        int sres = sceNetAdhocPdpSend(snd, destMac, recvPort, msg, &send_len, 0);
        printf("UDP send res=%d sent=%d\n", sres, send_len);

        char bufudp[2048];
        int buflen = sizeof(bufudp);
        // use extended recvfrom so we get source info if available
        uint8_t srcmac[6];
        uint16_t srcport = 0;
        uint32_t srcip = 0;
        int trecv = sceNetAdhocPdpRecvFrom(rcv, bufudp, &buflen, 2000000, srcmac, &srcport, &srcip);
        if (trecv > 0) {
            printf("UDP recv OK len=%d from %s:%d mac=%02x:%02x:%02x:%02x:%02x:%02x : '%s'\n",
                buflen, inet_ntoa(*(struct in_addr*)&srcip), srcport,
                srcmac[0], srcmac[1], srcmac[2], srcmac[3], srcmac[4], srcmac[5],
                bufudp);
        }
        else {
            printf("UDP recv failed %d\n", trecv);
        }

        sceNetAdhocPdpDelete(snd);
        sceNetAdhocPdpDelete(rcv);
    }

    // Clean up: stop discover & matching and terminate
    sceNetAdhocDiscoverStop();
    sceNetAdhocMatchingTerm(); // terminates all matching slots
    sceNetAdhocctlTerm();
    sceNetAdhocTerm();
    sceNetTerm();

    printf("done\n");
    return 0;
}

int main2() {
    printf("adhoc test start\n");

    // core network init
    if (sceNetInit() != 0) {
        printf("sceNetInit failed\n");
        return 1;
    }

    // generate random nickname and macs
    uint8_t mac1[6], mac2[6];
    char nick[24];
    sceNetGenerateRandomMac(mac1);
    sceNetGenerateRandomMac(mac2);
    sceNetGenerateRandomNickname(nick, sizeof(nick));
    printf("Local nick: %s\n", nick);
    char macstr[32];
    sceNetEtherNtostr(mac1, macstr, sizeof(macstr));
    printf("Local MAC1: %s\n", macstr);
    sceNetEtherNtostr(mac2, macstr, sizeof(macstr));
    printf("Local MAC2: %s\n", macstr);

    // init adhoc subsystem
    if (sceNetAdhocInit() != 0) {
        printf("sceNetAdhocInit failed\n");
        sceNetTerm();
        return 2;
    }

    // Add a friend manually (via adhocctl API)
    // We'll create a friend record by using adhocctlGetPeerList trick: but easiest is to call existing wrapper
    uint8_t friendmac[6];
    sceNetGenerateRandomMac(friendmac);
    uint32_t loop_ip_nbo = inet_addr("127.0.0.1");
    // NetAdhoc_AddFriend_Wrap exists internally; use sceNetAdhocctlConnect + other flows in real apps.
    // For quick test, call NetAdhoc_AddFriend_Wrap if available (extern). If not, you can rely on friendFinder thread in adhocctl to add local peers.

    // Create two PDP sockets (send & recv)
    int recvPort = 10010;
    int sendPort = 10011;
    int rcv = sceNetAdhocPdpCreate(mac1, recvPort, 1500, 0);
    if (rcv <= 0) { printf("pdp create recv failed %d\n", rcv); return 3; }
    printf("rcv id=%d\n", rcv);

    int snd = sceNetAdhocPdpCreate(mac2, sendPort, 1500, 0);
    if (snd <= 0) { printf("pdp create snd failed %d\n", snd); return 4; }
    printf("snd id=%d\n", snd);

    // prepare dest mac = 127.0.0.1 packed into first 4 bytes
    uint32_t ip_nbo = inet_addr("127.0.0.1");
    uint8_t destMac[6];
    memcpy(destMac, &ip_nbo, 4);
    destMac[4] = 0; destMac[5] = 0;

    const char* msg = "hello adhoc UDP";
    int len = (int)strlen(msg) + 1;
    int send_len = len;
    int sres = sceNetAdhocPdpSend(snd, destMac, recvPort, msg, &send_len, 0);
    printf("UDP send res=%d sent=%d\n", sres, send_len);

    char bufudp[2048];
    int buflen = sizeof(bufudp);
    int trecv = sceNetAdhocPdpRecv(rcv, bufudp, &buflen, 2000000, 0);
    if (trecv > 0) {
        printf("UDP recv OK len=%d: '%s'\n", buflen, bufudp);
    }
    else {
        printf("UDP recv failed %d\n", trecv);
    }

    sceNetAdhocPdpDelete(snd);
    sceNetAdhocPdpDelete(rcv);

    sceNetAdhocTerm();
    sceNetTerm();
    printf("done\n");
    return 0;
}


int main1() {
    printf("adhoc test start\n");

    if (sceNetAdhocInit() != 0) {
        printf("init failed\n");
        return 1;
    }

    // generate random MAC for local sockets
    uint8_t mymac1[6], mymac2[6];
    ks_generate_random_mac(mymac1);
    ks_generate_random_mac(mymac2);
    char nickbuf[24];
    ks_generate_random_nick(nickbuf, sizeof(nickbuf));
    printf("Local nick: %s\n", nickbuf);
    printf("Local MAC1: %02x:%02x:%02x:%02x:%02x:%02x\n", mymac1[0], mymac1[1], mymac1[2], mymac1[3], mymac1[4], mymac1[5]);
    printf("Local MAC2: %02x:%02x:%02x:%02x:%02x:%02x\n", mymac2[0], mymac2[1], mymac2[2], mymac2[3], mymac2[4], mymac2[5]);

    // ADD a test friend into the peer list using generated MAC + nickname (loopback IP)
    uint32_t loop_ip_nbo = inet_addr("127.0.0.1");
    uint8_t friendmac[6];
    ks_generate_random_mac(friendmac);
    char friendnick[24];
    ks_generate_random_nick(friendnick, sizeof(friendnick));
    NetAdhoc_AddFriend_Wrap(friendmac, loop_ip_nbo, friendnick);
    printf("Added friend %s with MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
        friendnick, friendmac[0], friendmac[1], friendmac[2], friendmac[3], friendmac[4], friendmac[5]);

    // --- PDP test (UDP) ---
    int recvPort = 10010;
    int sendPort = 10011;

    int rcv = sceNetAdhocPdpCreate(mymac1, recvPort, 1500, 0);
    if (rcv <= 0) { printf("pdp create recv failed %d\n", rcv); return 2; }
    printf("rcv id=%d\n", rcv);

    int snd = sceNetAdhocPdpCreate(mymac2, sendPort, 1500, 0);
    if (snd <= 0) { printf("pdp create snd failed %d\n", snd); return 3; }
    printf("snd id=%d\n", snd);

    uint8_t destMac[6];
    memcpy(destMac, &loop_ip_nbo, 4);
    destMac[4] = 0; destMac[5] = 0;

    const char* msg = "hello adhoc UDP";
    int len = (int)strlen(msg) + 1;
    int send_len = len;
    int sres = sceNetAdhocPdpSend(snd, destMac, recvPort, msg, &send_len, 0);
    printf("UDP send res=%d sent=%d\n", sres, send_len);

    char bufudp[2048];
    int buflen = sizeof(bufudp);
    int trecv = sceNetAdhocPdpRecv(rcv, bufudp, &buflen, 2000000, 0);
    if (trecv > 0) {
        printf("UDP recv OK len=%d: '%s'\n", buflen, bufudp);
    }
    else {
        printf("UDP recv failed %d\n", trecv);
    }

    sceNetAdhocPdpDelete(snd);
    sceNetAdhocPdpDelete(rcv);

    // Optionally show peer list using sceNetAdhocctlGetPeerList()
    // Prepare buffer for peers
    // SceNetAdhocctlPeerInfoEmu defined in adhoc_core.cpp; we can allocate raw buffer and call getPeerList
    // We'll declare a compatible struct here for reading the results:
    //struct PeerInfoEmuLocal {
    //    uint32_t next;
    //    uint8_t mac[6];
    //    uint8_t pad[2];
    //    uint32_t ip_addr;
    //    uint32_t flags;
    //    uint64_t last_recv;
    //    char nickname[32];
    //} peers_buf[MAX_PEERS];
    PeerInfoEmuLocal peers_buf[MAX_PEERS];

    int got = sceNetAdhocctlGetPeerList(peers_buf, MAX_PEERS);
    printf("Peer list count: %d\n", got);
    for (int i = 0; i < got; ++i) {
        auto& p = peers_buf[i];
        printf("Peer %d: MAC %02x:%02x:%02x:%02x:%02x:%02x ip=%s nick=%s\n", i,
            p.mac[0], p.mac[1], p.mac[2], p.mac[3], p.mac[4], p.mac[5],
            inet_ntoa(*(struct in_addr*)&p.ip_addr),
            p.nickname);
    }

    // --- PTP test (TCP) left unchanged (you have existing test) ---

    sceNetAdhocTerm();
    printf("done\n");
    return 0;
}


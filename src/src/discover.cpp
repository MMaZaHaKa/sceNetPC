// src/discover.cpp
// Implementation of sceNetAdhocDiscoverStart / sceNetAdhocDiscoverStop
// Integrates with existing adhoc_core peerlist and PDP wrappers.
// Behavior:
//  - create a PDP socket for discover
//  - periodically send "DISCOVER_PING:<nick>" to known peers (or loopback if none)
//  - reply to incoming pings with "DISCOVER_RESP:<nick>"
//  - when receive DISCOVER_RESP, add/update peer via NetAdhoc_AddFriend_Wrap
// Note: This is written to be robust for local testing (loopback) and LAN.

#include "ppsspp_adhoc.h"
#include "kernel_shim.h"
#include "socket_compat.h"

#include <thread>
#include <atomic>
#include <vector>
#include <cstring>
#include <chrono>
#include <cstdio>

extern "C" {
    // from adhoc_core / pdp wrappers
    int NetAdhoc_GetPeerList_Wrap(void* outBuf, int maxEntries);
    int NetAdhoc_GetPeerCount_Wrap();
    int NetAdhoc_AddFriend_Wrap(const uint8_t* mac, uint32_t ip_nbo, const char* nick);

    int NetAdhocPdp_Create_Wrap(const char* mac, int port, int bufsz, uint32_t flag);
    int NetAdhocPdp_Delete_Wrap(int socketId);
    int NetAdhocPdp_Send_Wrap(int socketId, const char* destMac, uint16_t port, const void* data, int* len, uint32_t flag);
    int NetAdhocPdp_Recv_Wrap(int socketId, void* buf, int* len, int timeout_us);
    int NetAdhocPdp_RecvFrom_Wrap(int socketId, void* buf, int* len, int timeout_us, uint8_t outMac[6], uint16_t* outPort, uint32_t* outIp);
}

using namespace std::chrono_literals;

static std::atomic<bool> g_discover_running(false);
static std::thread g_discover_thread;
static int g_discover_pdp_socket = -1;
static const uint16_t DISCOVER_PORT = 15020; // chosen discover port

// Local helper: pack ipv4 -> 6-byte destMac (first 4 bytes ip_nbo)
static void pack_ip_to_mac(uint32_t ip_nbo, uint8_t dest[6]) {
    memcpy(dest, &ip_nbo, 4);
    dest[4] = 0; dest[5] = 0;
}

// Local structure matching earlier SceNetAdhocctlPeerInfoEmu in adhoc_core
struct PeerInfoEmuLocal {
    uint32_t next;
    uint8_t mac[6];
    uint8_t pad[2];
    uint32_t ip_addr;
    uint32_t flags;
    uint64_t last_recv;
    char nickname[32];
};

// Send a discover ping to given ip_nbo / port
static void discover_send_ping(int pdp_socket, uint32_t ip_nbo, uint16_t port, const char* mynick) {
    char payload[256];
    int plen = snprintf(payload, sizeof(payload), "DISCOVER_PING:%s", mynick ? mynick : "unknown");
    if (plen <= 0) return;
    int sendlen = plen + 1;
    char destMac[6];
    pack_ip_to_mac(ip_nbo, (uint8_t*)destMac);
    int res = NetAdhocPdp_Send_Wrap(pdp_socket, destMac, port, payload, &sendlen, 0);
    if (res >= 0) {
        LOG("[discover] sent ping to %s:%d (len=%d)", inet_ntoa(*(struct in_addr*)&ip_nbo), port, sendlen);
    }
    else {
        LOG("[discover] ping send failed to %s:%d res=%d", inet_ntoa(*(struct in_addr*)&ip_nbo), port, res);
    }
}

// Send discover response (reply to ping) - uses same pdp socket
static void discover_send_resp(int pdp_socket, uint32_t ip_nbo, uint16_t port, const char* mynick) {
    char payload[256];
    int plen = snprintf(payload, sizeof(payload), "DISCOVER_RESP:%s", mynick ? mynick : "unknown");
    if (plen <= 0) return;
    int sendlen = plen + 1;
    char destMac[6];
    pack_ip_to_mac(ip_nbo, (uint8_t*)destMac);
    int res = NetAdhocPdp_Send_Wrap(pdp_socket, destMac, port, payload, &sendlen, 0);
    if (res >= 0) {
        LOG("[discover] sent resp to %s:%d", inet_ntoa(*(struct in_addr*)&ip_nbo), port);
    }
    else {
        LOG("[discover] resp send failed to %s:%d res=%d", inet_ntoa(*(struct in_addr*)&ip_nbo), port, res);
    }
}

static void discover_thread_func() {
    LOG("[discover] thread started");
    // Create PDP socket bound to DISCOVER_PORT
    g_discover_pdp_socket = NetAdhocPdp_Create_Wrap(nullptr, DISCOVER_PORT, 1500, 0);
    if (g_discover_pdp_socket <= 0) {
        LOG("[discover] failed to create PDP socket for discover: %d", g_discover_pdp_socket);
        g_discover_running = false;
        return;
    }
    LOG("[discover] PDP socket id=%d created on port %d", g_discover_pdp_socket, DISCOVER_PORT);

    char mynick[64];
    ks_generate_random_nick(mynick, sizeof(mynick));

    while (g_discover_running) {
        int peerCount = NetAdhoc_GetPeerCount_Wrap();
        if (peerCount <= 0) {
            uint32_t loop_ip = inet_addr("127.0.0.1");
            discover_send_ping(g_discover_pdp_socket, loop_ip, DISCOVER_PORT, mynick);
        }
        else {
            const int MAX_PEERS = 64;
            PeerInfoEmuLocal peers[MAX_PEERS];
            int got = NetAdhoc_GetPeerList_Wrap(peers, MAX_PEERS);
            for (int i = 0; i < got; ++i) {
                uint32_t ip = peers[i].ip_addr;
                if (ip == 0) continue;
                discover_send_ping(g_discover_pdp_socket, ip, DISCOVER_PORT, mynick);
            }
        }

        const int RECEIVE_WINDOW_MS = 2000;
        int elapsed = 0;
        const int POLL_MS = 200;
        while (g_discover_running && elapsed < RECEIVE_WINDOW_MS) {
            char buf[2048];
            int buflen = sizeof(buf);
            uint8_t srcmac[6] = { 0 };
            uint16_t srcport = 0;
            uint32_t srcip = 0;
            int r = NetAdhocPdp_RecvFrom_Wrap(g_discover_pdp_socket, buf, &buflen, 200000, srcmac, &srcport, &srcip);
            if (r > 0) {
                buf[buflen] = '\0';
                LOG("[discover] recv: %s (from %s:%d)", buf, inet_ntoa(*(struct in_addr*)&srcip), srcport);
                const char* pingPrefix = "DISCOVER_PING:";
                const char* respPrefix = "DISCOVER_RESP:";
                if (strncmp(buf, pingPrefix, strlen(pingPrefix)) == 0) {
                    const char* peernick = buf + strlen(pingPrefix);
                    LOG("[discover] got ping from %s -> send resp (ip=%s)", peernick, inet_ntoa(*(struct in_addr*)&srcip));
                    discover_send_resp(g_discover_pdp_socket, srcip, srcport, mynick);
                    NetAdhoc_AddFriend_Wrap(srcmac, srcip, peernick);
                }
                else if (strncmp(buf, respPrefix, strlen(respPrefix)) == 0) {
                    const char* peernick = buf + strlen(respPrefix);
                    LOG("[discover] got resp from %s -> add to peers (ip=%s)", peernick, inet_ntoa(*(struct in_addr*)&srcip));
                    NetAdhoc_AddFriend_Wrap(srcmac, srcip, peernick);
                }
                else {
                    LOG("[discover] unknown discover payload: %s", buf);
                }
            }
            if (!g_discover_running) break;
            ks_sleep_ms(POLL_MS);
            elapsed += POLL_MS;
        }
        ks_sleep_ms(200);
    }

    if (g_discover_pdp_socket > 0) {
        NetAdhocPdp_Delete_Wrap(g_discover_pdp_socket);
        g_discover_pdp_socket = -1;
    }

    LOG("[discover] thread exiting");
}


// Public API
extern "C" {

    ADHOCPP_API int sceNetAdhocDiscoverStart() {
        if (g_discover_running) return 0; // already running
        g_discover_running = true;
        g_discover_thread = std::thread(discover_thread_func);
        // give it a moment to start
        ks_sleep_ms(10);
        LOG("[discover] started");
        return 0;
    }

    ADHOCPP_API int sceNetAdhocDiscoverStop() {
        if (!g_discover_running) return 0;
        g_discover_running = false;
        if (g_discover_thread.joinable()) g_discover_thread.join();
        LOG("[discover] stopped");
        return 0;
    }

} // extern "C"

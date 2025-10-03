// File: src/sceNetAdhoc.cpp
#include "../include/sceNetAdhoc.h"
#include <cstdio>
#include <cstring>
#include <vector>
#include <mutex>
#include <thread>
#include <chrono>
#include <random>
#include <algorithm>  // For std::min
#include <cstddef>    // For size_t

// Global state
static bool net_inited = false;
static bool adhoc_inited = false;
static bool adhocctl_inited = false;
static char global_nickname[128] = "PCPlayer";  // Updated size from header
static SceNetEtherAddr global_mac = { 0x02, 0x50, 0xF2, 0x00, 0x00, 0x00 }; // Local admin MAC prefix
static std::mutex global_lock;
static std::random_device rd;
static std::mt19937 gen(rd());

// Socket map for PDP (UDP-like)
struct PdpSlot {
    native_socket_t sock = -1;
    SceNetEtherAddr mac;
    uint16_t port;
    bool used = false;
};
static std::vector<PdpSlot> pdp_slots;
static std::mutex pdp_lock;

// Socket map for PTP (TCP-like) - now global for access if needed, but better use functions
struct PtpSlot {
    native_socket_t sock = -1;
    bool is_server = false;
    uint32_t peer_ip = 0;
    uint16_t peer_port = 0;
    bool used = false;
    SceNetEtherAddr peer_mac;
};
static std::vector<PtpSlot> ptp_slots(32);  // Fixed declaration
static std::mutex ptp_lock;

// Peer list for adhocctl (updated to match header)
std::vector<SceNetAdhocctlPeerInfo> peer_list;
static std::mutex peer_lock;

// Matching contexts (simplified)
struct MatchingCtx {
    int id;
    bool active = false;
    std::vector<int> targets;
};
static std::vector<MatchingCtx> matching_ctxs;
static std::mutex matching_lock;

// Thread for scanning/sending beacons (simulated)
static std::thread scan_thread;
static bool scan_running = false;

// Startup sockets
static void socket_startup() {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
}
static void socket_cleanup() {
#ifdef _WIN32
    WSACleanup();
#endif
}

// Utility: IP from MAC (loopback for PC sim)
static uint32_t mac_to_ip(const SceNetEtherAddr mac) {
    uint32_t ip = 0x7F000001; // 127.0.0.1
    // Pack first 4 bytes of MAC into IP for sim
    memcpy(&ip, mac, 4);
    return htonl(ip);
}

// Utility: Random MAC
static void generate_random_mac(SceNetEtherAddr mac) {
    std::uniform_int_distribution<> dis(0, 255);
    mac[0] = 0x02; // Local
    for (int i = 1; i < 6; ++i) {
        mac[i] = dis(gen);
    }
}

// Custom: Set nickname
int sceNetSetNickname(const char* nick) {
    if (!nick || strlen(nick) >= sizeof(global_nickname)) return -1;
    std::lock_guard<std::mutex> lk(global_lock);
    strncpy(global_nickname, nick, sizeof(global_nickname) - 1);
    global_nickname[sizeof(global_nickname) - 1] = 0;
    return 0;
}

// Custom: Set MAC
int sceNetSetMacAddr(const SceNetEtherAddr mac) {
    std::lock_guard<std::mutex> lk(global_lock);
    memcpy(global_mac, mac, 6);
    return 0;
}

// Custom: Random MAC
int sceNetSetRandomMacAddr(SceNetEtherAddr out_mac) {
    std::lock_guard<std::mutex> lk(global_lock);
    generate_random_mac(global_mac);
    memcpy(out_mac, global_mac, 6);
    return 0;
}

// Net init/term (updated signature)
int sceNetInit(int poolsize, int calloutprio, int calloutstack, int netintrprio, int netintrstack) {
    (void)poolsize; (void)calloutprio; (void)calloutstack; (void)netintrprio; (void)netintrstack;
    if (net_inited) return 0;
    socket_startup();
    net_inited = true;
    return 0;
}

int sceNetTerm(void) {
    if (!net_inited) return 0;
    net_inited = false;
    socket_cleanup();
    return 0;
}

// Ether utils (updated)
int sceNetGetLocalEtherAddr(SceNetEtherAddr addr) {
    std::lock_guard<std::mutex> lk(global_lock);
    memcpy(addr, global_mac, 6);
    return 0;
}

void sceNetEtherNtostr(const SceNetEtherAddr mac, char* name) {
    snprintf(name, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Adhoc init/term
int sceNetAdhocInit(void) {
    if (adhoc_inited) return 0;
    if (!net_inited) return SCE_NET_ERROR_ADHOC_INIT;
    adhoc_inited = true;
    // Add self to peer list (updated struct)
    {
        std::lock_guard<std::mutex> lk(peer_lock);
        SceNetAdhocctlPeerInfo self;
        self.next = nullptr;
        strncpy(self.nickname, global_nickname, sizeof(self.nickname) - 1);
        memcpy(self.mac, global_mac, 6);
        memset(self.unknown, 0, sizeof(self.unknown));
        self.timestamp = (unsigned long)std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        peer_list.push_back(self);
    }
    return 0;
}

int sceNetAdhocTerm(void) {
    if (!adhoc_inited) return 0;
    adhoc_inited = false;
    // Stop scan thread if running
    scan_running = false;
    if (scan_thread.joinable()) scan_thread.join();
    return 0;
}

// PDP (updated signatures)
int sceNetAdhocPdpCreate(const SceNetEtherAddr mac_addr, uint16_t port, int buf_size, int unk1) {
    (void)unk1;
    if (!adhoc_inited) return SCE_NET_ERROR_ADHOC_INIT;
    native_socket_t sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    std::lock_guard<std::mutex> lk(pdp_lock);
    PdpSlot slot;
    slot.sock = sock;
    memcpy(slot.mac, mac_addr ? mac_addr : global_mac, 6);
    slot.port = port;
    slot.used = true;
    pdp_slots.push_back(slot);
    return (int)pdp_slots.size() - 1;
}

int sceNetAdhocPdpDelete(int id, int unk1) {
    (void)unk1;
    std::lock_guard<std::mutex> lk(pdp_lock);
    if (id < 0 || id >= (int)pdp_slots.size() || !pdp_slots[id].used) return -1;
    close(pdp_slots[id].sock);
    pdp_slots[id].used = false;
    return 0;
}

int sceNetAdhocPdpSend(int id, const SceNetEtherAddr dest_mac, uint16_t port, const void* data, int len, int timeout_us, int nonblock) {
    (void)timeout_us; (void)nonblock;
    std::lock_guard<std::mutex> lk(pdp_lock);
    if (id < 0 || id >= (int)pdp_slots.size() || !pdp_slots[id].used || len <= 0) return -1;
    uint32_t dest_ip = mac_to_ip(dest_mac);

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = dest_ip;
    dest.sin_port = htons(port);

    int sent = sendto(pdp_slots[id].sock, (const char*)data, len, 0, (struct sockaddr*)&dest, sizeof(dest));
    if (sent < 0) return -1;
    return sent;
}

int sceNetAdhocPdpRecv(int id, SceNetEtherAddr src_mac, uint16_t* port, void* data, int* data_len, int timeout_us, int nonblock) {
    (void)nonblock;
    std::lock_guard<std::mutex> lk(pdp_lock);
    if (id < 0 || id >= (int)pdp_slots.size() || !pdp_slots[id].used || !data || !data_len || *data_len <= 0) return -1;

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(pdp_slots[id].sock, &readfds);

    struct timeval tv;
    tv.tv_sec = timeout_us / 1000000;
    tv.tv_usec = timeout_us % 1000000;

    int nfds = pdp_slots[id].sock + 1;
    int r = select(nfds, &readfds, NULL, NULL, timeout_us > 0 ? &tv : NULL);
    if (r <= 0) return SCE_NET_ERROR_TIMEOUT;

    struct sockaddr_in src;
    socklen_t slen = sizeof(src);
    int recvd = recvfrom(pdp_slots[id].sock, (char*)data, *data_len, 0, (struct sockaddr*)&src, &slen);
    if (recvd < 0) return -1;
    *data_len = recvd;
    if (src_mac) memcpy(src_mac, global_mac, 6); // Sim self
    if (port) *port = ntohs(src.sin_port);
    return recvd;
}

// PTP implementations (new)
int sceNetAdhocPtpOpen(const SceNetEtherAddr src_mac, uint16_t src_port, const SceNetEtherAddr dest_mac, uint16_t dest_port, int buf_size, int delay_us, int count, int unk1) {
    (void)src_mac; (void)src_port; (void)dest_mac; (void)dest_port; (void)buf_size; (void)delay_us; (void)count; (void)unk1;
    if (!adhoc_inited) return SCE_NET_ERROR_ADHOC_INIT;
    std::lock_guard<std::mutex> lk(ptp_lock);
    for (size_t i = 0; i < ptp_slots.size(); ++i) {
        if (!ptp_slots[i].used) {
            ptp_slots[i].used = true;
            ptp_slots[i].is_server = false;
            ptp_slots[i].peer_ip = mac_to_ip(dest_mac);
            ptp_slots[i].peer_port = dest_port;
            memcpy(ptp_slots[i].peer_mac, dest_mac, 6);
            // Create client socket
            ptp_slots[i].sock = socket(AF_INET, SOCK_STREAM, 0);
            if (ptp_slots[i].sock < 0) {
                ptp_slots[i].used = false;
                return -1;
            }
            return (int)i;
        }
    }
    return -1;
}

int sceNetAdhocPtpConnect(int id, int timeout_us, int nonblock) {
    (void)nonblock;
    std::lock_guard<std::mutex> lk(ptp_lock);
    if (id < 0 || id >= (int)ptp_slots.size() || !ptp_slots[id].used || ptp_slots[id].is_server) return -1;

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = ptp_slots[id].peer_ip;
    dest.sin_port = htons(ptp_slots[id].peer_port);

    // Simple connect (no timeout sim for now)
    if (connect(ptp_slots[id].sock, (struct sockaddr*)&dest, sizeof(dest)) < 0) return -1;

    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(ptp_slots[id].sock, &wset);
    struct timeval tv;
    tv.tv_sec = timeout_us / 1000000;
    tv.tv_usec = timeout_us % 1000000;
    int nfds = ptp_slots[id].sock + 1;
    int sel = select(nfds, NULL, &wset, NULL, &tv);
    if (sel <= 0) return SCE_NET_ERROR_TIMEOUT;
    return 0;
}

int sceNetAdhocPtpListen(const SceNetEtherAddr src_mac, uint16_t src_port, int buf_size, int delay_us, int count, int queue, int unk1) {
    (void)src_mac; (void)delay_us; (void)count; (void)unk1;
    if (!adhoc_inited) return SCE_NET_ERROR_ADHOC_INIT;
    std::lock_guard<std::mutex> lk(ptp_lock);
    for (size_t i = 0; i < ptp_slots.size(); ++i) {
        if (!ptp_slots[i].used) {
            ptp_slots[i].used = true;
            ptp_slots[i].is_server = true;
            ptp_slots[i].peer_port = src_port;
            // Create server socket
            ptp_slots[i].sock = socket(AF_INET, SOCK_STREAM, 0);
            if (ptp_slots[i].sock < 0) {
                ptp_slots[i].used = false;
                return -1;
            }
            int opt = 1;
            setsockopt(ptp_slots[i].sock, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
            addr.sin_port = htons(src_port);
            if (bind(ptp_slots[i].sock, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
                listen(ptp_slots[i].sock, queue) < 0) {
                close(ptp_slots[i].sock);
                ptp_slots[i].used = false;
                return -1;
            }
            return (int)i;
        }
    }
    return -1;
}

int sceNetAdhocPtpAccept(int id, SceNetEtherAddr* mac, uint16_t* port, int timeout_us, int nonblock) {
    (void)nonblock;
    std::lock_guard<std::mutex> lk(ptp_lock);
    if (id < 0 || id >= (int)ptp_slots.size() || !ptp_slots[id].used || !ptp_slots[id].is_server) return -1;

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(ptp_slots[id].sock, &readfds);

    struct timeval tv;
    tv.tv_sec = timeout_us / 1000000;
    tv.tv_usec = timeout_us % 1000000;

    int nfds = ptp_slots[id].sock + 1;
    int r = select(nfds, &readfds, NULL, NULL, timeout_us > 0 ? &tv : NULL);
    if (r <= 0) return SCE_NET_ERROR_TIMEOUT;

    struct sockaddr_in client_addr;
    socklen_t clen = sizeof(client_addr);
    native_socket_t client_sock = accept(ptp_slots[id].sock, (struct sockaddr*)&client_addr, &clen);
    if (client_sock < 0) return -1;

    // Find free slot for client
    for (size_t i = 0; i < ptp_slots.size(); ++i) {
        if (!ptp_slots[i].used) {
            ptp_slots[i].sock = client_sock;
            ptp_slots[i].used = true;
            ptp_slots[i].is_server = false;
            ptp_slots[i].peer_ip = client_addr.sin_addr.s_addr;
            if (mac) memcpy(mac, global_mac, 6); // Sim
            if (port) *port = ntohs(client_addr.sin_port);
            return (int)i;
        }
    }
    close(client_sock);
    return -1;
}

int sceNetAdhocPtpSend(int id, const void* data, int* data_size, int timeout_us, int nonblock) {
    (void)timeout_us; (void)nonblock;
    std::lock_guard<std::mutex> lk(ptp_lock);
    if (id < 0 || id >= (int)ptp_slots.size() || !ptp_slots[id].used || !data || !data_size || *data_size <= 0) return -1;

    int sent = send(ptp_slots[id].sock, (const char*)data, *data_size, 0);
    if (sent < 0) return -1;
    *data_size = sent;
    return 0;
}

int sceNetAdhocPtpRecv(int id, void* data, int* data_size, int timeout_us, int nonblock) {
    (void)nonblock;
    std::lock_guard<std::mutex> lk(ptp_lock);
    if (id < 0 || id >= (int)ptp_slots.size() || !ptp_slots[id].used || !data || !data_size || *data_size <= 0) return -1;

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(ptp_slots[id].sock, &readfds);

    struct timeval tv;
    tv.tv_sec = timeout_us / 1000000;
    tv.tv_usec = timeout_us % 1000000;

    int nfds = ptp_slots[id].sock + 1;
    int r = select(nfds, &readfds, NULL, NULL, timeout_us > 0 ? &tv : NULL);
    if (r <= 0) return SCE_NET_ERROR_TIMEOUT;

    int recvd = recv(ptp_slots[id].sock, (char*)data, *data_size, 0);
    if (recvd < 0) return -1;
    *data_size = recvd;
    return 0;
}

int sceNetAdhocPtpClose(int id, int unk1) {
    (void)unk1;
    std::lock_guard<std::mutex> lk(ptp_lock);
    if (id < 0 || id >= (int)ptp_slots.size() || !ptp_slots[id].used) return -1;
    close(ptp_slots[id].sock);
    ptp_slots[id].used = false;
    return 0;
}

// Adhocctl (updated with more funcs, fixed min)
int sceNetAdhocctlInit(int stacksize, int priority, void* product) {
    (void)stacksize; (void)priority; (void)product;
    if (adhocctl_inited) return 0;
    if (!adhoc_inited) return SCE_NET_ERROR_ADHOC_INIT;
    adhocctl_inited = true;
    // Start scan thread
    scan_running = true;
    scan_thread = std::thread([]() {
        while (scan_running) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            // Simulate peer discovery - add random peers occasionally
            std::lock_guard<std::mutex> lk(peer_lock);
            if (peer_list.size() < 5) {
                SceNetAdhocctlPeerInfo p;
                p.next = nullptr;
                generate_random_mac(p.mac);
                snprintf(p.nickname, sizeof(p.nickname), "Peer%d", (int)peer_list.size());
                memset(p.unknown, 0, sizeof(p.unknown));
                p.timestamp = (unsigned long)std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                peer_list.push_back(p);
            }
        }
        });
    return 0;
}

int sceNetAdhocctlTerm(void) {
    if (!adhocctl_inited) return 0;
    adhocctl_inited = false;
    scan_running = false;
    if (scan_thread.joinable()) scan_thread.join();
    return 0;
}

int sceNetAdhocctlConnect(const char* name) {
    (void)name;
    return 0;
}

int sceNetAdhocctlDisconnect(void) {
    return 0;
}

int sceNetAdhocctlGetState(int* event) {
    if (!event) return -1;
    *event = 1; // Simulated connected
    return 0;
}

int sceNetAdhocctlCreate(const char* name) {
    (void)name;
    return 0;
}

int sceNetAdhocctlJoin(const SceNetAdhocctlScanInfo* scaninfo) {
    (void)scaninfo;
    return 0;
}

int sceNetAdhocctlGetPeerList(int* length, void* buf) {
    (void)length; (void)buf;
    return 0;
}

int sceNetAdhocctlGetPeerInfo(const SceNetEtherAddr mac, int size, SceNetAdhocctlPeerInfo* peerinfo) {
    (void)size;
    std::lock_guard<std::mutex> lk(peer_lock);
    for (const auto& p : peer_list) {
        if (memcmp(p.mac, mac, 6) == 0) {
            memcpy(peerinfo, &p, sizeof(SceNetAdhocctlPeerInfo));
            return 0;
        }
    }
    return -1;
}

int sceNetAdhocctlScan(void) {
    return 0; // Thread handles it
}

int sceNetAdhocctlGetScanInfo(int* length, void* buf) {
    if (!length || !buf) return -1;
    std::lock_guard<std::mutex> lk(peer_lock);
    size_t num = min(static_cast<size_t>(32), peer_list.size());  // Fixed: cast to avoid unknown-type
    *length = static_cast<int>(num * sizeof(SceNetAdhocctlScanInfo));
    SceNetAdhocctlScanInfo* scans = static_cast<SceNetAdhocctlScanInfo*>(buf);
    for (size_t i = 0; i < num; ++i) {
        scans[i].next = nullptr;
        scans[i].channel = 1 + static_cast<int>(i);
        snprintf(scans[i].name, sizeof(scans[i].name), "Scan%d", static_cast<int>(i));
        memcpy(scans[i].bssid, peer_list[i].mac, 6);
        memset(scans[i].unknown, 0, sizeof(scans[i].unknown));
        scans[i].unknown2 = 0;
    }
    return 0;
}

int sceNetAdhocctlAddHandler(void (*handler)(int, int, void*), void* unknown) {
    (void)handler; (void)unknown;
    return 0;
}

int sceNetAdhocctlDelHandler(int id) {
    (void)id;
    return 0;
}

int sceNetAdhocctlGetNameByAddr(const SceNetEtherAddr mac, char* nickname) {
    std::lock_guard<std::mutex> lk(peer_lock);
    for (const auto& p : peer_list) {
        if (memcmp(p.mac, mac, 6) == 0) {
            strncpy(nickname, p.nickname, 127);
            nickname[127] = 0;
            return 0;
        }
    }
    return -1;
}

int sceNetAdhocctlGetAddrByName(const char* nickname, int* length, void* buf) {
    (void)length; (void)buf; (void)nickname;
    return 0;
}

// Matching (simplified, updated sigs)
int sceNetAdhocMatchingInit(int memsize) {
    (void)memsize;
    if (!adhoc_inited) return SCE_NET_ERROR_ADHOC_INIT;
    return 0;
}

int sceNetAdhocMatchingTerm(void) {
    matching_ctxs.clear();
    return 0;
}

int sceNetAdhocMatchingCreate(int mode, int maxpeers, uint16_t port, int bufsize, uint32_t hellodelay, uint32_t pingdelay, int initcount, uint32_t msgdelay, void* callback) {
    (void)mode; (void)maxpeers; (void)port; (void)bufsize; (void)hellodelay; (void)pingdelay; (void)initcount; (void)msgdelay; (void)callback;
    std::lock_guard<std::mutex> lk(matching_lock);
    MatchingCtx ctx;
    ctx.id = static_cast<int>(matching_ctxs.size());
    matching_ctxs.push_back(ctx);
    return ctx.id;
}

int sceNetAdhocMatchingDelete(int matchingid) {
    std::lock_guard<std::mutex> lk(matching_lock);
    if (matchingid < 0 || matchingid >= static_cast<int>(matching_ctxs.size())) return -1;
    matching_ctxs[matchingid].active = false;
    return 0;
}

int sceNetAdhocMatchingStart(int matchingid, int evthpri, int evthstack, int inthpri, int inthstack, int optlen, void* optdata) {
    (void)evthpri; (void)evthstack; (void)inthpri; (void)inthstack; (void)optlen; (void)optdata;
    std::lock_guard<std::mutex> lk(matching_lock);
    if (matchingid < 0 || matchingid >= static_cast<int>(matching_ctxs.size())) return -1;
    matching_ctxs[matchingid].active = true;
    // Simulate targets
    matching_ctxs[matchingid].targets.resize(3); // Fake 3 targets
    for (int i = 0; i < 3; ++i) matching_ctxs[matchingid].targets[i] = i;
    return 0;
}

int sceNetAdhocMatchingStop(int matchingid) {
    std::lock_guard<std::mutex> lk(matching_lock);
    if (matchingid < 0 || matchingid >= static_cast<int>(matching_ctxs.size())) return -1;
    matching_ctxs[matchingid].active = false;
    return 0;
}

int sceNetAdhocMatchingSelectTarget(int matchingid, const SceNetEtherAddr mac, int optlen, void* optdata) {
    (void)mac; (void)optlen; (void)optdata;
    std::lock_guard<std::mutex> lk(matching_lock);
    if (matchingid < 0 || matchingid >= static_cast<int>(matching_ctxs.size()) || !matching_ctxs[matchingid].active || matching_ctxs[matchingid].targets.empty()) return -1;
    return 0;
}

int sceNetAdhocMatchingCancelTarget(int matchingid, const SceNetEtherAddr mac) {
    (void)mac;
    std::lock_guard<std::mutex> lk(matching_lock);
    if (matchingid < 0 || matchingid >= static_cast<int>(matching_ctxs.size())) return -1;
    return 0;
}

int sceNetAdhocMatchingSetHelloOpt(int matchingid, int optlen, void* optdata) {
    (void)matchingid; (void)optlen; (void)optdata;
    return 0;
}
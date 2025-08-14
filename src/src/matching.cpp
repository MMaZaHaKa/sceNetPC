// src/matching.cpp
// Full-ish port of PPSSPP's sceNetAdhocMatching subsystem (matching create/term/add/update).
// Integrates with adhoc_core peer list (NetAdhoc_AddFriend_Wrap / NetAdhoc_GetPeerList_Wrap)
// and uses PDP to send hello/keepalive messages. Provides realistic matching behaviour for games.

#include "ppsspp_adhoc.h"
#include "kernel_shim.h"
#include "socket_compat.h"

#include <thread>
#include <vector>
#include <mutex>
#include <atomic>
#include <cstring>
#include <chrono>
#include <map>
#include <cstdio>
#include <cstdlib>

#ifdef _WIN32
#include <winsock2.h>
#endif

// External C wrappers from adhoc_core / ptp / pdp
extern "C" {
    int NetAdhoc_AddFriend_Wrap(const uint8_t* mac, uint32_t ip_nbo, const char* nick);
    int NetAdhoc_GetPeerList_Wrap(void* outBuf, int maxEntries); // returns count
    int NetAdhoc_GetPeerCount_Wrap();

    int NetAdhocPdp_Create_Wrap(const char* mac, int port, int bufsz, uint32_t flag);
    int NetAdhocPdp_Delete_Wrap(int socketId);
    int NetAdhocPdp_Send_Wrap(int socketId, const char* destMac, uint16_t port, const void* data, int* len, uint32_t flag);
    int NetAdhocPdp_Recv_Wrap(int socketId, void* buf, int* len, int timeout_us);
    int NetAdhocPdp_RecvFrom_Wrap(int socketId, void* buf, int* len, int timeout_us, uint8_t outMac[6], uint16_t* outPort, uint32_t* outIp);
}

using namespace std::chrono_literals;

// ----- Matching subsystem design -----
//
// - Multiple matching slots (MAX_MATCHING). Each slot represents a matching session.
// - Each slot has:
//     - slot id (PSP-style id = index+1)
//     - a vector of members (mac + ip + port + nickname)
//     - a background thread that periodically sends hello/keepalive (via PDP) to members
//     - optional input thread to receive PDP messages destined to matching sockets (we reuse PDP slots if needed)
//
// - Public API:
//     sceNetAdhocMatchingCreate() -> returns matching id (>0) or negative error
//     sceNetAdhocMatchingTerm() -> frees all matching slots / global cleanup
//     sceNetAdhocMatchingAdd(matchingId, params) -> add a member (params: custom struct pointer or null)
//     sceNetAdhocMatchingUpdate(matchingId, params) -> update member/slot settings
//
// NOTE: params format is not strictly defined in our header; we accept a simple ABI:
//   params pointer expected to point to this struct (native code must pass matching info):
//   struct MatchingAddParams { uint8_t mac[6]; uint32_t ip_nbo; uint16_t port; char nickname[32]; uint32_t flags; };
//
// This keeps compatibility for many test/usage cases; if your PSP game expects exact PSP struct binary
// layout we can adjust later — currently we focus on behavior parity and API coverage.

// ---- Config ----
static const int MAX_MATCHING = 32;
static const int MAX_MEMBERS_PER_MATCH = 32;
static const int HEARTBEAT_MS = 1000;        // send hello every 1s
static const int MEMBER_TIMEOUT_MS = 5000;   // remove member if no heartbeat within 5s

// ---- Types ----
struct MatchingMember {
    uint8_t mac[6];
    uint32_t ip_nbo;   // network byte order
    uint16_t port;
    char nickname[32];
    uint64_t last_seen_us; // microseconds timestamp
    uint32_t flags;
};

struct MatchingSlot {
    std::atomic<bool> used{ false };
    std::mutex lock;
    int id; // index+1
    std::vector<MatchingMember> members;
    std::thread worker;
    std::atomic<bool> running{ false };
    // For sending hello/msgs, create a dedicated PDP socket per matching slot (as PPSSPP sometimes does)
    int pdp_socket_id; // >0 if created
    int local_port; // bound port for pdp socket
    // matching metadata
    uint32_t match_flags;
    char match_name[64];
};

static MatchingSlot g_matching_slots[MAX_MATCHING];
static std::mutex g_matching_global_lock;
static std::atomic<bool> g_matching_inited{ false };

// matching params expected by Add/Update (user-provided)
struct MatchingAddParams {
    uint8_t mac[6];
    uint32_t ip_nbo;
    uint16_t port;
    char nickname[32];
    uint32_t flags;
};

// Utility: find free matching slot
static int find_free_matching_slot() {
    for (int i = 0; i < MAX_MATCHING; ++i) {
        bool used = g_matching_slots[i].used.load();
        if (!used) return i;
    }
    return -1;
}

// Utility: get microseconds
static uint64_t now_us() {
    return ks_time_ms() * 1000;
}

// Send a small hello packet to member via PDP (packet format simple: "MATCH_HELLO:<nick>\0")
static int send_hello_to_member(int pdp_socket_id, const MatchingMember& m) {
    // Build payload
    char payload[256];
    int plen = snprintf(payload, sizeof(payload), "MATCH_HELLO:%s", m.nickname);
    if (plen <= 0) plen = 0;
    int sendlen = plen + 1;
    // destMac: we pass 6 bytes — first 4 bytes ip_nbo, last two zeros
    char destMac[6];
    memcpy(destMac, &m.ip_nbo, 4);
    destMac[4] = 0; destMac[5] = 0;
    int res = NetAdhocPdp_Send_Wrap(pdp_socket_id, destMac, m.port, payload, &sendlen, 0);
    if (res < 0) {
        LOG("[matching] hello send failed to %02x:%02x:%02x:%02x:%02x:%02x (ip=%s:%d) res=%d",
            m.mac[0], m.mac[1], m.mac[2], m.mac[3], m.mac[4], m.mac[5],
            inet_ntoa(*(struct in_addr*)&m.ip_nbo), m.port, res);
    }
    else {
        //LOG("[matching] sent hello to %s (%s:%d) len=%d", m.nickname, inet_ntoa(*(struct in_addr*)&m.ip_nbo), m.port, sendlen);
    }
    return res;
}

// Worker thread for a matching slot
static void matching_worker_func(MatchingSlot* slot) {
    if (!slot) return;
    LOG("[matching] slot %d worker started", slot->id);
    slot->running = true;

    // create a PDP socket for this slot (use ephemeral port 0)
    // name mac: derive a mac from slot id? We'll just provide nullptr to get local MAC.
    int pdp_socket = NetAdhocPdp_Create_Wrap(nullptr, 0, 1500, 0);
    if (pdp_socket <= 0) {
        LOG("[matching] slot %d: failed to create internal PDP socket (%d)", slot->id, pdp_socket);
        slot->pdp_socket_id = -1;
    }
    else {
        slot->pdp_socket_id = pdp_socket;
        LOG("[matching] slot %d: created PDP socket id=%d", slot->id, pdp_socket);
    }

    // We'll use a simple loop: every HEARTBEAT_MS iterate members, send hello to each,
    // and check for timed-out members and remove them.
    uint64_t last_heartbeat = now_us();
    while (slot->running) {
        uint64_t tnow = now_us();
        if (tnow - last_heartbeat >= (uint64_t)HEARTBEAT_MS * 1000ULL) {
            // Copy members under lock to avoid holding lock while sending network ops
            std::vector<MatchingMember> membersCopy;
            {
                std::lock_guard<std::mutex> lk(slot->lock);
                membersCopy = slot->members;
            }

            // Send hello to each
            for (auto& m : membersCopy) {
                if (slot->pdp_socket_id > 0) {
                    send_hello_to_member(slot->pdp_socket_id, m);
                }
            }

            // cleanup stale members
            {
                std::lock_guard<std::mutex> lk(slot->lock);
                uint64_t nowu = now_us();
                for (auto it = slot->members.begin(); it != slot->members.end();) {
                    if ((nowu - it->last_seen_us) > (uint64_t)MEMBER_TIMEOUT_MS * 1000ULL) {
                        LOG("[matching] slot %d: removing stale member %s", slot->id, it->nickname);
                        it = slot->members.erase(it);
                    }
                    else ++it;
                }
            }

            last_heartbeat = tnow;
        }

        // Poll incoming messages on slot PDP socket (nonblocking wait)
        if (slot->pdp_socket_id > 0) {
            // try recv with small timeout (100 ms)
            char buf[2048];
            int buflen = sizeof(buf);
            //int r = NetAdhocPdp_Recv_Wrap(slot->pdp_socket_id, buf, &buflen, 100000); // 100ms
            uint8_t srcmac[6];
            uint16_t srcport = 0;
            uint32_t srcip = 0;
            int r = NetAdhocPdp_RecvFrom_Wrap(slot->pdp_socket_id, buf, &buflen, 100000, srcmac, &srcport, &srcip);
            if (r > 0) {
                buf[buflen] = '\0';
                // update matching member by ip/mac
                {
                    std::lock_guard<std::mutex> lk(slot->lock);
                    for (auto& m : slot->members) {
                        if (m.ip_nbo == srcip || memcmp(m.mac, srcmac, 6) == 0) {
                            m.last_seen_us = now_us();
                            break;
                        }
                    }
                }

                // crude parsing: if message starts with "MATCH_HELLO:" extract nick and update member table
                const char* prefix = "MATCH_HELLO:";
                if (strncmp(buf, prefix, strlen(prefix)) == 0) {
                    const char* nick = buf + strlen(prefix);
                    // We do not know source ip/mac from this simplified receive wrapper; best we can do is log.
                    LOG("[matching] slot %d: received hello '%s' (len=%d) - updating peer list", slot->id, nick, buflen);
                    // If we could get sender IP/MAC we would update that member's last_seen_us. For now rely on external NetAdhoc_AddFriend calls.
                }
                else {
                    LOG("[matching] slot %d: recv unhandled msg: '%s'", slot->id, buf);
                }
            }
        }

        // Sleep a bit to avoid busy loop
        ks_sleep_ms(50);
    }

    // cleanup
    if (slot->pdp_socket_id > 0) {
        NetAdhocPdp_Delete_Wrap(slot->pdp_socket_id);
        slot->pdp_socket_id = -1;
    }

    slot->running = false;
    LOG("[matching] slot %d worker exiting", slot->id);
}

// Public API implementations

extern "C" {

    // Create a matching slot. Returns matchingId (>0) or negative error.
    ADHOCPP_API int sceNetAdhocMatchingCreate() {
        if (!g_matching_inited.load()) {
            std::lock_guard<std::mutex> g(g_matching_global_lock);
            if (!g_matching_inited.load()) {
                // initialize all slots
                for (int i = 0; i < MAX_MATCHING; ++i) {
                    g_matching_slots[i].used = false;
                    g_matching_slots[i].pdp_socket_id = -1;
                    g_matching_slots[i].id = i + 1;
                    g_matching_slots[i].match_flags = 0;
                    g_matching_slots[i].match_name[0] = '\0';
                }
                g_matching_inited = true;
            }
        }

        std::lock_guard<std::mutex> g(g_matching_global_lock);
        int idx = find_free_matching_slot();
        if (idx < 0) return -1; // no free slot
        MatchingSlot& slot = g_matching_slots[idx];
        slot.used = true;
        slot.members.clear();
        slot.match_flags = 0;
        snprintf(slot.match_name, sizeof(slot.match_name), "match-%d", idx + 1);
        slot.running = true;
        // start worker thread
        slot.worker = std::thread(matching_worker_func, &slot);
        // detach? we'll join on Term; keep thread joinable
        LOG("[matching] created slot id=%d", slot.id);
        return idx + 1;
    }

    // Terminate all matching slots (global)
    ADHOCPP_API int sceNetAdhocMatchingTerm() {
        std::lock_guard<std::mutex> g(g_matching_global_lock);
        if (!g_matching_inited.load()) return 0;
        // Stop threads and free slots
        for (int i = 0; i < MAX_MATCHING; ++i) {
            MatchingSlot& slot = g_matching_slots[i];
            if (slot.used) {
                slot.running = false;
                if (slot.worker.joinable()) slot.worker.join();
                slot.members.clear();
                slot.used = false;
                slot.pdp_socket_id = -1;
                LOG("[matching] terminated slot id=%d", slot.id);
            }
        }
        g_matching_inited = false;
        return 0;
    }

    // Add a new member to matching slot. params can be nullptr to indicate use of external peer list
    // We accept a user-provided structure MatchingAddParams for convenience.
    ADHOCPP_API int sceNetAdhocMatchingAdd(int matchingId, const void* params) {
        if (!g_matching_inited.load()) return -1;
        int idx = matchingId - 1;
        if (idx < 0 || idx >= MAX_MATCHING) return -1;
        MatchingSlot& slot = g_matching_slots[idx];
        if (!slot.used) return -1;

        std::lock_guard<std::mutex> lk(slot.lock);
        if (params == nullptr) {
            // if no params, add all peers from global peerlist into matching slot (up to capacity)
            // Use NetAdhoc_GetPeerList_Wrap to fetch peers
            const int MAX_PEERS = 64;
            // temporary buffer uses the same layout used earlier (SceNetAdhocctlPeerInfoEmu)
            struct PeerInfoEmuLocal {
                uint32_t next;
                uint8_t mac[6];
                uint8_t pad[2];
                uint32_t ip_addr;
                uint32_t flags;
                uint64_t last_recv;
                char nickname[32];
            } peers[MAX_PEERS];
            int got = NetAdhoc_GetPeerList_Wrap(peers, MAX_PEERS);
            int added = 0;
            for (int i = 0; i < got && (int)slot.members.size() < MAX_MEMBERS_PER_MATCH; ++i) {
                MatchingMember mm;
                memset(&mm, 0, sizeof(mm));
                memcpy(mm.mac, peers[i].mac, 6);
                mm.ip_nbo = peers[i].ip_addr;
                mm.port = 4444; // default adhoc port guess; games often use specified port - may need adjusting
                strncpy(mm.nickname, peers[i].nickname, sizeof(mm.nickname) - 1);
                mm.last_seen_us = peers[i].last_recv;
                slot.members.push_back(mm);
                ++added;
            }
            LOG("[matching] slot %d: added %d peers from global peer list", slot.id, added);
            return added;
        }
        else {
            // parse params as MatchingAddParams
            MatchingAddParams mp;
            memcpy(&mp, params, sizeof(MatchingAddParams));
            // validate
            if (slot.members.size() >= MAX_MEMBERS_PER_MATCH) return -2;
            // add or update existing member by MAC
            for (auto& m : slot.members) {
                if (memcmp(m.mac, mp.mac, 6) == 0) {
                    // update details
                    m.ip_nbo = mp.ip_nbo;
                    m.port = mp.port;
                    strncpy(m.nickname, mp.nickname, sizeof(m.nickname) - 1);
                    m.flags = mp.flags;
                    m.last_seen_us = now_us();
                    LOG("[matching] slot %d: updated member %s", slot.id, m.nickname);
                    return 0;
                }
            }
            // new member
            MatchingMember mm;
            memcpy(mm.mac, mp.mac, 6);
            mm.ip_nbo = mp.ip_nbo;
            mm.port = mp.port;
            strncpy(mm.nickname, mp.nickname, sizeof(mm.nickname) - 1);
            mm.flags = mp.flags;
            mm.last_seen_us = now_us();
            slot.members.push_back(mm);
            // Also register member in global peer list so PDP/PTP can resolve it
            NetAdhoc_AddFriend_Wrap(mp.mac, mp.ip_nbo, mp.nickname);
            LOG("[matching] slot %d: added member %s", slot.id, mm.nickname);
            return 0;
        }
    }

    // Update matching slot config (simple set flags / name)
    struct MatchingUpdateParams {
        uint32_t match_flags;
        char match_name[64];
    };
    ADHOCPP_API int sceNetAdhocMatchingUpdate(int matchingId, const void* params) {
        if (!g_matching_inited.load()) return -1;
        if (!params) return -2;
        int idx = matchingId - 1;
        if (idx < 0 || idx >= MAX_MATCHING) return -1;
        MatchingSlot& slot = g_matching_slots[idx];
        if (!slot.used) return -1;
        MatchingUpdateParams mup;
        memcpy(&mup, params, sizeof(mup));
        std::lock_guard<std::mutex> lk(slot.lock);
        slot.match_flags = mup.match_flags;
        strncpy(slot.match_name, mup.match_name, sizeof(slot.match_name) - 1);
        LOG("[matching] slot %d: updated flags=0x%08x name=%s", slot.id, slot.match_flags, slot.match_name);
        return 0;
    }

} // extern "C"


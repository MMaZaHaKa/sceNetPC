// src/lib_extras.cpp
// Implement "extra" sceNetAdhoc functions that were stubs or missing.
// These functions are thin wrappers / small helpers that integrate existing modules.

#include "ppsspp_adhoc.h"
#include "kernel_shim.h"
#include <cstring>
#include <map>
#include <mutex>
#include <array>

#ifdef __cplusplus
extern "C" {
#endif

    // We rely on existing wrappers from adhoc_core and matching/discover modules:
    int NetAdhoc_GetPeerList_Wrap(void* outBuf, int maxEntries);
    int NetAdhoc_GetPeerCount_Wrap();
    int NetAdhoc_AddFriend_Wrap(const uint8_t* mac, uint32_t ip_nbo, const char* nick);

    int sceNetAdhocMatchingCreate();
    int sceNetAdhocMatchingTerm();
    int sceNetAdhocMatchingAdd(int matchingId, const void* params);
    int sceNetAdhocDiscoverStart();
    int sceNetAdhocDiscoverStop();
    int sceNetAdhocctlInit(int stackSize, int prio, uint32_t productAddr);
    int sceNetAdhocctlTerm();

#ifdef __cplusplus
}
#endif

// Local bookkeeping for selectTarget per matching slot
static std::mutex g_target_lock;
static std::map<int, std::array<uint8_t, 6>> g_matching_targets;

// Implementations

extern "C" {

    // Alias: create/init matching (returns matchingId)
    ADHOCPP_API int sceNetAdhocMatchingInit() {
        return sceNetAdhocMatchingCreate();
    }

    // Select a target (store into local map) so later calls can use it.
    // This does not perform network actions by itself.
    ADHOCPP_API int sceNetAdhocMatchingSelectTarget(int matchingId, const uint8_t mac[6]) {
        if (!mac) return -1;
        std::lock_guard<std::mutex> lk(g_target_lock);
        std::array<uint8_t, 6> arr;
        memcpy(arr.data(), mac, 6);
        g_matching_targets[matchingId] = arr;
        LOG("[lib_extras] selected target for matching %d -> %02x:%02x:%02x:%02x:%02x:%02x",
            matchingId, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return 0;
    }

    ADHOCPP_API int sceNetAdhocMatchingCancelTarget(int matchingId) {
        std::lock_guard<std::mutex> lk(g_target_lock);
        auto it = g_matching_targets.find(matchingId);
        if (it != g_matching_targets.end()) {
            g_matching_targets.erase(it);
            LOG("[lib_extras] canceled target for matching %d", matchingId);
        }
        return 0;
    }

    // Adhocctl scan -> start discover (best-effort)
    ADHOCPP_API int sceNetAdhocctlScan() {
        LOG("[lib_extras] sceNetAdhocctlScan -> starting discover");
        return sceNetAdhocDiscoverStart();
    }

    // Add handler: store pointer if needed; for now just log and return success.
    ADHOCPP_API int sceNetAdhocctlAddHandler(void* handler) {
        LOG("[lib_extras] sceNetAdhocctlAddHandler handler=%p (noop)", handler);
        (void)handler;
        return 0;
    }

    // Create control object - alias to init for simplicity
    ADHOCPP_API int sceNetAdhocctlCreate(int stackSize, int prio, uint32_t productAddr) {
        return sceNetAdhocctlInit(stackSize, prio, productAddr);
    }

    // Get name by addr: search peer list by mac and copy nickname to out buffer.
    ADHOCPP_API int sceNetAdhocctlGetNameByAddr(const uint8_t mac[6], char* out, int out_len) {
        if (!mac || !out || out_len <= 0) return -1;
        //const int MAX_PEERS = 64;
        //struct PeerInfoLocal {
        //    uint32_t next;
        //    uint8_t mac[6];
        //    uint8_t pad[2];
        //    uint32_t ip_addr;
        //    uint32_t flags;
        //    uint64_t last_recv;
        //    char nickname[32];
        //} peers[MAX_PEERS];
        PeerInfoEmuLocal peers[MAX_PEERS];

        int got = NetAdhoc_GetPeerList_Wrap((void*)peers, MAX_PEERS);
        for (int i = 0; i < got; ++i) {
            if (memcmp(peers[i].mac, mac, 6) == 0) {
                strncpy(out, peers[i].nickname, out_len - 1);
                out[out_len - 1] = '\0';
                return 0;
            }
        }
        // not found
        out[0] = '\0';
        return -1;
    }

    // sceNetAdhocctlGetScanInfo:
    //  out - pointer to an array of PeerInfoEmuLocal (see your header)
    //  size - number of entries space available (in elements)
    //  returns number of filled entries (>=0). On error returns negative.
    ADHOCPP_API int sceNetAdhocctlGetScanInfo(void* out, int size) {
        if (!out || size <= 0) return -1;
        // We will call the internal peer list wrapper to fill local array
        // NetAdhoc_GetPeerList_Wrap expects SceNetAdhocctlPeerInfoEmu, which is binary-compatible
        // with PeerInfoEmuLocal in your header (we used same layout earlier).
        const int MAXQ = (size > MAX_PEERS) ? MAX_PEERS : size;
        // Use the runtime wrapper to fetch peers
        // NetAdhoc_GetPeerList_Wrap takes SceNetAdhocctlPeerInfoEmu*; we used same layout earlier.
        int got = NetAdhoc_GetPeerList_Wrap(out, MAXQ);
        if (got < 0) return -2;
        // If the out buffer was larger than the returned count, zero the rest of nicknames to be safe
        if (got < size) {
            // zero remaining entries' nickname just in case
            PeerInfoEmuLocal* arr = (PeerInfoEmuLocal*)out;
            for (int i = got; i < size; ++i) {
                arr[i].next = 0;
                memset(arr[i].mac, 0, sizeof(arr[i].mac));
                arr[i].ip_addr = 0;
                arr[i].flags = 0;
                arr[i].last_recv = 0;
                arr[i].nickname[0] = '\0';
            }
        }
        return got;
    }


} // extern "C"

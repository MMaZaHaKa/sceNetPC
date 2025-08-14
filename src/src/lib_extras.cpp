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

    // Start matching: currently a lightweight no-op (matching worker already created at create time).
    ADHOCPP_API int sceNetAdhocMatchingStart(int matchingId) {
        LOG("[lib_extras] sceNetAdhocMatchingStart id=%d (noop)", matchingId);
        (void)matchingId;
        return 0;
    }

    // Stop matching: no-op placeholder (matchingTerm will fully stop)
    ADHOCPP_API int sceNetAdhocMatchingStop(int matchingId) {
        LOG("[lib_extras] sceNetAdhocMatchingStop id=%d (noop)", matchingId);
        (void)matchingId;
        return 0;
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

    // Delete a single matching slot - we don't have per-slot delete in matching.cpp, so signal Term if id==all.
    // To avoid destroying everything unexpectedly, we'll implement delete as Term if matchingId==0 (special),
    // otherwise attempt to stop slot by calling Term then recreating remaining slots is complex - so return not implemented for now.
    ADHOCPP_API int sceNetAdhocMatchingDelete(int matchingId) {
        if (matchingId == 0) {
            sceNetAdhocMatchingTerm();
            return 0;
        }
        LOG("[lib_extras] sceNetAdhocMatchingDelete id=%d -> not fully implemented (use Term)", matchingId);
        return -1;
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

    // Get scan info: not implemented in full, return 0
    ADHOCPP_API int sceNetAdhocctlGetScanInfo(void* out, int size) {
        (void)out; (void)size;
        LOG("[lib_extras] sceNetAdhocctlGetScanInfo (stub)");
        return 0;
    }


} // extern "C"

// src/adhocctl.cpp
// ���������� sceNetAdhocctl* �� ���� internal peer-list (adhoc_core).
// ��������� ������ � PPSSPP: fake friendFinder thread, state machine, GetPeerList.

#include "ppsspp_adhoc.h"
#include "kernel_shim.h"
#include <thread>
#include <atomic>
#include <vector>
#include <cstring>
#include <chrono>
#include <cstdio>

#ifdef _WIN32
#include <winsock2.h>
#endif

// ������� �������� (�� adhoc_core.cpp)
extern "C" {
    int NetAdhoc_AddFriend_Wrap(const uint8_t* mac, uint32_t ip_nbo, const char* nick);
    int NetAdhoc_GetPeerList_Wrap(void* outBuf, int maxEntries); // outBuf -> SceNetAdhocctlPeerInfoEmu*
    int NetAdhoc_GetPeerCount_Wrap();
}

// ������������ ��������� adhocctl (����� ������ �� PPSSPP)
enum AdhocctlState {
    ADHOCCTL_STATE_NONE = 0,
    ADHOCCTL_STATE_CONNECTING,
    ADHOCCTL_STATE_CONNECTED,
    ADHOCCTL_STATE_DISCONNECTING,
    ADHOCCTL_STATE_DISCONNECTED
};

// ���������� ���������� ��������� (�������� PPSSPP)
static std::atomic<int> g_adhocctl_state{ ADHOCCTL_STATE_NONE };
static std::atomic<bool> g_friendFinderRunning{ false };
static std::thread g_friendFinderThread;
static std::atomic<bool> g_netAdhocctlInited{ false };

// ������� ���������� "friend finder" � ������������ ��������� loopback peer (��� ������) � ��������� timestamps.
// PPSSPP ������ ��� �������; ��� � ���������, ����������� ��� ���.
static void friendFinderThreadFunc() {
    g_friendFinderRunning = true;
    LOG("[adhocctl] friendFinder thread started");
    while (g_netAdhocctlInited.load()) {
        // Emulate discovery of local peers: add a loopback entry and refresh its timestamp
        uint32_t ip_nbo = inet_addr("127.0.0.1");
        uint8_t mac[6] = { 0 };
        memcpy(mac, &ip_nbo, 4);
        mac[4] = 0; mac[5] = 1;
        NetAdhoc_AddFriend_Wrap(mac, ip_nbo, "LocalPeer");

        // Sleep a bit (PPSSPP uses micro-delays / events). Keep it modest.
        ks_sleep_ms(500);
    }
    LOG("[adhocctl] friendFinder thread exiting");
    g_friendFinderRunning = false;
}

// �������� API: sceNetAdhocctlInit / Term / Connect / Disconnect / GetState / GetPeerList

extern "C" {

    // stackSize / prio / productAddr � ��������� PSP, ��� �� ���� ������������.
    // ���������� 0 ��� ������, ������ ��� � PPSSPP (� ����� ������ ���������� ���������).
    ADHOCPP_API int sceNetAdhocctlInit(int stackSize, int prio, uint32_t productAddr) {
        LOG("[adhocctl] sceNetAdhocctlInit(stack=%d, prio=%d, productAddr=0x%08x)", stackSize, prio, productAddr);
        if (g_netAdhocctlInited.load()) {
            LOG("[adhocctl] already inited");
            return 0; // PPSSPP ������ ���������� ALREADY_INITIALIZED error; many games expect 0 � emulate success
        }
        g_netAdhocctlInited = true;
        g_adhocctl_state = ADHOCCTL_STATE_CONNECTED; // emulate already connected / ready state

        // start friendFinder thread
        if (!g_friendFinderRunning.load()) {
            g_friendFinderThread = std::thread(friendFinderThreadFunc);
            // give it a moment to start
            ks_sleep_ms(10);
        }
        LOG("[adhocctl] initialized");
        return 0;
    }

    ADHOCPP_API int sceNetAdhocctlTerm() {
        LOG("[adhocctl] sceNetAdhocctlTerm()");
        if (!g_netAdhocctlInited.load()) return 0;
        // stop background thread
        g_netAdhocctlInited = false;
        if (g_friendFinderThread.joinable()) g_friendFinderThread.join();
        g_friendFinderRunning = false;
        g_adhocctl_state = ADHOCCTL_STATE_NONE;
        LOG("[adhocctl] terminated");
        return 0;
    }

    // Connect to adhoc group (groupName) � we emulate an immediate success.
    // Returns 0 success, or error code if invalid arg.
    ADHOCPP_API int sceNetAdhocctlConnect(const char* groupName) {
        if (!g_netAdhocctlInited.load()) return -1;
        if (!groupName) return -2;
        LOG("[adhocctl] sceNetAdhocctlConnect('%s')", groupName);
        g_adhocctl_state = ADHOCCTL_STATE_CONNECTING;
        // emulate some network operations / delay
        ks_sleep_ms(50);
        g_adhocctl_state = ADHOCCTL_STATE_CONNECTED;
        return 0;
    }

    // Disconnect (emulated)
    ADHOCPP_API int sceNetAdhocctlDisconnect() {
        if (!g_netAdhocctlInited.load()) return -1;
        LOG("[adhocctl] sceNetAdhocctlDisconnect()");
        g_adhocctl_state = ADHOCCTL_STATE_DISCONNECTING;
        ks_sleep_ms(20);
        g_adhocctl_state = ADHOCCTL_STATE_DISCONNECTED;
        return 0;
    }

    ADHOCPP_API int sceNetAdhocctlGetState(uint32_t ptrToStatus) {
        (void)ptrToStatus;
        // In our simple bridge we return state as integer
        int st = (int)g_adhocctl_state.load();
        LOG("[adhocctl] sceNetAdhocctlGetState() -> %d", st);
        return st;
    }

    // �������� ������ �����. outBuf � ��������� �� ������ SceNetAdhocctlPeerInfoEmu, maxEntries � capacity (���������� ���������).
    // ���������� ����� ���������� ��������� ��� ������ (<0).
    ADHOCPP_API int sceNetAdhocctlGetPeerList(void* outBuf, int maxEntries) {
        if (!g_netAdhocctlInited.load()) return -1;
        if (!outBuf || maxEntries <= 0) return -2;
        int got = NetAdhoc_GetPeerList_Wrap(outBuf, maxEntries);
        LOG("[adhocctl] sceNetAdhocctlGetPeerList -> %d peers", got);
        return got;
    }

} // extern "C"

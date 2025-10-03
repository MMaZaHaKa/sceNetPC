// File: src/main.cpp
#include "../include/sceNetAdhoc.h"
#include <cstdio>
#include <cstring>
#include <chrono>
#include <thread>

int main() {
    printf("=== SCE Net Adhoc Test Start ===\n");

    // Custom setup
    SceNetEtherAddr my_mac;
    sceNetSetRandomMacAddr(my_mac);
    char mac_str[18];
    sceNetEtherNtostr(my_mac, mac_str);
    printf("Custom Random MAC: %s\n", mac_str);

    sceNetSetNickname("TestPCPlayer");
    printf("Custom Nickname: TestPCPlayer\n");

    // Init net (with defaults)
    if (sceNetInit(0x10000, 0x20, 0x1000, 0x20, 0x1000) != 0) {
        printf("sceNetInit failed\n");
        return 1;
    }
    printf("sceNetInit OK\n");

    // Init adhoc
    if (sceNetAdhocInit() != 0) {
        printf("sceNetAdhocInit failed\n");
        sceNetTerm();
        return 2;
    }
    printf("sceNetAdhocInit OK\n");

    // Init adhocctl (product null for sim)
    if (sceNetAdhocctlInit(0x2000, 0x30, nullptr) != 0) {
        printf("sceNetAdhocctlInit failed\n");
        goto cleanup;
    }
    printf("sceNetAdhocctlInit OK\n");

    // Scan for peers
    sceNetAdhocctlScan();
    std::this_thread::sleep_for(std::chrono::seconds(3)); // Let scan thread run

    // Get scan info (use buf for list)
    int scan_len = 32 * sizeof(SceNetAdhocctlScanInfo);
    char scan_buf[1024]; // Enough for 32
    if (sceNetAdhocctlGetScanInfo(&scan_len, scan_buf) == 0) {
        SceNetAdhocctlScanInfoList* list = reinterpret_cast<SceNetAdhocctlScanInfoList*>(scan_buf);
        printf("Scan Info: %d results\n", list->num_results);
        for (int i = 0; i < list->num_results; ++i) {
            char bssid_str[18];
            sceNetEtherNtostr(list->results[i].bssid, bssid_str);
            printf("Scan %d: Channel %d, Name %s, BSSID %s\n", i, list->results[i].channel, list->results[i].name, bssid_str);
        }
    }
    else {
        printf("sceNetAdhocctlGetScanInfo failed\n");
    }

    // Test PDP (UDP)
    printf("\n--- PDP Test ---\n");
    SceNetEtherAddr pdp_mac;
    memcpy(pdp_mac, my_mac, 6);
    int pdp_id = sceNetAdhocPdpCreate(pdp_mac, 10010, 1500, 0);
    if (pdp_id >= 0) {
        printf("PDP Create OK, ID: %d\n", pdp_id);

        // Send to self (loopback)
        const char* msg = "Hello PDP from PC!";
        int len = static_cast<int>(strlen(msg) + 1);
        SceNetEtherAddr dest_mac;
        memcpy(dest_mac, my_mac, 6); // Self
        int sent = sceNetAdhocPdpSend(pdp_id, dest_mac, 10010, msg, len, 0, 0);
        if (sent > 0) {
            printf("PDP Send OK, sent: %d bytes\n", sent);
        }
        else {
            printf("PDP Send failed: %d\n", sent);
        }

        // Recv
        char recv_buf[2048];
        int recv_len = sizeof(recv_buf);
        SceNetEtherAddr src_mac;
        uint16_t src_port = 0;
        int recvd = sceNetAdhocPdpRecv(pdp_id, src_mac, &src_port, recv_buf, &recv_len, 2000000, 0);
        if (recvd > 0) {
            printf("PDP Recv OK: %s (from port %d)\n", recv_buf, src_port);
        }
        else {
            printf("PDP Recv failed: %d\n", recvd);
        }

        sceNetAdhocPdpDelete(pdp_id, 0);
    }
    else {
        printf("PDP Create failed: %d\n", pdp_id);
    }

    // Test PTP (TCP) - using proper funcs now
    printf("\n--- PTP Test ---\n");
    // Listen (server)
    int listen_id = sceNetAdhocPtpListen(my_mac, 12345, 4096, 1000000, 5, 5, 0);
    if (listen_id >= 0) {
        printf("PTP Listen OK, ID: %d\n", listen_id);

        // Open (client) to self sim
        int open_id = sceNetAdhocPtpOpen(my_mac, 12346, my_mac, 12345, 4096, 1000000, 5, 0);
        if (open_id >= 0) {
            if (sceNetAdhocPtpConnect(open_id, 1000000, 0) == 0) {
                printf("PTP Connect OK\n");
            }
            else {
                printf("PTP Connect failed\n");
            }

            // Accept on server
            SceNetEtherAddr accept_mac;
            uint16_t accept_port = 0;
            int accept_id = sceNetAdhocPtpAccept(listen_id, &accept_mac, &accept_port, 1000000, 0);
            if (accept_id >= 0) {
                printf("PTP Accept OK, Client ID: %d, Port: %d\n", accept_id, accept_port);

                // Send from client to server
                const char* ptp_msg = "Hello PTP from PC!";
                int ptp_len = static_cast<int>(strlen(ptp_msg) + 1);
                if (sceNetAdhocPtpSend(open_id, ptp_msg, &ptp_len, 1000000, 0) == 0) {
                    printf("PTP Send OK: %d bytes\n", ptp_len);
                }

                // Recv on server
                char ptp_buf[2048];
                int ptp_recv_len = sizeof(ptp_buf);
                if (sceNetAdhocPtpRecv(accept_id, ptp_buf, &ptp_recv_len, 1000000, 0) == 0) {
                    printf("PTP Recv OK: %s\n", ptp_buf);
                }
                else {
                    printf("PTP Recv timeout (expected if no send)\n");
                }

                sceNetAdhocPtpClose(accept_id, 0);
            }
            sceNetAdhocPtpClose(open_id, 0);
        }
        sceNetAdhocPtpClose(listen_id, 0);
    }
    else {
        printf("PTP Listen failed: %d\n", listen_id);
    }

    // Test Matching (sim)
    printf("\n--- Matching Test ---\n");
    if (sceNetAdhocMatchingInit(0x20000) == 0) {
        int match_id = sceNetAdhocMatchingCreate(1, 4, 555, 1024, 1000000, 60000000, 3, 1000000, nullptr);
        if (match_id >= 0) {
            printf("Matching Create OK, ID: %d\n", match_id);

            if (sceNetAdhocMatchingStart(match_id, 0x10, 0x2000, 0x10, 0x2000, 0, nullptr) == 0) {
                printf("Matching Start OK\n");
                std::this_thread::sleep_for(std::chrono::seconds(1));

                SceNetEtherAddr target_mac;
                memcpy(target_mac, my_mac, 6);
                if (sceNetAdhocMatchingSelectTarget(match_id, target_mac, 0, nullptr) == 0) {
                    printf("Matching Select Target OK\n");
                    sceNetAdhocMatchingCancelTarget(match_id, target_mac);
                }

                sceNetAdhocMatchingStop(match_id);
            }

            sceNetAdhocMatchingDelete(match_id);
        }
        sceNetAdhocMatchingTerm();
    }
    else {
        printf("Matching Init failed\n");
    }

    // Adhocctl group ops
    printf("\n--- Adhocctl Group Test ---\n");
    if (sceNetAdhocctlCreate("TestGroup") == 0) {
        printf("Adhocctl Create OK\n");
    }
    if (sceNetAdhocctlConnect("TestGroup") == 0) {
        printf("Adhocctl Connect OK\n");
        char name_buf[128];
        if (sceNetAdhocctlGetNameByAddr(my_mac, name_buf) == 0) {
            printf("Get Name OK: %s\n", name_buf);
        }
        sceNetAdhocctlDisconnect();
    }

    int state;
    if (sceNetAdhocctlGetState(&state) == 0) {
        printf("State: %d\n", state);
    }

cleanup:
    sceNetAdhocctlTerm();
    sceNetAdhocTerm();
    sceNetTerm();
    printf("=== Test Done ===\n");
    return 0;
}
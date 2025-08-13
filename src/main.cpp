#include "src/ppsspp_adhoc.h"
#include "src/socket_compat.h" // <- добавлено, содержит winsock/posix includes
#include <cstdio>
#include <cstring>
#include <thread>

int main() {
    printf("adhoc test start\n");
    if (sceNetAdhocInit() != 0) {
        printf("init failed\n");
        return 1;
    }

    uint8_t mymac[6] = { 0 };
    int recvPort = 10010;
    int sendPort = 10011;

    int rcv = sceNetAdhocPdpCreate(mymac, recvPort, 1500, 0);
    if (rcv <= 0) { printf("pdp create recv failed %d\n", rcv); return 2; }
    printf("rcv id=%d\n", rcv);

    int snd = sceNetAdhocPdpCreate(mymac, sendPort, 1500, 0);
    if (snd <= 0) { printf("pdp create snd failed %d\n", snd); return 3; }
    printf("snd id=%d\n", snd);

    // prepare destination MAC = 127.0.0.1 in network byte order (inet_addr returns nbo)
    uint32_t loop_ip_nbo = inet_addr("127.0.0.1");
    uint8_t destMac[6];
    memcpy(destMac, &loop_ip_nbo, 4);
    destMac[4] = 0; destMac[5] = 0;

    const char* msg = "hello adhoc";
    int len = (int)strlen(msg) + 1;
    int send_len = len;

    int sres = sceNetAdhocPdpSend(snd, destMac, recvPort, msg, &send_len, 0);
    printf("send res=%d sent=%d\n", sres, send_len);

    char buf[2048];
    int buflen = sizeof(buf);
    int trecv = sceNetAdhocPdpRecv(rcv, buf, &buflen, 2000000, 0);
    if (trecv > 0) {
        printf("recv OK len=%d: '%s'\n", buflen, buf);
    }
    else {
        printf("recv failed %d\n", trecv);
    }

    sceNetAdhocPdpDelete(snd);
    sceNetAdhocPdpDelete(rcv);

    sceNetAdhocTerm();
    printf("done\n");
    return 0;
}

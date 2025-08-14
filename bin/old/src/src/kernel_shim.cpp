#include "kernel_shim.h"
#include <chrono>
#include <thread>
#include <cstdarg>
#include <cstdio>
#include <random>
#include <cstring>

// time / sleep / log already exist
uint64_t ks_time_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}
void ks_sleep_ms(uint32_t ms) {
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

void LOG(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    printf("\n");
    va_end(ap);
}

// Random MAC / Nick generators
void ks_generate_random_mac(uint8_t mac_out[6]) {
    if (!mac_out) return;
    // Use random_device + mt19937 for good randomness
    static thread_local std::mt19937_64 rng((std::random_device())());
    std::uniform_int_distribution<uint16_t> dist(0, 255);

    // Create locally administered MAC (set bit 1 of first octet)
    uint8_t b0 = (uint8_t)(dist(rng) & 0xFE); // ensure unicast by clearing multicast bit
    b0 |= 0x02; // locally administered
    mac_out[0] = b0;
    for (int i = 1; i < 6; ++i) mac_out[i] = (uint8_t)dist(rng);
}

void ks_generate_random_nick(char* out, int out_len) {
    if (!out || out_len <= 0) return;
    static const char* charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static thread_local std::mt19937 rng((std::random_device())());
    std::uniform_int_distribution<int> dist(0, (int)strlen(charset) - 1);
    // produce nickname like "Player-XXXX"
    const char* prefix = "Player-";
    int prefix_len = (int)strlen(prefix);
    int remaining = out_len - 1;
    int pos = 0;
    for (int i = 0; i < prefix_len && pos < remaining; ++i) out[pos++] = prefix[i];
    // fill the rest with random chars (keep at least 4 chars random or until buffer)
    while (pos < remaining) {
        out[pos++] = charset[dist(rng)];
    }
    out[pos] = '\0';
}

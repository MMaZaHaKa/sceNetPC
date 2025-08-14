#pragma once
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

	uint64_t ks_time_ms();
	void ks_sleep_ms(uint32_t ms);
	void LOG(const char* fmt, ...);

	// New utilities
	void ks_generate_random_mac(uint8_t mac_out[6]);
	void ks_generate_random_nick(char* out, int out_len);

#ifdef __cplusplus
}
#endif

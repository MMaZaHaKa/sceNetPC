#pragma once
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

	uint64_t ks_time_ms();
	void ks_sleep_ms(uint32_t ms);
	void LOG(const char* fmt, ...);

#ifdef __cplusplus
}
#endif

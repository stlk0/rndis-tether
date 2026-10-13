#include "clock.h"

#include <errno.h>
#include <time.h>

uint64_t now_ms(void) {
    return clock_gettime_nsec_np(CLOCK_MONOTONIC) / 1000000u;
}

void sleep_ms(unsigned ms) {
    struct timespec t = {.tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000L};
    while (nanosleep(&t, &t) && errno == EINTR) {}
}

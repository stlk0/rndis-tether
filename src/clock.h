/* Time and run-loop timers. Everything in the daemon runs on the main thread's run
 * loop; tests provide their own now_ms and sleep_ms to control time.
 */
#ifndef CLOCK_H
#define CLOCK_H

#include <CoreFoundation/CoreFoundation.h>
#include <stdint.h>

uint64_t now_ms(void); /* monotonic */
void sleep_ms(unsigned ms);

/* A timer on the main run loop, created disarmed. interval: seconds between repeats
 * once armed (0: fires once per timer_set). */
static inline CFRunLoopTimerRef timer_new(CFRunLoopTimerCallBack fired, void *info, double interval,
                                          double tolerance) {
    CFRunLoopTimerContext context = {.info = info};
    CFRunLoopTimerRef timer = CFRunLoopTimerCreate(NULL, CFAbsoluteTimeGetCurrent() + 1e9,
                                                   interval > 0 ? interval : 1e9, 0, 0, fired, &context);
    if (timer) {
        CFRunLoopTimerSetTolerance(timer, tolerance);
        CFRunLoopAddTimer(CFRunLoopGetMain(), timer, kCFRunLoopDefaultMode);
    }
    return timer;
}

static inline void timer_set(CFRunLoopTimerRef timer, double seconds) {
    CFRunLoopTimerSetNextFireDate(timer, CFAbsoluteTimeGetCurrent() + seconds);
}

static inline void timer_disarm(CFRunLoopTimerRef timer) {
    CFRunLoopTimerSetNextFireDate(timer, CFAbsoluteTimeGetCurrent() + 10.0 * 365 * 86400);
}

#endif

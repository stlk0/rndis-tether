/* Time and run-loop timers. Everything in the daemon runs on the main thread's run
 * loop; tests provide their own now_ms and sleep_ms to control time.
 */
#ifndef CLOCK_H
#define CLOCK_H

#include <CoreFoundation/CoreFoundation.h>
#include <stdint.h>

uint64_t now_ms(void); /* monotonic */
void sleep_ms(unsigned ms);

#define TIMER_FAR_FUTURE_S (10.0 * 365 * 86400) /* "never" for a fire date or a repeat interval */

/* A timer on the main run loop, created disarmed. interval: seconds between repeats
 * once armed (0: fires once per timer_set). A CFRunLoopTimer created without a repeat
 * interval is invalidated after it fires, so one-shot timers repeat at TIMER_FAR_FUTURE_S
 * instead and stay re-armable. */
static inline CFRunLoopTimerRef timer_new(CFRunLoopTimerCallBack fired, void *info, double interval,
                                          double tolerance) {
    CFRunLoopTimerContext context = {.info = info};
    CFRunLoopTimerRef timer = CFRunLoopTimerCreate(NULL, CFAbsoluteTimeGetCurrent() + TIMER_FAR_FUTURE_S,
                                                   interval > 0 ? interval : TIMER_FAR_FUTURE_S, 0, 0, fired, &context);
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
    timer_set(timer, TIMER_FAR_FUTURE_S);
}

#endif

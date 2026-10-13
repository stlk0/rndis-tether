/* Offline scenarios for the control pump (control.c). No USB or run loop is started:
 * a fake usb_link captures every submission and the tests deliver completions by hand,
 * with a clock they move themselves.
 */
#include "clock.h"
#include "control.h"

#include <stdio.h>
#include <string.h>

static unsigned tests, failures;
#define CHECK(x) do { ++tests; if (!(x)) { ++failures; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); } } while (0)

/* ------------------------------------------------------------------- fakes */

static uint64_t test_now = 10000;
uint64_t now_ms(void) { return test_now; }
void sleep_ms(unsigned ms) { test_now += ms; }

static UsbLink usb_link;
static Control control;
static UsbTransfer *submitted;
static void *submitted_buffer;
static uint16_t submitted_size;
static uint32_t submitted_timeout;
static unsigned submissions, notify_reads;
static IOReturn submit_error;

IOReturn usb_control(UsbLink *u, UsbTransfer *t, bool in, void *buffer, uint16_t size, uint32_t timeout_ms) {
    CHECK(u == &usb_link && t == &control.transfer);
    CHECK(!control.pending); /* never over a request whose callback has not run */
    CHECK(timeout_ms > 0);
    CHECK(in ? buffer == control.response : buffer == control.current.bytes);
    ++submissions;
    if (submit_error) return submit_error;
    t->request.wLength = size;
    submitted = t;
    submitted_buffer = buffer;
    submitted_size = size;
    submitted_timeout = timeout_ms;
    return kIOReturnSuccess;
}

IOReturn usb_read(UsbLink *u, UsbPipe pipe, UsbTransfer *t, void *buffer, uint32_t size) {
    (void)u; (void)t; (void)buffer; (void)size;
    CHECK(pipe == USB_NOTIFY);
    ++notify_reads;
    return kIOReturnSuccess;
}

void usb_clear_stall(UsbLink *u, UsbPipe pipe) { (void)u; (void)pipe; }

/* Synchronous bring-up: replies are taken from a script. */
static const uint8_t *script[4];
static size_t script_size[4];
static unsigned script_next, script_count;

IOReturn usb_send_encapsulated(UsbLink *u, const uint8_t *b, uint16_t n, uint32_t timeout_ms) {
    (void)u; (void)b; (void)n; (void)timeout_ms;
    return kIOReturnSuccess;
}

IOReturn usb_get_encapsulated(UsbLink *u, uint8_t *b, uint16_t capacity, uint32_t *done, uint32_t timeout_ms) {
    (void)u; (void)timeout_ms;
    *done = 0;
    if (script_next == script_count) return kIOReturnSuccess; /* "not ready yet" */
    size_t n = script_size[script_next];
    if (n <= capacity) memcpy(b, script[script_next], n);
    ++script_next;
    *done = (uint32_t)n;
    return kIOReturnSuccess;
}

/* ------------------------------------------------------------------ events */

static unsigned callbacks, messages, heard, failed;
static ControlResult last_result;
static uint32_t last_status, last_addressing, last_message_type;
static const char *failed_reason;

static void on_message(const uint8_t *b, size_t n) {
    ++messages;
    last_message_type = rndis_control_type(b, n);
    uint32_t id = 0;
    /* As the session does: a device KEEPALIVE is answered before anything else. */
    if (last_message_type == RNDIS_KEEPALIVE_MSG && !rndis_parse_keepalive(b, n, &id)) {
        ControlMessage reply = {.id = id};
        reply.length = rndis_build_keepalive_cmplt(reply.bytes, id);
        CHECK(control_send(&control, &reply, true));
    }
}

static void on_heard(void) { ++heard; }

static void on_failed(const char *reason, IOReturn status) {
    (void)status;
    ++failed;
    failed_reason = reason;
    control_stop(&control); /* as the session does */
}

static const ControlEvents events = {on_message, on_heard, on_failed};

static void result_done(void *context, ControlResult result, uint32_t status, uint32_t addressing_reset) {
    (void)context;
    ++callbacks;
    last_result = result;
    last_status = status;
    last_addressing = addressing_reset;
}

static bool not_wanted(void *context) {
    (void)context;
    return false;
}

static void fixture(void) {
    control_close(&control);
    usb_link = (UsbLink){.control_open = true};
    test_now = 10000;
    submissions = notify_reads = callbacks = messages = heard = failed = 0;
    submit_error = 0;
    submitted = NULL;
    failed_reason = NULL;
    control_open(&control, &usb_link, &events);
    control_run(&control);
}

/* The kernel finishes the submitted request: response bytes for a GET, n bytes moved. */
static void complete(IOReturn status, const uint8_t *response, size_t n) {
    CHECK(control.pending && submitted);
    if (response && n <= submitted_size) memcpy(submitted_buffer, response, n);
    UsbTransfer *t = submitted;
    submitted = NULL;
    t->done(t, status, n);
}

static void queue_keepalive(uint32_t id) {
    ControlMessage m = {.type = RNDIS_KEEPALIVE_MSG, .id = id, .done = result_done};
    m.length = rndis_build_keepalive(m.bytes, id);
    CHECK(control_send(&control, &m, false));
}

/* ------------------------------------------------------------------- tests */

static void test_polling_and_serialization(void) {
    fixture();
    CHECK(notify_reads == 1);
    queue_keepalive(42);
    control_kick(&control);
    CHECK(submissions == 1 && control.state == CONTROL_SEND && control.pending);
    ControlMessage reply = {.id = 7, .done = result_done};
    reply.length = rndis_build_keepalive_cmplt(reply.bytes, 7);
    CHECK(control_send(&control, &reply, true));
    control_kick(&control);
    CHECK(submissions == 1 && rndis_control_id(control.current.bytes, 12) == 42);
    complete(0, NULL, 12);
    CHECK(control.state == CONTROL_WAIT && !control.pending);
    test_now += 249;
    control_kick(&control);
    CHECK(submissions == 1);
    ++test_now;
    control_kick(&control);
    CHECK(submissions == 2 && control.state == CONTROL_GET);
    complete(0, NULL, 0);
    CHECK(control.state == CONTROL_WAIT && callbacks == 0);
    test_now += 19;
    control_kick(&control);
    CHECK(submissions == 2);
    ++test_now;
    control_kick(&control);
    CHECK(submissions == 3);
    complete(kIOUSBPipeStalled, NULL, 0);
    test_now += 20;
    control_kick(&control);
    CHECK(submissions == 4);
    uint8_t wrong[16];
    rndis_build_keepalive_cmplt(wrong, 999);
    complete(0, wrong, sizeof wrong);
    CHECK(callbacks == 0 && messages == 1 && control.state == CONTROL_GET);
    uint8_t answer[16];
    rndis_build_keepalive_cmplt(answer, 42);
    complete(0, answer, sizeof answer);
    CHECK(callbacks == 1 && last_result == CONTROL_SUCCESS && heard == 2);
    CHECK(control.state == CONTROL_SEND && control.current.id == 7 && control.pending);
    complete(0, NULL, 16);
    CHECK(callbacks == 2 && control.state == CONTROL_GET); /* drain leftovers while idle */
    complete(0, NULL, 0);
    CHECK(control.state == CONTROL_IDLE && !control.pending && !control.busy);
}

static void test_notifications_and_device_keepalive(void) {
    fixture();
    queue_keepalive(42);
    control_kick(&control);
    control.notified = true; /* a notification before SEND's completion must not be lost */
    control_kick(&control);
    CHECK(submissions == 1);
    complete(0, NULL, 12);
    CHECK(submissions == 2 && control.state == CONTROL_GET);
    uint8_t both[28];
    rndis_build_keepalive(both, 7);
    rndis_build_keepalive_cmplt(both + 12, 42);
    complete(0, both, sizeof both);
    CHECK(callbacks == 1 && last_result == CONTROL_SUCCESS && heard == 1 && messages == 1);
    CHECK(control.state == CONTROL_SEND && control.current.type == 0 && control.current.id == 7);
    CHECK(rndis_control_type(control.current.bytes, 16) == (RNDIS_KEEPALIVE_MSG | RNDIS_COMPLETION));
    complete(0, NULL, 16);
    complete(0, NULL, 0);
    control.notified = true;
    control_kick(&control);
    CHECK(control.state == CONTROL_GET && !control.busy);
    uint8_t indication[20] = {0};
    rndis_put32(indication, RNDIS_INDICATE_STATUS_MSG);
    rndis_put32(indication + 4, sizeof indication);
    rndis_put32(indication + 8, RNDIS_STATUS_MEDIA_DISCONNECT);
    complete(0, indication, sizeof indication);
    CHECK(messages == 2 && last_message_type == RNDIS_INDICATE_STATUS_MSG);
    complete(0, NULL, 0);
}

static void test_timeouts_and_stop(void) {
    fixture();
    queue_keepalive(42);
    control_kick(&control);
    complete(0, NULL, 12);
    test_now += 4999;
    control_kick(&control);
    CHECK(control.pending && submitted_timeout == 1);
    ++test_now;
    control_kick(&control);
    CHECK(callbacks == 0 && control.pending); /* the deadline never releases kernel-owned buffers */
    uint8_t late[16];
    rndis_build_keepalive_cmplt(late, 42);
    complete(0, late, sizeof late);
    CHECK(callbacks == 1 && last_result == CONTROL_TIMEOUT && heard == 1);
    complete(0, NULL, 0);
    CHECK(callbacks == 1 && !control.pending);

    fixture();
    queue_keepalive(42);
    control_kick(&control);
    control_stop(&control);
    complete(0, NULL, 12);
    CHECK(!control.pending && callbacks == 0 && submissions == 1);
    ControlMessage after_stop = {.type = RNDIS_KEEPALIVE_MSG, .id = 43, .done = result_done};
    after_stop.length = rndis_build_keepalive(after_stop.bytes, 43);
    CHECK(!control_send(&control, &after_stop, false) && submissions == 1);
}

static void test_errors_and_priority(void) {
    fixture();
    ControlMessage reset = {.type = RNDIS_RESET_MSG, .done = result_done};
    reset.length = rndis_build_reset(reset.bytes);
    CHECK(control_send(&control, &reset, false));
    ControlMessage reply = {.id = 9, .done = result_done};
    reply.length = rndis_build_keepalive_cmplt(reply.bytes, 9);
    CHECK(control_send(&control, &reply, true));
    control_kick(&control);
    CHECK(control.current.id == 9 && control.current.type == 0);
    complete(0, NULL, 16);
    CHECK(control.current.type == RNDIS_RESET_MSG);
    complete(0, NULL, 12);
    control.notified = true;
    control_kick(&control);
    uint8_t reset_reply[16] = {0};
    rndis_put32(reset_reply, RNDIS_RESET_MSG | RNDIS_COMPLETION);
    rndis_put32(reset_reply + 4, 16);
    rndis_put32(reset_reply + 8, 0xc0000001u); /* Status is not a RequestId */
    rndis_put32(reset_reply + 12, 1);
    complete(0, reset_reply, sizeof reset_reply);
    CHECK(callbacks == 2 && last_result == CONTROL_DEVICE_STATUS && last_status == 0xc0000001u && last_addressing == 1);
    complete(0, NULL, 0);

    fixture();
    queue_keepalive(42);
    submit_error = kIOReturnError;
    control_kick(&control);
    CHECK(callbacks == 1 && last_result == CONTROL_USB_ERROR && !control.pending && !control.busy && !failed);

    fixture();
    queue_keepalive(42);
    control_kick(&control);
    complete(0, NULL, 11);
    CHECK(callbacks == 1 && last_result == CONTROL_USB_ERROR && last_status == (uint32_t)kIOReturnUnderrun);

    fixture();
    ControlMessage skipped = {.type = RNDIS_KEEPALIVE_MSG, .id = 5, .wanted = not_wanted, .done = result_done};
    skipped.length = rndis_build_keepalive(skipped.bytes, 5);
    CHECK(control_send(&control, &skipped, false));
    control_kick(&control);
    CHECK(submissions == 0 && callbacks == 1 && last_result == CONTROL_SKIPPED);
}

static void test_failures(void) {
    fixture();
    queue_keepalive(42);
    control_kick(&control);
    complete(kIOReturnNoDevice, NULL, 0);
    CHECK(failed == 1 && !strcmp(failed_reason, "control endpoint failed"));
    CHECK(callbacks == 1 && last_result == CONTROL_USB_ERROR && !control.pending);

    fixture();
    queue_keepalive(42);
    control_kick(&control);
    complete(0, NULL, 12);
    control.notified = true;
    control_kick(&control);
    uint8_t short_reply[12];
    rndis_build_keepalive(short_reply, 42);
    rndis_put32(short_reply, RNDIS_KEEPALIVE_MSG | RNDIS_COMPLETION);
    complete(0, short_reply, sizeof short_reply);
    CHECK(callbacks == 1 && last_result == CONTROL_INVALID);
    complete(0, NULL, 0);

    fixture();
    for (unsigned i = 0; i < CONTROL_QUEUE; ++i) queue_keepalive(i);
    ControlMessage one_more = {.type = RNDIS_KEEPALIVE_MSG, .id = 99, .done = result_done};
    one_more.length = rndis_build_keepalive(one_more.bytes, 99);
    CHECK(!control_send(&control, &one_more, false));
    CHECK(failed == 1 && control.count == CONTROL_QUEUE && callbacks == 1);
}

static void test_exchange(void) {
    fixture();
    control_close(&control);
    control_open(&control, &usb_link, &events); /* bring-up: not running yet */
    uint8_t indication[20] = {0}, completion[16];
    rndis_put32(indication, RNDIS_INDICATE_STATUS_MSG);
    rndis_put32(indication + 4, sizeof indication);
    rndis_put32(indication + 8, RNDIS_STATUS_MEDIA_CONNECT);
    rndis_build_keepalive_cmplt(completion, 77);
    script[0] = indication;
    script_size[0] = sizeof indication;
    script[1] = completion;
    script_size[1] = sizeof completion;
    script_next = 0;
    script_count = 2;
    uint8_t request[12], response[RNDIS_CONTROL_CAP];
    size_t n = 0;
    IOReturn status = kIOReturnError;
    const char *e = control_exchange(&control, request, rndis_build_keepalive(request, 77), RNDIS_KEEPALIVE_MSG, 77,
                                     response, &n, &status);
    CHECK(!e && n == sizeof completion && !status && messages == 1 && heard == 2);
    script_next = script_count = 0;
    uint64_t started = test_now;
    e = control_exchange(&control, request, sizeof request, RNDIS_KEEPALIVE_MSG, 78, response, &n, &status);
    CHECK(e && test_now - started >= 3000);
    /* Before control_run only replies are possible, sent at once. */
    ControlMessage reply = {.id = 1, .done = result_done};
    reply.length = rndis_build_keepalive_cmplt(reply.bytes, 1);
    CHECK(control_send(&control, &reply, true) && callbacks == 1 && last_result == CONTROL_SUCCESS);
    ControlMessage request_later = {.type = RNDIS_KEEPALIVE_MSG, .id = 2, .done = result_done};
    request_later.length = rndis_build_keepalive(request_later.bytes, 2);
    CHECK(!control_send(&control, &request_later, false) && !control.count);
}

int main(void) {
    test_polling_and_serialization();
    test_notifications_and_device_keepalive();
    test_timeouts_and_stop();
    test_errors_and_priority();
    test_failures();
    test_exchange();
    control_close(&control);
    printf("controltest: %u checks, %u failures\n", tests, failures);
    return failures ? 1 : 0;
}

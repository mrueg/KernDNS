// Calls into the Rust host through the function pointers kb_init stores.
// cgo can't call C function pointers directly, hence these trampolines.
#include "callbacks.h"

static kb_write_fn write_cb;
static kb_next_fn next_cb;
static kb_done_fn done_cb;

void kb_set_callbacks(kb_write_fn w, kb_next_fn n, kb_done_fn d) {
    write_cb = w;
    next_cb = n;
    done_cb = d;
}

void kb_call_write(uint64_t token, const uint8_t* msg, size_t len) { write_cb(token, msg, len); }

void kb_call_next(uint64_t token, uint64_t next_token, const uint8_t* msg, size_t len) {
    next_cb(token, next_token, msg, len);
}

void kb_call_done(uint64_t token, int rcode, const char* err) { done_cb(token, rcode, err); }

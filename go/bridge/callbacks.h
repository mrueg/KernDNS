#ifndef KERNDNS_BRIDGE_CALLBACKS_H
#define KERNDNS_BRIDGE_CALLBACKS_H
#include <stddef.h>
#include <stdint.h>

// A response the Go plugin wrote (packed DNS message).
typedef void (*kb_write_fn)(uint64_t token, const uint8_t* msg, size_t len);
// The Go plugin calls the next (Rust) plugin; answer with kb_next_done.
typedef void (*kb_next_fn)(uint64_t token, uint64_t next_token, const uint8_t* msg, size_t len);
// The Go plugin returned: rcode and error text ("" for none).
typedef void (*kb_done_fn)(uint64_t token, int rcode, const char* err);

void kb_set_callbacks(kb_write_fn w, kb_next_fn n, kb_done_fn d);
void kb_call_write(uint64_t token, const uint8_t* msg, size_t len);
void kb_call_next(uint64_t token, uint64_t next_token, const uint8_t* msg, size_t len);
void kb_call_done(uint64_t token, int rcode, const char* err);
#endif

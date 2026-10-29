/* Watchtower native SDK (C API). Apache-2.0. Usable from C and C++. */
#ifndef WATCHTOWER_H
#define WATCHTOWER_H
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WT_SDK_VERSION "0.1.0"

typedef enum { WT_DEBUG, WT_INFO, WT_WARNING, WT_ERROR, WT_FATAL } wt_level;

/* Transport results. RETRY keeps the envelope in the offline queue (needs cache_dir). */
#define WT_SEND_OK 0
#define WT_SEND_RETRY 1
#define WT_SEND_DROP 2

/* POST `body` (an envelope) to `url` with `Authorization: Bearer <key>`. */
typedef int (*wt_transport_fn)(void *ud, const char *url, const char *key, const void *body, size_t len);

/* Redaction hook: return a replacement for `value` or NULL to keep it. `field` is e.g. "message",
 * "exception.value", "breadcrumb.message", "tag.<name>", "extra.<name>", "user.email". */
typedef const char *(*wt_redact_fn)(void *ud, const char *field, const char *value);

typedef struct wt_options {
  const char *publishable_key;  /* default: env WT_PUBLISHABLE_KEY. Never a secret ingest key. */
  const char *endpoint;         /* default: env WT_OTLP_ENDPOINT, else http://localhost:4318 */
  const char *service;          /* default: env WT_SERVICE */
  const char *environment;      /* default: env WT_ENVIRONMENT */
  const char *release;          /* default: env WT_RELEASE */
  const char *cache_dir;        /* crash dumps and the offline queue live here; NULL disables both */
  const char *crashpad_handler; /* path to crashpad_handler; used only when built with WT_CRASHPAD */
  int install_crash_handler;    /* wt_options_init sets 1; 0 skips installing any crash handler */
  wt_transport_fn transport;    /* default: libcurl (POSIX) or WinHTTP (Windows) */
  void *transport_ud;
  wt_redact_fn redact;
  void *redact_ud;
} wt_options;

void wt_options_init(wt_options *o);
/* 0 on success. Copies all strings. Uploads crash dumps left by a previous run. */
int wt_init(const wt_options *o);
/* Re-sends queued envelopes; returns how many were delivered. */
int wt_flush(void);
void wt_close(void);

/* Return 0 when the envelope was delivered or queued, -1 otherwise. */
int wt_capture_message(wt_level level, const char *message);
/* A handled error with the calling thread's stack (addresses only; symbolicate with uploaded debug files). */
int wt_capture_error(const char *type, const char *message);

void wt_add_breadcrumb(const char *category, const char *message, wt_level level); /* last 100 kept */
void wt_set_user(const char *id, const char *email, const char *username);
void wt_set_tag(const char *key, const char *value);   /* keys starting with "wt." are ignored */
void wt_set_extra(const char *key, const char *value); /* "wt." keys ignored */
/* Link events to the active trace (hex ids: 32 and 16 chars); NULL clears. */
void wt_set_trace(const char *trace_id, const char *span_id);

/* Writes a masked form like "wtpk...f3a9" (never the whole key) into out. */
void wt_mask_key(const char *key, char *out, size_t out_len);

#ifdef __cplusplus
}
#endif
#endif

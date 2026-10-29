#undef NDEBUG /* asserts are the test; keep them in Release builds */
#include "watchtower.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <direct.h>
#define MKDIR(p) _mkdir(p)
#else
#include <sys/stat.h>
#include <unistd.h>
#define MKDIR(p) mkdir(p, 0700)
#endif

static char last[65536];
static char last_key[128], last_url[256];
static int posts, offline;

static int transport(void *ud, const char *url, const char *key, const void *body, size_t len) {
  (void)ud;
  if (offline) return WT_SEND_RETRY;
  posts++;
  snprintf(last_key, sizeof last_key, "%s", key);
  snprintf(last_url, sizeof last_url, "%s", url);
  assert(len < sizeof last - 1);
  memcpy(last, body, len);
  last[len] = 0;
  return WT_SEND_OK;
}

static const char *redact(void *ud, const char *field, const char *value) {
  (void)ud; (void)value;
  return strcmp(field, "user.email") == 0 ? "[email]" : NULL;
}

static void put(const char *path, const char *data) {
  FILE *f = fopen(path, "wb");
  assert(f);
  fwrite(data, 1, strlen(data), f);
  fclose(f);
}

int main(void) {
  char dir[128], p[256], m[32];
  snprintf(dir, sizeof dir, "wt-native-test-%ld", (long)time(NULL));
  MKDIR(dir);
  wt_options o;
  wt_options_init(&o);
  o.publishable_key = "wtpk_testkey_123456";
  o.endpoint = "https://ingest.example.test/";
  o.service = "game";
  o.environment = "prod";
  o.release = "1.2.3";
  o.cache_dir = dir;
  o.transport = transport;
  o.redact = redact;

  /* key masking never shows the whole key */
  wt_mask_key("wtpk_testkey_123456", m, sizeof m);
  assert(strcmp(m, "wtpk...3456") == 0);

  /* an inproc crash report from the previous run is uploaded by init and deleted */
  snprintf(p, sizeof p, "%s/crashes", dir);
  MKDIR(p);
  snprintf(p, sizeof p, "%s/crashes/42.wtcrash", dir);
  put(p, "SIGSEGV\n401000\n402000\n");
  assert(wt_init(&o) == 0);
  assert(wt_init(&o) == -1);
  assert(posts == 1);
  assert(strstr(last, "\"type\":\"event\""));
  assert(strstr(last, "\"type\":\"SIGSEGV\""));
  assert(strstr(last, "\"instruction_addr\":\"0x402000\""));
  assert(strstr(last, "\"handled\":false"));
  assert(strcmp(last_url, "https://ingest.example.test/api/0/envelope/") == 0);
  assert(strcmp(last_key, "wtpk_testkey_123456") == 0);
  assert(fopen(p, "rb") == NULL);

  /* a minidump rides along as an event.minidump attachment */
  snprintf(p, sizeof p, "%s/crashes/43.dmp", dir);
  put(p, "MDMPfake");
  posts = 0;
  wt_close();
  assert(wt_init(&o) == 0);
  assert(posts == 1);
  assert(strstr(last, "\"attachment_type\":\"event.minidump\""));
  assert(strstr(last, "MDMPfake"));

  /* message with scope: redaction, wt.* tag dropped, trace link, breadcrumb escaping */
  wt_set_user("u1", "a@b.c", "bob");
  wt_set_tag("wt.tenant", "evil");
  wt_set_tag("level_name", "forest");
  wt_set_extra("fps", "59");
  wt_set_trace("0123456789abcdef0123456789abcdef", "0123456789abcdef");
  wt_add_breadcrumb("ui", "clicked \"play\"", WT_INFO);
  assert(wt_capture_message(WT_WARNING, "low memory") == 0);
  assert(strstr(last, "\"formatted\":\"low memory\""));
  assert(strstr(last, "\"service.name\":\"game\""));
  assert(strstr(last, "\"release\":\"1.2.3\""));
  assert(strstr(last, "\"level_name\":\"forest\""));
  assert(!strstr(last, "wt.tenant"));
  assert(strstr(last, "\"email\":\"[email]\""));
  assert(!strstr(last, "a@b.c"));
  assert(strstr(last, "\"trace_id\":\"0123456789abcdef0123456789abcdef\""));
  assert(strstr(last, "clicked \\\"play\\\""));
  assert(!strstr(last, "wtpk_testkey"));

  /* breadcrumbs keep the last 100 */
  for (int i = 0; i < 150; i++) {
    char b[16];
    snprintf(b, sizeof b, "crumb%d.", i);
    wt_add_breadcrumb("t", b, WT_DEBUG);
  }
  assert(wt_capture_message(WT_INFO, "x") == 0);
  assert(!strstr(last, "crumb49.") && strstr(last, "crumb50.") && strstr(last, "crumb149."));

  /* handled error */
  assert(wt_capture_error("IoError", "disk full") == 0);
  assert(strstr(last, "\"type\":\"IoError\""));
  assert(strstr(last, "\"handled\":true"));

  /* offline: queued on disk, delivered by flush */
  offline = 1;
  posts = 0;
  assert(wt_capture_message(WT_ERROR, "while offline") == 0);
  assert(posts == 0);
  offline = 0;
  assert(wt_flush() == 1);
  assert(strstr(last, "while offline"));
  assert(wt_flush() == 0);
  wt_close();
  assert(wt_capture_message(WT_INFO, "closed") == -1);

  /* no key, no start */
  o.publishable_key = NULL;
#ifndef _WIN32
  unsetenv("WT_PUBLISHABLE_KEY");
#endif
  assert(wt_init(&o) == -1);
  puts("ok");
  return 0;
}

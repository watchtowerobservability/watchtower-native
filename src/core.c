#include "watchtower.h"
#include "internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAXCRUMB 100
#define MAXKV 32
#define MAXQUEUE 30
#define MAXFRAMES 64

typedef struct { char *cat, *msg; int level; long long ts; } crumb;
typedef struct { char *k, *v; } kv;

static struct {
  int on;
  char *key, *url, *service, *env, *release, *cache;
  wt_transport_fn transport;
  void *transport_ud;
  wt_redact_fn redact;
  void *redact_ud;
  crumb crumbs[MAXCRUMB];
  int ncrumb, cstart;
  char *uid, *uemail, *uname;
  kv tags[MAXKV], extra[MAXKV];
  int ntags, nextra;
  char trace[33], span[17];
} G;

static const char *LEVELS[] = {"debug", "info", "warning", "error", "fatal"};

static char *env_or(const char *v, const char *name) {
  if (v && *v) return wt_strdup(v);
  const char *e = getenv(name);
  return (e && *e) ? wt_strdup(e) : NULL;
}

static int ends_with(const char *s, const char *suf) {
  size_t a = strlen(s), b = strlen(suf);
  return a >= b && strcmp(s + a - b, suf) == 0;
}

void wt_mask_key(const char *key, char *out, size_t n) {
  if (!n) return;
  size_t l = key ? strlen(key) : 0;
  if (l <= 8) snprintf(out, n, "****");
  else snprintf(out, n, "%.4s...%s", key, key + l - 4);
}

void wt_options_init(wt_options *o) {
  memset(o, 0, sizeof *o);
  o->install_crash_handler = 1;
}

/* ---- scope ---- */

static void setkv(kv *a, int *n, const char *k, const char *v) {
  if (!k || !v || strncmp(k, "wt.", 3) == 0) return;
  wt_lock();
  for (int i = 0; i < *n; i++)
    if (strcmp(a[i].k, k) == 0) {
      free(a[i].v);
      a[i].v = wt_strdup(v);
      wt_unlock();
      return;
    }
  if (*n < MAXKV) {
    a[*n].k = wt_strdup(k);
    a[*n].v = wt_strdup(v);
    (*n)++;
  }
  wt_unlock();
}
void wt_set_tag(const char *k, const char *v) { setkv(G.tags, &G.ntags, k, v); }
void wt_set_extra(const char *k, const char *v) { setkv(G.extra, &G.nextra, k, v); }

void wt_set_user(const char *id, const char *email, const char *name) {
  wt_lock();
  free(G.uid); free(G.uemail); free(G.uname);
  G.uid = wt_strdup(id); G.uemail = wt_strdup(email); G.uname = wt_strdup(name);
  wt_unlock();
}

void wt_set_trace(const char *t, const char *s) {
  wt_lock();
  G.trace[0] = G.span[0] = 0;
  if (t && strlen(t) == 32 && s && strlen(s) == 16) {
    memcpy(G.trace, t, 33);
    memcpy(G.span, s, 17);
  }
  wt_unlock();
}

void wt_add_breadcrumb(const char *cat, const char *msg, wt_level lvl) {
  wt_lock();
  int i;
  if (G.ncrumb < MAXCRUMB) i = (G.cstart + G.ncrumb++) % MAXCRUMB;
  else { i = G.cstart; G.cstart = (G.cstart + 1) % MAXCRUMB; free(G.crumbs[i].cat); free(G.crumbs[i].msg); }
  G.crumbs[i].cat = wt_strdup(cat ? cat : "default");
  G.crumbs[i].msg = wt_strdup(msg ? msg : "");
  G.crumbs[i].level = lvl;
  G.crumbs[i].ts = (long long)time(NULL);
  wt_unlock();
}

/* ---- event and envelope ---- */

/* JSON string of `v` after the redaction hook (field name `prefix` + `name`). */
static void rstr(wt_buf *b, const char *prefix, const char *name, const char *v) {
  if (v && G.redact) {
    char f[160];
    snprintf(f, sizeof f, "%s%s", prefix, name ? name : "");
    const char *r = G.redact(G.redact_ud, f, v);
    if (r) v = r;
  }
  wt_buf_json_str(b, v);
}

static void put_kvs(wt_buf *b, const char *prefix, kv *a, int n) {
  wt_buf_add(b, "{", 1);
  for (int i = 0; i < n; i++) {
    if (i) wt_buf_add(b, ",", 1);
    wt_buf_json_str(b, a[i].k);
    wt_buf_add(b, ":", 1);
    rstr(b, prefix, a[i].k, a[i].v);
  }
  wt_buf_add(b, "}", 1);
}

/* Caller holds the lock. `scope` adds breadcrumbs, user, tags, extra and the trace link. */
static void build_event(wt_buf *b, const char *id, long long ts, int level, const char *msg, const char *etype,
                        const char *evalue, const unsigned long long *addr, int naddr, int handled, int scope) {
  wt_buf_printf(b, "{\"event_id\":\"%s\",\"timestamp\":%lld,\"platform\":\"native\",\"level\":\"%s\"", id, ts, LEVELS[level]);
  wt_buf_puts(b, ",\"sdk\":{\"name\":\"watchtower.native\",\"version\":\"" WT_SDK_VERSION "\"}");
  if (G.release) { wt_buf_puts(b, ",\"release\":"); wt_buf_json_str(b, G.release); }
  if (G.env) { wt_buf_puts(b, ",\"environment\":"); wt_buf_json_str(b, G.env); }
  wt_buf_puts(b, ",\"tags\":{");
  int first = 1;
  if (G.service) { wt_buf_puts(b, "\"service.name\":"); wt_buf_json_str(b, G.service); first = 0; }
  if (scope)
    for (int i = 0; i < G.ntags; i++) {
      if (!first) wt_buf_add(b, ",", 1);
      first = 0;
      wt_buf_json_str(b, G.tags[i].k);
      wt_buf_add(b, ":", 1);
      rstr(b, "tag.", G.tags[i].k, G.tags[i].v);
    }
  wt_buf_puts(b, "},\"contexts\":{\"os\":{\"name\":");
  wt_buf_json_str(b, wt_os_name());
  wt_buf_add(b, "}", 1);
  if (scope && G.trace[0]) wt_buf_printf(b, ",\"trace\":{\"trace_id\":\"%s\",\"span_id\":\"%s\"}", G.trace, G.span);
  wt_buf_add(b, "}", 1);
  if (msg) { wt_buf_puts(b, ",\"logentry\":{\"formatted\":"); rstr(b, "message", NULL, msg); wt_buf_add(b, "}", 1); }
  if (etype) {
    wt_buf_puts(b, ",\"exception\":{\"values\":[{\"type\":");
    wt_buf_json_str(b, etype);
    wt_buf_puts(b, ",\"value\":");
    rstr(b, "exception.value", NULL, evalue);
    wt_buf_printf(b, ",\"mechanism\":{\"type\":\"native\",\"handled\":%s}", handled ? "true" : "false");
    if (naddr > 0) {
      wt_buf_puts(b, ",\"stacktrace\":{\"frames\":[");
      for (int i = naddr - 1; i >= 0; i--) { /* Sentry order: oldest call first */
        wt_buf_printf(b, "{\"instruction_addr\":\"0x%llx\"}", addr[i]);
        if (i) wt_buf_add(b, ",", 1);
      }
      wt_buf_puts(b, "]}");
    }
    wt_buf_puts(b, "}]}");
  }
  if (scope) {
    if (G.uid || G.uemail || G.uname) {
      wt_buf_puts(b, ",\"user\":{\"id\":"); rstr(b, "user.", "id", G.uid);
      wt_buf_puts(b, ",\"email\":"); rstr(b, "user.", "email", G.uemail);
      wt_buf_puts(b, ",\"username\":"); rstr(b, "user.", "username", G.uname);
      wt_buf_add(b, "}", 1);
    }
    if (G.nextra) { wt_buf_puts(b, ",\"extra\":"); put_kvs(b, "extra.", G.extra, G.nextra); }
    if (G.ncrumb) {
      wt_buf_puts(b, ",\"breadcrumbs\":{\"values\":[");
      for (int i = 0; i < G.ncrumb; i++) {
        crumb *c = &G.crumbs[(G.cstart + i) % MAXCRUMB];
        if (i) wt_buf_add(b, ",", 1);
        wt_buf_printf(b, "{\"timestamp\":%lld,\"level\":\"%s\",\"category\":", c->ts, LEVELS[c->level]);
        wt_buf_json_str(b, c->cat);
        wt_buf_puts(b, ",\"message\":");
        rstr(b, "breadcrumb.message", NULL, c->msg);
        wt_buf_add(b, "}", 1);
      }
      wt_buf_puts(b, "]}");
    }
  }
  wt_buf_add(b, "}", 1);
}

static void new_id(char *out) { /* 32 hex chars */
  unsigned char r[16];
  wt_random(r, 16);
  for (int i = 0; i < 16; i++) snprintf(out + 2 * i, 3, "%02x", r[i]);
}

static void build_envelope(wt_buf *env, const char *id, const wt_buf *ev, const void *dump, size_t dlen) {
  char sent[32];
  time_t t = time(NULL);
  struct tm tmv;
#ifdef _WIN32
  gmtime_s(&tmv, &t);
#else
  gmtime_r(&t, &tmv);
#endif
  strftime(sent, sizeof sent, "%Y-%m-%dT%H:%M:%SZ", &tmv);
  wt_buf_printf(env, "{\"event_id\":\"%s\",\"sent_at\":\"%s\"}\n", id, sent);
  wt_buf_printf(env, "{\"type\":\"event\",\"length\":%zu}\n", ev->len);
  wt_buf_add(env, ev->p, ev->len);
  wt_buf_add(env, "\n", 1);
  if (dump) {
    wt_buf_printf(env, "{\"type\":\"attachment\",\"length\":%zu,\"attachment_type\":\"event.minidump\","
                       "\"filename\":\"upload_file_minidump.dmp\"}\n", dlen);
    wt_buf_add(env, dump, dlen);
    wt_buf_add(env, "\n", 1);
  }
}

/* ---- send, queue ---- */

static int post(const void *body, size_t len) {
  wt_transport_fn f = G.transport ? G.transport : wt_default_post;
  return f(G.transport_ud, G.url, G.key, body, len);
}

static int queue_count_cb(void *ud, const char *p, long long m) { (void)p; (void)m; (*(int *)ud)++; return 0; }

static int send_env(const wt_buf *env) {
  if (env->oom) return -1;
  int r = post(env->p, env->len);
  if (r == WT_SEND_OK) return 0;
  if (r == WT_SEND_RETRY && G.cache) {
    char dir[1100], id[33], path[1200];
    int n = 0;
    snprintf(dir, sizeof dir, "%s/queue", G.cache);
    wt_listdir(dir, ".envelope", queue_count_cb, &n);
    if (n < MAXQUEUE) {
      new_id(id);
      snprintf(path, sizeof path, "%s/%s.envelope", dir, id);
      if (wt_write_file(path, env->p, env->len) == 0) return 0;
    }
  }
  return -1;
}

typedef struct { int sent, stop; } flush_st;
static int flush_cb(void *ud, const char *path, long long m) {
  flush_st *s = (flush_st *)ud;
  size_t len;
  (void)m;
  char *d = wt_read_file(path, &len);
  if (!d) return 0;
  int r = post(d, len);
  free(d);
  if (r == WT_SEND_RETRY) { s->stop = 1; return 1; } /* offline: keep the rest */
  wt_remove(path);
  if (r == WT_SEND_OK) s->sent++;
  return 0;
}

int wt_flush(void) {
  flush_st s = {0, 0};
  char dir[1100];
  if (!G.on || !G.cache) return 0;
  snprintf(dir, sizeof dir, "%s/queue", G.cache);
  wt_listdir(dir, ".envelope", flush_cb, &s);
  return s.sent;
}

static int emit(int level, const char *msg, const char *etype, const char *evalue,
                const unsigned long long *addr, int naddr, int handled, int scope, long long ts,
                const void *dump, size_t dlen) {
  char id[33];
  wt_buf ev = {0}, env = {0};
  new_id(id);
  wt_lock();
  if (!G.on) { wt_unlock(); return -1; }
  build_event(&ev, id, ts ? ts : (long long)time(NULL), level, msg, etype, evalue, addr, naddr, handled, scope);
  wt_unlock();
  build_envelope(&env, id, &ev, dump, dlen);
  int r = ev.oom ? -1 : send_env(&env);
  wt_buf_free(&ev);
  wt_buf_free(&env);
  return r;
}

int wt_capture_message(wt_level level, const char *message) {
  if (level < WT_DEBUG || level > WT_FATAL || !message) return -1;
  return emit(level, message, NULL, NULL, NULL, 0, 1, 1, 0, NULL, 0);
}

int wt_capture_error(const char *type, const char *message) {
  unsigned long long a[MAXFRAMES];
  int n = wt_backtrace(a, MAXFRAMES);
  int skip = n > 1 ? 1 : 0; /* this function's own frame */
  return emit(WT_ERROR, NULL, type ? type : "Error", message ? message : "", a + skip, n - skip, 1, 1, 0, NULL, 0);
}

/* ---- crash reports left by the previous run ---- */

static int crash_cb(void *ud, const char *path, long long mtime) {
  size_t len;
  char *d = wt_read_file(path, &len);
  (void)ud;
  if (!d) return 0;
  if (ends_with(path, ".dmp")) {
    /* the edge reads the stack from the dump; the event only has to be usable */
    emit(WT_FATAL, NULL, "NativeCrash", "Native crash (minidump attached)", NULL, 0, 0, 0, mtime, d, len);
  } else { /* inproc report: line 1 is the signal name, then one hex address per line */
    unsigned long long a[MAXFRAMES];
    int n = 0;
    char *nl = strchr(d, '\n'), *p = nl ? nl + 1 : NULL;
    if (nl) *nl = 0;
    while (p && *p && n < MAXFRAMES) {
      char *e;
      unsigned long long v = strtoull(p, &e, 16);
      if (e == p) break;
      a[n++] = v;
      p = *e ? e + 1 : e;
    }
    emit(WT_FATAL, NULL, *d ? d : "Signal", "Fatal signal", a, n, 0, 0, mtime, NULL, 0);
  }
  free(d);
  wt_remove(path);
  return 0;
}

/* ---- lifecycle ---- */

int wt_init(const wt_options *o) {
  char dir[1100];
  if (G.on || !o) return -1;
  char *key = env_or(o->publishable_key, "WT_PUBLISHABLE_KEY");
  if (!key) return -1;
  char *ep = env_or(o->endpoint, "WT_OTLP_ENDPOINT");
  if (!ep) ep = wt_strdup("http://localhost:4318");
  size_t el = strlen(ep);
  while (el && ep[el - 1] == '/') ep[--el] = 0;
  wt_buf u = {0};
  wt_buf_puts(&u, ep);
  wt_buf_puts(&u, "/api/0/envelope/");
  free(ep);
  wt_lock();
  G.key = key;
  G.url = u.p;
  G.service = env_or(o->service, "WT_SERVICE");
  G.env = env_or(o->environment, "WT_ENVIRONMENT");
  G.release = env_or(o->release, "WT_RELEASE");
  G.cache = o->cache_dir ? wt_strdup(o->cache_dir) : NULL;
  G.transport = o->transport;
  G.transport_ud = o->transport_ud;
  G.redact = o->redact;
  G.redact_ud = o->redact_ud;
  G.on = 1;
  wt_unlock();
  if (G.cache) {
    snprintf(dir, sizeof dir, "%s/queue", G.cache);
    wt_mkdirs(dir);
    snprintf(dir, sizeof dir, "%s/crashes", G.cache);
    wt_mkdirs(dir);
    wt_listdir(dir, ".wtcrash", crash_cb, NULL);
    wt_listdir(dir, ".dmp", crash_cb, NULL);
    snprintf(dir, sizeof dir, "%s/crashpad/pending", G.cache);
    wt_listdir(dir, ".dmp", crash_cb, NULL);
    wt_flush();
    if (o->install_crash_handler) {
      int cp = -1;
#ifdef WT_CRASHPAD
      if (o->crashpad_handler) {
        snprintf(dir, sizeof dir, "%s/crashpad", G.cache);
        cp = wt_crashpad_start(o->crashpad_handler, dir);
      }
#endif
      if (cp != 0) {
        snprintf(dir, sizeof dir, "%s/crashes", G.cache);
        wt_crash_install(dir);
      }
    }
  }
  return 0;
}

void wt_close(void) {
  wt_lock();
  G.on = 0;
  free(G.key); free(G.url); free(G.service); free(G.env); free(G.release); free(G.cache);
  free(G.uid); free(G.uemail); free(G.uname);
  for (int i = 0; i < G.ncrumb; i++) { free(G.crumbs[(G.cstart + i) % MAXCRUMB].cat); free(G.crumbs[(G.cstart + i) % MAXCRUMB].msg); }
  for (int i = 0; i < G.ntags; i++) { free(G.tags[i].k); free(G.tags[i].v); }
  for (int i = 0; i < G.nextra; i++) { free(G.extra[i].k); free(G.extra[i].v); }
  memset(&G, 0, sizeof G);
  wt_unlock();
}

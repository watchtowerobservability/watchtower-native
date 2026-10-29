#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#define _DARWIN_C_SOURCE
#include "internal.h"
#include "watchtower.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#if defined(__GLIBC__) || defined(__APPLE__)
#include <execinfo.h>
#define WT_HAVE_BACKTRACE 1
#endif
#ifdef WT_HAVE_CURL
#include <curl/curl.h>
#endif
#include <pthread.h>

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
void wt_lock(void) { pthread_mutex_lock(&g_mu); }
void wt_unlock(void) { pthread_mutex_unlock(&g_mu); }

const char *wt_os_name(void) {
#ifdef __APPLE__
  return "macOS";
#else
  return "Linux";
#endif
}

void wt_random(unsigned char *out, size_t n) {
  FILE *f = fopen("/dev/urandom", "rb");
  size_t got = f ? fread(out, 1, n, f) : 0;
  if (f) fclose(f);
  /* shortcut: weak mix if /dev/urandom is unreadable; ids only need to be unique, not secret */
  for (size_t i = got; i < n; i++) out[i] = (unsigned char)(rand() ^ (int)time(NULL) ^ (int)getpid());
}

int wt_mkdirs(const char *path) {
  char p[1100];
  snprintf(p, sizeof p, "%s", path);
  for (char *c = p + 1; *c; c++)
    if (*c == '/') { *c = 0; mkdir(p, 0700); *c = '/'; }
  return mkdir(p, 0700) == 0 || errno == EEXIST ? 0 : -1;
}

void wt_listdir(const char *dir, const char *suffix, wt_dir_cb cb, void *ud) {
  DIR *d = opendir(dir);
  struct dirent *e;
  if (!d) return;
  size_t sl = strlen(suffix);
  while ((e = readdir(d))) {
    size_t l = strlen(e->d_name);
    char path[1400];
    struct stat st;
    if (l < sl || strcmp(e->d_name + l - sl, suffix) != 0) continue;
    snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) continue;
    if (cb(ud, path, (long long)st.st_mtime)) break;
  }
  closedir(d);
}

char *wt_read_file(const char *path, size_t *len) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  size_t cap = 4096, n = 0;
  char *b = (char *)malloc(cap + 1);
  size_t r;
  while (b && (r = fread(b + n, 1, cap - n, f)) > 0) {
    n += r;
    if (n == cap) { cap *= 2; char *nb = (char *)realloc(b, cap + 1); if (!nb) { free(b); b = NULL; } else b = nb; }
  }
  fclose(f);
  if (!b) return NULL;
  b[n] = 0;
  *len = n;
  return b;
}

int wt_write_file(const char *path, const void *d, size_t n) {
  FILE *f = fopen(path, "wb");
  if (!f) return -1;
  int ok = fwrite(d, 1, n, f) == n;
  return (fclose(f) == 0 && ok) ? 0 : -1;
}

void wt_remove(const char *path) { unlink(path); }

int wt_backtrace(unsigned long long *out, int max) {
#ifdef WT_HAVE_BACKTRACE
  void *fr[128];
  int n = backtrace(fr, max > 128 ? 128 : max);
  for (int i = 0; i < n; i++) out[i] = (unsigned long long)(size_t)fr[i];
  return n;
#else
  (void)out; (void)max;
  return 0;
#endif
}

/* ---- inproc crash handler: async-signal-safe report, uploaded on the next start ---- */

static char g_dir[1024];
static char g_altstack[64 * 1024];
static const int SIGS[] = {SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL};

static size_t put_hex(char *o, unsigned long long v) {
  char t[17];
  size_t n = 0, l = 0;
  do { t[n++] = "0123456789abcdef"[v & 15]; v >>= 4; } while (v);
  while (n) o[l++] = t[--n];
  return l;
}

static const char *sig_name(int s) {
  switch (s) {
    case SIGSEGV: return "SIGSEGV\n";
    case SIGABRT: return "SIGABRT\n";
    case SIGBUS: return "SIGBUS\n";
    case SIGFPE: return "SIGFPE\n";
    default: return "SIGILL\n";
  }
}

static void on_signal(int sig) {
  char path[1100], line[24];
  size_t l = 0, d = strlen(g_dir);
  memcpy(path, g_dir, d);
  l = d;
  path[l++] = '/';
  l += put_hex(path + l, (unsigned long long)getpid());
  memcpy(path + l, ".wtcrash", 9);
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd >= 0) {
    ssize_t w = write(fd, sig_name(sig), strlen(sig_name(sig)));
    (void)w;
#ifdef WT_HAVE_BACKTRACE
    void *fr[64];
    int n = backtrace(fr, 64);
    for (int i = 0; i < n; i++) {
      size_t k = put_hex(line, (unsigned long long)(size_t)fr[i]);
      line[k++] = '\n';
      w = write(fd, line, k);
    }
#endif
    close(fd);
  }
  signal(sig, SIG_DFL);
  raise(sig);
}

int wt_crash_install(const char *dir) {
  struct sigaction sa;
  stack_t ss;
#ifdef WT_HAVE_BACKTRACE
  void *warm[2];
  backtrace(warm, 2); /* loads libgcc now, not inside the handler */
#endif
  snprintf(g_dir, sizeof g_dir, "%s", dir);
  ss.ss_sp = g_altstack;
  ss.ss_size = sizeof g_altstack;
  ss.ss_flags = 0;
  sigaltstack(&ss, NULL);
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = on_signal;
  sa.sa_flags = SA_ONSTACK;
  sigemptyset(&sa.sa_mask);
  for (size_t i = 0; i < sizeof SIGS / sizeof SIGS[0]; i++) sigaction(SIGS[i], &sa, NULL);
  return 0;
}

/* ---- default transport ---- */

#ifdef WT_HAVE_CURL
int wt_default_post(void *ud, const char *url, const char *key, const void *body, size_t len) {
  static int once;
  (void)ud;
  if (!once) { curl_global_init(CURL_GLOBAL_DEFAULT); once = 1; }
  CURL *c = curl_easy_init();
  if (!c) return WT_SEND_RETRY;
  char auth[1024];
  snprintf(auth, sizeof auth, "Authorization: Bearer %s", key);
  struct curl_slist *h = curl_slist_append(NULL, auth);
  h = curl_slist_append(h, "Content-Type: application/x-sentry-envelope");
  curl_easy_setopt(c, CURLOPT_URL, url);
  curl_easy_setopt(c, CURLOPT_HTTPHEADER, h);
  curl_easy_setopt(c, CURLOPT_POSTFIELDS, body);
  curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)len);
  curl_easy_setopt(c, CURLOPT_TIMEOUT, 10L);
  curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
  CURLcode rc = curl_easy_perform(c);
  long code = 0;
  curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
  curl_slist_free_all(h);
  curl_easy_cleanup(c);
  if (rc != CURLE_OK || code == 429 || code >= 500) return WT_SEND_RETRY;
  return code >= 200 && code < 300 ? WT_SEND_OK : WT_SEND_DROP;
}
#else
int wt_default_post(void *ud, const char *url, const char *key, const void *body, size_t len) {
  (void)ud; (void)url; (void)key; (void)body; (void)len;
  return WT_SEND_DROP; /* built without libcurl: set wt_options.transport */
}
#endif

#ifndef WT_CRASHPAD
int wt_crashpad_start(const char *h, const char *d) { (void)h; (void)d; return -1; }
#endif
#endif

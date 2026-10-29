#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include "internal.h"
#include "watchtower.h"
#include <windows.h>
#include <bcrypt.h>
#include <dbghelp.h>
#include <winhttp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static SRWLOCK g_mu = SRWLOCK_INIT;
void wt_lock(void) { AcquireSRWLockExclusive(&g_mu); }
void wt_unlock(void) { ReleaseSRWLockExclusive(&g_mu); }

const char *wt_os_name(void) { return "Windows"; }

static int wide(const char *s, wchar_t *w, int n) { return MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n) > 0; }

void wt_random(unsigned char *out, size_t n) {
  if (BCryptGenRandom(NULL, out, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
    for (size_t i = 0; i < n; i++) out[i] = (unsigned char)(rand() ^ (int)GetTickCount());
}

int wt_mkdirs(const char *path) {
  wchar_t w[1100];
  if (!wide(path, w, 1100)) return -1;
  for (wchar_t *c = w + 1; *c; c++)
    if (*c == L'/' || *c == L'\\') { wchar_t t = *c; *c = 0; CreateDirectoryW(w, NULL); *c = t; }
  return CreateDirectoryW(w, NULL) || GetLastError() == ERROR_ALREADY_EXISTS ? 0 : -1;
}

void wt_listdir(const char *dir, const char *suffix, wt_dir_cb cb, void *ud) {
  wchar_t pat[1100];
  WIN32_FIND_DATAW fd;
  char name[1400], path[1500];
  if (!wide(dir, pat, 1000)) return;
  wcscat(pat, L"\\*");
  HANDLE h = FindFirstFileW(pat, &fd);
  if (h == INVALID_HANDLE_VALUE) return;
  size_t sl = strlen(suffix);
  do {
    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
    if (!WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1, name, sizeof name, NULL, NULL)) continue;
    size_t l = strlen(name);
    if (l < sl || _stricmp(name + l - sl, suffix) != 0) continue;
    ULARGE_INTEGER t;
    t.LowPart = fd.ftLastWriteTime.dwLowDateTime;
    t.HighPart = fd.ftLastWriteTime.dwHighDateTime;
    snprintf(path, sizeof path, "%s\\%s", dir, name);
    if (cb(ud, path, (long long)(t.QuadPart / 10000000ULL - 11644473600ULL))) break;
  } while (FindNextFileW(h, &fd));
  FindClose(h);
}

char *wt_read_file(const char *path, size_t *len) {
  wchar_t w[1500];
  if (!wide(path, w, 1500)) return NULL;
  FILE *f = _wfopen(w, L"rb");
  if (!f) return NULL;
  size_t cap = 4096, n = 0, r;
  char *b = (char *)malloc(cap + 1);
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
  wchar_t w[1500];
  if (!wide(path, w, 1500)) return -1;
  FILE *f = _wfopen(w, L"wb");
  if (!f) return -1;
  int ok = fwrite(d, 1, n, f) == n;
  return (fclose(f) == 0 && ok) ? 0 : -1;
}

void wt_remove(const char *path) {
  wchar_t w[1500];
  if (wide(path, w, 1500)) DeleteFileW(w);
}

int wt_backtrace(unsigned long long *out, int max) {
  void *fr[62];
  int n = (int)CaptureStackBackTrace(0, max > 62 ? 62 : (DWORD)max, fr, NULL);
  for (int i = 0; i < n; i++) out[i] = (unsigned long long)(size_t)fr[i];
  return n;
}

/* ---- crash handler: a real minidump, uploaded on the next start ---- */

static wchar_t g_dir[1100];

static LONG WINAPI on_exception(EXCEPTION_POINTERS *ep) {
  wchar_t path[1200];
  swprintf(path, 1200, L"%ls\\%lu.dmp", g_dir, GetCurrentProcessId());
  HANDLE f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (f != INVALID_HANDLE_VALUE) {
    MINIDUMP_EXCEPTION_INFORMATION mei;
    mei.ThreadId = GetCurrentThreadId();
    mei.ExceptionPointers = ep;
    mei.ClientPointers = FALSE;
    MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), f, MiniDumpWithThreadInfo, &mei, NULL, NULL);
    CloseHandle(f);
  }
  return EXCEPTION_CONTINUE_SEARCH; /* let Windows Error Reporting and debuggers see it too */
}

int wt_crash_install(const char *dir) {
  if (!wide(dir, g_dir, 1100)) return -1;
  SetUnhandledExceptionFilter(on_exception);
  return 0;
}

/* ---- default transport: WinHTTP ---- */

int wt_default_post(void *ud, const char *url, const char *key, const void *body, size_t len) {
  wchar_t wurl[1100], host[256], path[1024], hdr[1100], k[900];
  URL_COMPONENTS uc;
  int result = WT_SEND_RETRY;
  (void)ud;
  if (!wide(url, wurl, 1100) || !wide(key, k, 900)) return WT_SEND_DROP;
  memset(&uc, 0, sizeof uc);
  uc.dwStructSize = sizeof uc;
  uc.lpszHostName = host; uc.dwHostNameLength = 256;
  uc.lpszUrlPath = path; uc.dwUrlPathLength = 1024;
  if (!WinHttpCrackUrl(wurl, 0, 0, &uc)) return WT_SEND_DROP;
  swprintf(hdr, 1100, L"Authorization: Bearer %ls\r\nContent-Type: application/x-sentry-envelope", k);
  HINTERNET s = WinHttpOpen(L"watchtower-native/" L"0.1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
  HINTERNET c = s ? WinHttpConnect(s, host, uc.nPort, 0) : NULL;
  HINTERNET r = c ? WinHttpOpenRequest(c, L"POST", path, NULL, NULL, NULL,
                                       uc.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0) : NULL;
  if (r && WinHttpSendRequest(r, hdr, (DWORD)-1, (LPVOID)body, (DWORD)len, (DWORD)len, 0) &&
      WinHttpReceiveResponse(r, NULL)) {
    DWORD code = 0, sz = sizeof code;
    WinHttpQueryHeaders(r, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &code, &sz, NULL);
    if (code >= 200 && code < 300) result = WT_SEND_OK;
    else if (code != 429 && code < 500) result = WT_SEND_DROP;
  }
  if (r) WinHttpCloseHandle(r);
  if (c) WinHttpCloseHandle(c);
  if (s) WinHttpCloseHandle(s);
  return result;
}

#ifndef WT_CRASHPAD
int wt_crashpad_start(const char *h, const char *d) { (void)h; (void)d; return -1; }
#endif
#endif

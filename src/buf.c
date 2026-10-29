#include "internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void wt_buf_add(wt_buf *b, const void *d, size_t n) {
  if (b->oom) return;
  if (b->len + n + 1 > b->cap) {
    size_t c = b->cap ? b->cap : 256;
    while (c < b->len + n + 1) c *= 2;
    char *p = (char *)realloc(b->p, c);
    if (!p) { b->oom = 1; return; }
    b->p = p;
    b->cap = c;
  }
  memcpy(b->p + b->len, d, n);
  b->len += n;
  b->p[b->len] = 0;
}
void wt_buf_puts(wt_buf *b, const char *s) { wt_buf_add(b, s, strlen(s)); }
void wt_buf_printf(wt_buf *b, const char *fmt, ...) {
  char tmp[512];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
  va_end(ap);
  if (n > 0 && (size_t)n < sizeof tmp) wt_buf_add(b, tmp, (size_t)n);
  else b->oom = 1; /* callers only format short numbers and ids */
}
void wt_buf_json_str(wt_buf *b, const char *s) {
  if (!s) { wt_buf_puts(b, "null"); return; }
  wt_buf_add(b, "\"", 1);
  for (; *s; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\') { char e[2] = {'\\', (char)c}; wt_buf_add(b, e, 2); }
    else if (c == '\n') wt_buf_puts(b, "\\n");
    else if (c == '\r') wt_buf_puts(b, "\\r");
    else if (c == '\t') wt_buf_puts(b, "\\t");
    else if (c < 0x20) wt_buf_printf(b, "\\u%04x", c);
    else wt_buf_add(b, &c, 1);
  }
  wt_buf_add(b, "\"", 1);
}
void wt_buf_free(wt_buf *b) { free(b->p); memset(b, 0, sizeof *b); }
char *wt_strdup(const char *s) {
  if (!s) return NULL;
  size_t n = strlen(s) + 1;
  char *p = (char *)malloc(n);
  if (p) memcpy(p, s, n);
  return p;
}

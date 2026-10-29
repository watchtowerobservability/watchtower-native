#ifndef WT_INTERNAL_H
#define WT_INTERNAL_H
#include <stdarg.h>
#include <stddef.h>

typedef struct { char *p; size_t len, cap; int oom; } wt_buf;
void wt_buf_add(wt_buf *b, const void *d, size_t n);
void wt_buf_puts(wt_buf *b, const char *s);
void wt_buf_printf(wt_buf *b, const char *fmt, ...);
void wt_buf_json_str(wt_buf *b, const char *s); /* quoted and escaped; NULL -> null */
void wt_buf_free(wt_buf *b);
char *wt_strdup(const char *s);

/* platform */
void wt_lock(void);
void wt_unlock(void);
void wt_random(unsigned char *out, size_t n);
int wt_mkdirs(const char *path);
/* cb returns nonzero to stop */
typedef int (*wt_dir_cb)(void *ud, const char *path, long long mtime);
void wt_listdir(const char *dir, const char *suffix, wt_dir_cb cb, void *ud);
char *wt_read_file(const char *path, size_t *len); /* malloc'd, NUL-terminated */
int wt_write_file(const char *path, const void *d, size_t n);
void wt_remove(const char *path);
int wt_backtrace(unsigned long long *out, int max); /* innermost first */
int wt_default_post(void *ud, const char *url, const char *key, const void *body, size_t len);
int wt_crash_install(const char *dir); /* dir exists; dumps/reports are written there */
const char *wt_os_name(void);

/* optional Crashpad backend (crashpad.cc); returns 0 on success */
int wt_crashpad_start(const char *handler, const char *db_dir);
#endif

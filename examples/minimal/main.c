/* Minimal app: sends a message and a handled error, then crashes on purpose when WT_DEMO_CRASH=1.
 * Run it twice with a cache dir: the second run uploads the crash from the first.
 *   WT_PUBLISHABLE_KEY=... WT_OTLP_ENDPOINT=https://... WT_DEMO_CRASH=1 ./wt_example */
#include <stdio.h>
#include <stdlib.h>
#include "watchtower.h"

int main(void) {
  wt_options o;
  wt_options_init(&o);
  o.cache_dir = ".wt-cache";
  o.release = "example@0.1.0";
  if (wt_init(&o) != 0) {
    fprintf(stderr, "set WT_PUBLISHABLE_KEY\n");
    return 1;
  }
  wt_add_breadcrumb("app", "started", WT_INFO);
  wt_capture_message(WT_INFO, "hello from the native SDK");
  wt_capture_error("ExampleError", "handled, with a stack");
  if (getenv("WT_DEMO_CRASH")) {
    volatile int *p = NULL;
    *p = 1;
  }
  wt_close();
  return 0;
}

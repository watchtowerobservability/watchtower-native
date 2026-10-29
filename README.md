# watchtower-native (C and C++)

[![CI](https://github.com/watchtowerobservability/watchtower-native/actions/workflows/ci.yml/badge.svg)](https://github.com/watchtowerobservability/watchtower-native/actions/workflows/ci.yml)

Native crash and error reporting for desktop apps and games. A small C11 library with a C API that
works from C++ too. It sends Sentry-format envelopes to the Watchtower edge, so native crashes link to
traces, logs and releases in the same store.

## Install

CMake (needs libcurl on Linux and macOS; Windows uses WinHTTP):

```cmake
include(FetchContent)
FetchContent_Declare(watchtower URL https://github.com/watchtowerobservability/watchtower-native/releases/download/v0.1.0/watchtower-native-v0.1.0-src.tar.gz)
FetchContent_MakeAvailable(watchtower)
target_link_libraries(app PRIVATE Watchtower::watchtower)
```

Or install a release archive and use `find_package(watchtower REQUIRED)`.

## Quick start

```c
#include "watchtower.h"
wt_options o; wt_options_init(&o);
o.release = "app@1.4.0"; o.cache_dir = "/var/tmp/app-wt";   /* key: env WT_PUBLISHABLE_KEY */
wt_init(&o);
wt_add_breadcrumb("ui", "opened settings", WT_INFO);
wt_capture_error("IoError", "disk full");
```

A runnable version is in `examples/minimal/main.c`.

## Crashes

Set `cache_dir` and the SDK installs a crash handler. The report is written while crashing and uploaded by
the next `wt_init`, so no network code runs inside a broken process.

| Platform | Default handler | Result |
| --- | --- | --- |
| Windows | `SetUnhandledExceptionFilter` + `MiniDumpWriteDump` | minidump, symbolicated by the edge |
| Linux, macOS | in-process signal handler (SIGSEGV, SIGABRT, SIGBUS, SIGFPE, SIGILL) | signal name and raw stack addresses |
| Any | Crashpad (`-DWT_CRASHPAD=ON`, set `crashpad_handler`) | out-of-process minidump, symbolicated by the edge |

Upload debug files (dSYM, PDB, ELF) with `wtctl` so minidump frames resolve. The in-process fallback on
POSIX sends addresses only; use Crashpad for fully symbolicated native crashes there.

## Integrations

| Integration | Status |
| --- | --- |
| C and C++ API | yes |
| Crashpad | optional (`-DWT_CRASHPAD=ON`) |
| Windows minidumps | yes |
| POSIX signal handler | yes |
| Offline queue | yes (`cache_dir`, 30 envelopes) |
| Unity / Unreal / Godot | separate packages |

## Configuration

| Option | Environment | Default |
| --- | --- | --- |
| `publishable_key` | `WT_PUBLISHABLE_KEY` | required, a publishable key (never a secret ingest key) |
| `endpoint` | `WT_OTLP_ENDPOINT` | `http://localhost:4318` |
| `service` | `WT_SERVICE` | none |
| `environment` | `WT_ENVIRONMENT` | none |
| `release` | `WT_RELEASE` | none |
| `cache_dir` | | none (no crash capture, no offline queue) |
| `redact` | | none; return a replacement for any string field |
| `transport` | | libcurl / WinHTTP |

Keys go out as `Authorization: Bearer <key>` and are never logged or printed; `wt_mask_key` gives a safe
form for your own logs. Tags and extras whose key starts with `wt.` are ignored. Sending is synchronous
and bounded by a 10 s timeout; the redaction hook must not call back into the SDK.

## Provenance

Every release artifact carries a GitHub build attestation. Verify one with
`gh attestation verify <file> --repo watchtowerobservability/watchtower-native`.

## License

Apache-2.0. Source of truth is the Watchtower monorepo; this repository is a published mirror.

# Changelog

## 0.1.0

- C API: `wt_init`, `wt_capture_message`, `wt_capture_error`, breadcrumbs, user, tags, extra, trace link.
- Envelope transport with `Authorization: Bearer`, libcurl (POSIX) and WinHTTP (Windows), custom transport hook.
- Crash capture: in-process signal handler (POSIX), minidump via `MiniDumpWriteDump` (Windows), optional Crashpad.
  Crashes are uploaded on the next start, minidumps as `event.minidump` attachments.
- Disk offline queue, redaction hook, `wt.*` keys ignored, key masking helper.
- CMake package `Watchtower::watchtower`.

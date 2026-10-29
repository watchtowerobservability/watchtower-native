// Optional Crashpad backend (BSD-3). Built with -DWT_CRASHPAD=ON. The handler only writes dumps into
// <cache_dir>/crashpad; uploads are off here because the next wt_init sends them as envelope attachments.
#include <filesystem>
#include <map>
#include <string>
#include <vector>

#include "client/crash_report_database.h"
#include "client/crashpad_client.h"
#include "client/settings.h"

extern "C" int wt_crashpad_start(const char* handler, const char* db_dir) {
  namespace fs = std::filesystem;
  base::FilePath h(fs::path(handler).native());
  base::FilePath db(fs::path(db_dir).native());
  auto database = crashpad::CrashReportDatabase::Initialize(db);
  if (!database || !database->GetSettings()) return -1;
  database->GetSettings()->SetUploadsEnabled(false);
  static crashpad::CrashpadClient client;
  return client.StartHandler(h, db, db, /*url=*/"", std::map<std::string, std::string>{},
                             std::vector<std::string>{"--no-rate-limit"},
                             /*restartable=*/true, /*asynchronous_start=*/false)
             ? 0
             : -1;
}

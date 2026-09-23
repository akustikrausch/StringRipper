#pragma once

#include "workspace.hpp"
#include <filesystem>
#include <memory>
#include <sqlite3.h>

namespace ur {

// Infrastructure adapter. The scanner and domain model never depend on SQLite.
class SessionStore {
public:
    explicit SessionStore(const std::filesystem::path& file);
    ~SessionStore();
    SessionStore(const SessionStore&) = delete;
    SessionStore& operator=(const SessionStore&) = delete;

    int64_t saveSession(const Session& session);
    std::vector<Session> listSessions() const;
    Session loadSession(int64_t id) const;
    void saveJob(const ScanJob& job);
    std::vector<std::string> listJobs() const;
    std::optional<ScanJob> loadJob(const std::string& name) const;
    void setFavorite(const std::string& kind, const std::string& target, bool favorite);
    std::vector<std::string> favorites(const std::string& kind) const;

private:
    sqlite3* db_ = nullptr;
    void exec(const char* sql) const;
};

} // namespace ur

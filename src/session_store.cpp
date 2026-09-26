#include "session_store.hpp"

#include <stdexcept>

namespace ur {
namespace {
using Statement = std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>;
Statement prepare(sqlite3* db, const char* sql) {
    sqlite3_stmt* ptr = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &ptr, nullptr) != SQLITE_OK)
        throw std::runtime_error(sqlite3_errmsg(db));
    return {ptr, sqlite3_finalize};
}
void bindText(sqlite3_stmt* st, int index, const std::string& value) {
    if (sqlite3_bind_text(st, index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT) != SQLITE_OK)
        throw std::runtime_error("SQLite text binding failed");
}
std::string column(sqlite3_stmt* st, int index) {
    auto data = sqlite3_column_text(st, index);
    auto size = sqlite3_column_bytes(st, index);
    return data ? std::string(reinterpret_cast<const char*>(data), size) : std::string();
}
void stepDone(sqlite3* db, sqlite3_stmt* st) {
    if (sqlite3_step(st) != SQLITE_DONE) throw std::runtime_error(sqlite3_errmsg(db));
}
}

SessionStore::SessionStore(const std::filesystem::path& file) {
    auto utf8 = file.u8string();
    std::string name(utf8.begin(), utf8.end());
    if (sqlite3_open_v2(name.c_str(), &db_, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
        std::string error = db_ ? sqlite3_errmsg(db_) : "SQLite open failed";
        if (db_) sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error(error);
    }
    sqlite3_busy_timeout(db_, 5000);
    try {
        exec("PRAGMA foreign_keys=ON;");
        exec("CREATE TABLE IF NOT EXISTS sessions(id INTEGER PRIMARY KEY, name TEXT NOT NULL, source TEXT NOT NULL, created TEXT NOT NULL DEFAULT (datetime('now')));");
        exec("CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, group_name TEXT NOT NULL, value TEXT NOT NULL, encoding INTEGER NOT NULL, source TEXT NOT NULL, offset INTEGER, before_text TEXT NOT NULL, after_text TEXT NOT NULL);");
        exec("CREATE INDEX IF NOT EXISTS findings_session ON findings(session_id);");
        exec("CREATE TABLE IF NOT EXISTS captures(finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE, name TEXT NOT NULL, value TEXT NOT NULL);");
        exec("CREATE TABLE IF NOT EXISTS jobs(name TEXT PRIMARY KEY, payload TEXT NOT NULL);");
        exec("CREATE TABLE IF NOT EXISTS favorites(kind TEXT NOT NULL, target TEXT NOT NULL, PRIMARY KEY(kind,target));");
        exec("CREATE TABLE IF NOT EXISTS ignore_rules(pos INTEGER PRIMARY KEY, rule TEXT NOT NULL);");
    } catch (...) {
        sqlite3_close(db_);
        db_ = nullptr;
        throw;
    }
}
SessionStore::~SessionStore() { if (db_) sqlite3_close(db_); }
void SessionStore::exec(const char* sql) const {
    char* error = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &error) != SQLITE_OK) {
        std::string message = error ? error : "SQLite error";
        sqlite3_free(error);
        throw std::runtime_error(message);
    }
}

int64_t SessionStore::saveSession(const Session& session) {
    exec("BEGIN IMMEDIATE");
    try {
        auto header = prepare(db_, "INSERT INTO sessions(name,source,created) VALUES(?,?,COALESCE(NULLIF(?,''),datetime('now')))");
        bindText(header.get(), 1, session.name); bindText(header.get(), 2, session.source);
        bindText(header.get(), 3, session.created); stepDone(db_, header.get());
        int64_t id = sqlite3_last_insert_rowid(db_);
        auto finding = prepare(db_, "INSERT INTO findings(session_id,group_name,value,encoding,source,offset,before_text,after_text) VALUES(?,?,?,?,?,?,?,?)");
        auto capture = prepare(db_, "INSERT INTO captures(finding_id,name,value) VALUES(?,?,?)");
        for (const auto& group : session.groups) for (const auto& item : group.items) {
            sqlite3_reset(finding.get()); sqlite3_clear_bindings(finding.get());
            sqlite3_bind_int64(finding.get(), 1, id);
            bindText(finding.get(), 2, group.name); bindText(finding.get(), 3, item.value);
            sqlite3_bind_int(finding.get(), 4, static_cast<int>(item.enc));
            bindText(finding.get(), 5, item.source);
            if (item.hasOffset) sqlite3_bind_int64(finding.get(), 6, static_cast<sqlite3_int64>(item.offset));
            bindText(finding.get(), 7, item.before); bindText(finding.get(), 8, item.after);
            stepDone(db_, finding.get());
            int64_t findingId = sqlite3_last_insert_rowid(db_);
            for (const auto& [name, value] : item.captures) {
                sqlite3_reset(capture.get()); sqlite3_clear_bindings(capture.get());
                sqlite3_bind_int64(capture.get(), 1, findingId);
                bindText(capture.get(), 2, name); bindText(capture.get(), 3, value);
                stepDone(db_, capture.get());
            }
        }
        exec("COMMIT");
        return id;
    } catch (...) { try { exec("ROLLBACK"); } catch (...) {} throw; }
}

std::vector<Session> SessionStore::listSessions() const {
    auto st = prepare(db_, "SELECT id,name,source,created FROM sessions ORDER BY id DESC");
    std::vector<Session> result;
    while (sqlite3_step(st.get()) == SQLITE_ROW)
        result.push_back({sqlite3_column_int64(st.get(), 0), column(st.get(), 1), column(st.get(), 2), column(st.get(), 3), {}});
    return result;
}
Session SessionStore::loadSession(int64_t id) const {
    auto header = prepare(db_, "SELECT name,source,created FROM sessions WHERE id=?");
    sqlite3_bind_int64(header.get(), 1, id);
    if (sqlite3_step(header.get()) != SQLITE_ROW) throw std::runtime_error("Session not found");
    Session out{id, column(header.get(), 0), column(header.get(), 1), column(header.get(), 2), {}};
    auto st = prepare(db_, "SELECT id,group_name,value,encoding,source,offset,before_text,after_text FROM findings WHERE session_id=? ORDER BY id");
    sqlite3_bind_int64(st.get(), 1, id);
    auto cap = prepare(db_, "SELECT name,value FROM captures WHERE finding_id=? ORDER BY rowid");
    while (sqlite3_step(st.get()) == SQLITE_ROW) {
        auto group = column(st.get(), 1);
        if (out.groups.empty() || out.groups.back().name != group) out.groups.push_back({group, {}});
        Finding f{column(st.get(), 2), static_cast<Enc>(sqlite3_column_int(st.get(), 3)), column(st.get(), 4), group};
        f.hasOffset = sqlite3_column_type(st.get(), 5) != SQLITE_NULL;
        if (f.hasOffset) f.offset = static_cast<uint64_t>(sqlite3_column_int64(st.get(), 5));
        f.before = column(st.get(), 6); f.after = column(st.get(), 7);
        sqlite3_reset(cap.get()); sqlite3_clear_bindings(cap.get());
        sqlite3_bind_int64(cap.get(), 1, sqlite3_column_int64(st.get(), 0));
        while (sqlite3_step(cap.get()) == SQLITE_ROW) f.captures.emplace_back(column(cap.get(), 0), column(cap.get(), 1));
        out.groups.back().items.push_back(std::move(f));
    }
    return out;
}
void SessionStore::saveJob(const ScanJob& job) {
    auto st = prepare(db_, "INSERT INTO jobs(name,payload) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET payload=excluded.payload");
    auto payload = serializeJob(job);
    if (payload.empty()) throw std::runtime_error("Job serialization failed");
    bindText(st.get(), 1, job.name); bindText(st.get(), 2, payload); stepDone(db_, st.get());
}
std::vector<std::string> SessionStore::listJobs() const {
    auto st = prepare(db_, "SELECT name FROM jobs ORDER BY name COLLATE NOCASE");
    std::vector<std::string> out;
    while (sqlite3_step(st.get()) == SQLITE_ROW) out.push_back(column(st.get(), 0));
    return out;
}
std::optional<ScanJob> SessionStore::loadJob(const std::string& name) const {
    auto st = prepare(db_, "SELECT payload FROM jobs WHERE name=?"); bindText(st.get(), 1, name);
    if (sqlite3_step(st.get()) != SQLITE_ROW) return std::nullopt;
    return parseJob(column(st.get(), 0));
}
void SessionStore::setFavorite(const std::string& kind, const std::string& target, bool favorite) {
    auto st = prepare(db_, favorite ? "INSERT OR IGNORE INTO favorites(kind,target) VALUES(?,?)" :
                                    "DELETE FROM favorites WHERE kind=? AND target=?");
    bindText(st.get(), 1, kind); bindText(st.get(), 2, target); stepDone(db_, st.get());
}
std::vector<std::string> SessionStore::ignoreRules() const {
    auto st = prepare(db_, "SELECT rule FROM ignore_rules ORDER BY pos");
    std::vector<std::string> out;
    while (sqlite3_step(st.get()) == SQLITE_ROW) out.push_back(column(st.get(), 0));
    return out;
}
void SessionStore::setIgnoreRules(const std::vector<std::string>& rules) {
    exec("BEGIN IMMEDIATE");
    try {
        exec("DELETE FROM ignore_rules");
        auto st = prepare(db_, "INSERT INTO ignore_rules(rule) VALUES(?)");
        for (const auto& rule : rules) {
            sqlite3_reset(st.get()); sqlite3_clear_bindings(st.get());
            bindText(st.get(), 1, rule); stepDone(db_, st.get());
        }
        exec("COMMIT");
    } catch (...) { try { exec("ROLLBACK"); } catch (...) {} throw; }
}
std::vector<std::string> SessionStore::favorites(const std::string& kind) const {
    auto st = prepare(db_, "SELECT target FROM favorites WHERE kind=? ORDER BY target COLLATE NOCASE"); bindText(st.get(), 1, kind);
    std::vector<std::string> out;
    while (sqlite3_step(st.get()) == SQLITE_ROW) out.push_back(column(st.get(), 0));
    return out;
}
} // namespace ur

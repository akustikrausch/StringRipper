/* auto-updater, adapted from FXChainPlayer's UpdateManager (src/updates/).
   Same routine: fetch a latest.json manifest from the GitHub /releases/latest/
   alias, compare versions, download the asset, verify its SHA256, then hand
   over. The divergence: StringRipper ships one portable exe, not an Inno
   installer, so "install" self-replaces the running exe and relaunches. Win32 +
   WinHTTP + bcrypt instead of Qt. User presets (regex-user-presets.ini next to
   the exe) and the workspace database are never touched. */
#pragma once

#include "update_validation.hpp"

#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <array>
#include <atomic>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

namespace ur {

struct UpdateInfo {
    std::string version;      // manifest "version"
    std::string url;          // installer.url (the new StringRipper.exe)
    std::string sha256;       // installer.sha256, lowercase hex
    long long   size = 0;     // installer.size
    std::string changelog;    // manifest "changelog"
    std::string minVersion;   // manifest "minVersion"
    std::string notes;        // release page, manual-download fallback
};

// U10/U14 port: trim, strip a -pre/+build suffix, compare every numeric
// segment (a 4-segment hotfix must register as newer than a 3-segment release).
inline bool isNewerVersion(const std::string& remote, const std::string& local) {
    auto norm = [](std::string v) {
        std::size_t a = v.find_first_not_of(" \t\r\n");
        std::size_t b = v.find_last_not_of(" \t\r\n");
        v = (a == std::string::npos) ? "" : v.substr(a, b - a + 1);
        auto cut = v.find_first_of("-+");
        return cut == std::string::npos ? v : v.substr(0, cut);
    };
    auto split = [](const std::string& v) {
        std::vector<int> out; std::size_t i = 0;
        while (i <= v.size()) {
            std::size_t dot = v.find('.', i);
            std::string seg = v.substr(i, dot == std::string::npos ? std::string::npos : dot - i);
            int n = 0; for (char c : seg) { if (c < '0' || c > '9') { n = 0; break; } n = n * 10 + (c - '0'); }
            out.push_back(n);
            if (dot == std::string::npos) break;
            i = dot + 1;
        }
        return out;
    };
    auto r = split(norm(remote)), l = split(norm(local));
    std::size_t n = r.size() > l.size() ? r.size() : l.size();
    for (std::size_t i = 0; i < n; ++i) {
        int rv = i < r.size() ? r[i] : 0, lv = i < l.size() ? l[i] : 0;
        if (rv != lv) return rv > lv;
    }
    return false;
}

inline std::string sha256Hex(const void* data, std::size_t len) {
    BCRYPT_ALG_HANDLE alg = nullptr; BCRYPT_HASH_HANDLE h = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return {};
    unsigned char digest[32]; std::string out;
    if (BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0) == 0) {
        if (BCryptHashData(h, (PUCHAR)data, (ULONG)len, 0) == 0 &&
            BCryptFinishHash(h, digest, sizeof(digest), 0) == 0) {
            static const char* x = "0123456789abcdef";
            for (unsigned char b : digest) { out += x[b >> 4]; out += x[b & 15]; }
        }
        BCryptDestroyHash(h);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return out;
}

inline std::string sha256File(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return {};
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::string out;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return {};
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0) {
        std::array<char, 65536> buf;
        bool ok = true;
        while (file) {
            file.read(buf.data(), buf.size());
            const auto got = file.gcount();
            if (got && BCryptHashData(hash, reinterpret_cast<PUCHAR>(buf.data()), ULONG(got), 0) != 0) {
                ok = false; break;
            }
        }
        unsigned char digest[32];
        if (ok && file.eof() && BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0) {
            static const char* hex = "0123456789abcdef";
            for (unsigned char b : digest) { out += hex[b >> 4]; out += hex[b & 15]; }
        }
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return out;
}

// Fixed-shape manifest: every key we read (version, url, size, sha256,
// changelog, minVersion, notes) is unique across the document, so a flat
// search by "key" needs no object-brace tracking. Only the installer block
// carries url/size/sha256.
namespace detail {
inline std::string jsonUnescape(const std::string& s) {
    std::string o; o.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '\\' || i + 1 >= s.size()) { o += s[i]; continue; }
        char c = s[++i];
        switch (c) {
            case 'n': o += '\n'; break; case 't': o += '\t'; break;
            case 'r': o += '\r'; break; case '/': o += '/'; break;
            case '"': o += '"'; break; case '\\': o += '\\'; break;
            case 'u': {
                if (i + 4 < s.size()) {
                    int v = 0; bool ok = true;
                    for (int k = 1; k <= 4; ++k) { char d = s[i + k];
                        v <<= 4;
                        if (d >= '0' && d <= '9') v |= d - '0';
                        else if (d >= 'a' && d <= 'f') v |= d - 'a' + 10;
                        else if (d >= 'A' && d <= 'F') v |= d - 'A' + 10;
                        else { ok = false; break; } }
                    if (ok) { i += 4; if (v < 0x80) o += (char)v; else if (v < 0x800) {
                        o += (char)(0xC0 | (v >> 6)); o += (char)(0x80 | (v & 0x3F)); } else {
                        o += (char)(0xE0 | (v >> 12)); o += (char)(0x80 | ((v >> 6) & 0x3F));
                        o += (char)(0x80 | (v & 0x3F)); } }
                    else o += c;
                } else o += c;
                break;
            }
            default: o += c;
        }
    }
    return o;
}
inline std::size_t jsonValuePos(const std::string& j, const char* key) {
    std::string pat = std::string("\"") + key + "\"";
    std::size_t p = j.find(pat);
    if (p == std::string::npos) return std::string::npos;
    p = j.find(':', p + pat.size());
    if (p == std::string::npos) return std::string::npos;
    ++p; while (p < j.size() && (j[p] == ' ' || j[p] == '\t' || j[p] == '\n' || j[p] == '\r')) ++p;
    return p;
}
inline std::string jsonString(const std::string& j, const char* key) {
    std::size_t p = jsonValuePos(j, key);
    if (p == std::string::npos || j[p] != '"') return {};
    ++p; std::string raw;
    for (; p < j.size(); ++p) {
        if (j[p] == '\\' && p + 1 < j.size()) { raw += j[p]; raw += j[p + 1]; ++p; continue; }
        if (j[p] == '"') break;
        raw += j[p];
    }
    return jsonUnescape(raw);
}
inline long long jsonNumber(const std::string& j, const char* key) {
    std::size_t p = jsonValuePos(j, key);
    if (p == std::string::npos) return 0;
    long long n = 0; bool any = false;
    for (; p < j.size() && j[p] >= '0' && j[p] <= '9'; ++p) {
        const int digit = j[p] - '0';
        if (n > (std::numeric_limits<long long>::max() - digit) / 10) return 0;
        n = n * 10 + digit; any = true;
    }
    return any ? n : 0;
}
} // namespace detail

inline bool parseManifest(const std::string& json, UpdateInfo& info) {
    info.version = detail::jsonString(json, "version");
    if (!validUpdateVersion(info.version)) return false;
    info.url = detail::jsonString(json, "url");
    info.sha256 = detail::jsonString(json, "sha256");
    info.size = detail::jsonNumber(json, "size");
    info.changelog = detail::jsonString(json, "changelog");
    info.minVersion = detail::jsonString(json, "minVersion");
    if (!info.minVersion.empty() && !validUpdateVersion(info.minVersion)) return false;
    info.notes = detail::jsonString(json, "notes");
    if (!validUpdateNotes(info.notes)) info.notes.clear();
    return true;
}

struct HttpAsyncState {
    HANDLE ready = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    HANDLE closed = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::atomic<DWORD> status{0}, amount{0}, error{0};
    std::atomic<int> refs{2};
    ~HttpAsyncState() { CloseHandle(ready); CloseHandle(closed); }
    void release() { if (refs.fetch_sub(1) == 1) delete this; }
};

inline void CALLBACK httpStatus(HINTERNET, DWORD_PTR context, DWORD status, void* info, DWORD length) {
    auto* state = reinterpret_cast<HttpAsyncState*>(context);
    if (!state) return;
    if (status == WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING) {
        SetEvent(state->closed);
        state->release();
        return;
    }
    if (status == WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE && info)
        state->amount = *static_cast<DWORD*>(info);
    if (status == WINHTTP_CALLBACK_STATUS_READ_COMPLETE)
        state->amount = length;
    if (status == WINHTTP_CALLBACK_STATUS_REQUEST_ERROR && info)
        state->error = static_cast<WINHTTP_ASYNC_RESULT*>(info)->dwError;
    state->status = status;
    SetEvent(state->ready);
}

// WinHTTP GET into `out`. Follows https->https redirects (GitHub's asset alias
// hops to a signed CDN url). onProgress(received,total) may be null. Aborts past
// maxBytes so a hijacked manifest can't fill the disk (port of the C11 cap).
inline bool httpGet(const std::wstring& url, std::string& out, std::string* err,
                    long long maxBytes, const std::wstring& ua,
                    void (*onProgress)(long long, long long, void*) = nullptr,
                    void* progressCtx = nullptr, const std::atomic_bool* cancel = nullptr) {
    auto fail = [&](const char* m) { if (err) *err = m; return false; };
    URL_COMPONENTS uc{}; uc.dwStructSize = sizeof(uc);
    wchar_t host[256]{}, path[4096]{}, extra[4096]{};
    uc.lpszHostName = host; uc.dwHostNameLength = 255;
    uc.lpszUrlPath = path; uc.dwUrlPathLength = 4095;
    uc.lpszExtraInfo = extra; uc.dwExtraInfoLength = 4095;
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc)) return fail("bad update url");
    if (uc.nScheme != INTERNET_SCHEME_HTTPS) return fail("update url is not https");

    HINTERNET ses = WinHttpOpen(ua.c_str(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC);
    if (!ses) return fail("no internet connection");
    WinHttpSetTimeouts(ses, 10000, 10000, 30000, 30000);
    HINTERNET con = WinHttpConnect(ses, host, uc.nPort, 0);
    if (!con) { WinHttpCloseHandle(ses); return fail("no internet connection"); }
    const std::wstring target = std::wstring(path) + extra;
    HINTERNET req = WinHttpOpenRequest(con, L"GET", target.c_str(), nullptr, WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!req) { WinHttpCloseHandle(con); WinHttpCloseHandle(ses); return fail("no internet connection"); }
    auto* state = new HttpAsyncState;
    if (!state->ready || !state->closed ||
        WinHttpSetStatusCallback(req, httpStatus,
            WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS | WINHTTP_CALLBACK_FLAG_HANDLES,
            0) == WINHTTP_INVALID_STATUS_CALLBACK) {
        WinHttpCloseHandle(req); WinHttpCloseHandle(con); WinHttpCloseHandle(ses);
        delete state;
        return fail("no internet connection");
    }
    DWORD_PTR context = reinterpret_cast<DWORD_PTR>(state);
    if (!WinHttpSetOption(req, WINHTTP_OPTION_CONTEXT_VALUE, &context, sizeof(context))) {
        WinHttpCloseHandle(req); WinHttpCloseHandle(con); WinHttpCloseHandle(ses);
        delete state;
        return fail("no internet connection");
    }
    auto waitFor = [&](DWORD expected) {
        for (;;) {
            if (cancel && cancel->load()) return false;
            if (WaitForSingleObject(state->ready, 25) != WAIT_OBJECT_0) continue;
            const DWORD status = state->status.load();
            if (status == WINHTTP_CALLBACK_STATUS_REQUEST_ERROR) return false;
            if (status == expected) return true;
        }
    };
    auto started = [](BOOL result) { return result || GetLastError() == ERROR_IO_PENDING; };
    bool ok = false;
    if (!(cancel && cancel->load()) &&
        started(WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                  WINHTTP_NO_REQUEST_DATA, 0, 0, context)) &&
        waitFor(WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE) &&
        started(WinHttpReceiveResponse(req, nullptr)) &&
        waitFor(WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE)) {
        DWORD status = 0, sl = sizeof(status);
        if (WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX, &status, &sl, WINHTTP_NO_HEADER_INDEX) &&
            status == 200) {
            long long total = 0, got = 0;
            wchar_t clen[32]{}; DWORD cl = sizeof(clen);
            if (WinHttpQueryHeaders(req, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX,
                                    clen, &cl, WINHTTP_NO_HEADER_INDEX)) total = _wtoi64(clen);
            ok = true;
            for (;;) {
                if (!started(WinHttpQueryDataAvailable(req, nullptr)) ||
                    !waitFor(WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE)) { ok = false; break; }
                DWORD avail = state->amount.load();
                if (!avail) break;
                if (maxBytes > 0 && avail > static_cast<unsigned long long>(maxBytes - got)) {
                    ok = false; if (err) *err = "update file too large"; break;
                }
                std::string buf(avail, '\0');
                if (!started(WinHttpReadData(req, buf.data(), avail, nullptr)) ||
                    !waitFor(WINHTTP_CALLBACK_STATUS_READ_COMPLETE)) { ok = false; break; }
                const DWORD read = state->amount.load();
                if (!read) { ok = false; break; }
                out.append(buf.data(), read); got += read;
                if (onProgress) onProgress(got, total, progressCtx);
            }
        } else if (status == 404) {
            if (err) *err = "no release manifest found";
        } else if (err) *err = "update check failed";
    }
    if (!ok && err && err->empty()) *err = cancel && cancel->load() ? "cancelled" : "no internet connection";
    WinHttpCloseHandle(req);
    WaitForSingleObject(state->closed, 1500);
    state->release();
    WinHttpCloseHandle(con); WinHttpCloseHandle(ses);
    return ok;
}

/* Persisted preferences, StringRipper.update.ini next to the exe. Mirrors
   FXChainPlayer's updates.autoCheck / skippedVersion / cached snapshot. */
struct UpdatePrefs {
    bool autoCheck = true;
    bool asked = false;             // first-run consent answered
    std::string skipped;            // version the user chose to skip
    std::string cachedVersion, cachedUrl, cachedSha256, cachedChangelog;
    long long cachedSize = 0;

    static std::string trim(const std::string& s) {
        std::size_t a = s.find_first_not_of(" \t\r\n");
        std::size_t b = s.find_last_not_of(" \t\r\n");
        return a == std::string::npos ? "" : s.substr(a, b - a + 1);
    }
    void load(const std::filesystem::path& p) {
        std::ifstream f(p); std::string line;
        while (std::getline(f, line)) {
            auto eq = line.find('='); if (eq == std::string::npos) continue;
            std::string k = trim(line.substr(0, eq)), v = trim(line.substr(eq + 1));
            if (k == "autocheck") autoCheck = v != "0";
            else if (k == "asked") asked = v != "0";
            else if (k == "skipped") skipped = v;
            else if (k == "cached_version") cachedVersion = v;
            else if (k == "cached_url") cachedUrl = v;
            else if (k == "cached_sha256") cachedSha256 = v;
            else if (k == "cached_changelog") cachedChangelog = v;
            else if (k == "cached_size") cachedSize = _atoi64(v.c_str());
        }
    }
    void save(const std::filesystem::path& p) const {
        std::error_code ec; std::filesystem::create_directories(p.parent_path(), ec);
        std::ofstream f(p, std::ios::trunc);
        f << "autocheck=" << (autoCheck ? 1 : 0) << "\n"
          << "asked=" << (asked ? 1 : 0) << "\n"
          << "skipped=" << settingLine(skipped) << "\n"
          << "cached_version=" << settingLine(cachedVersion) << "\n"
          << "cached_url=" << settingLine(cachedUrl) << "\n"
          << "cached_sha256=" << settingLine(cachedSha256) << "\n"
          << "cached_changelog=" << settingLine(cachedChangelog) << "\n"
          << "cached_size=" << cachedSize << "\n";
    }
};

// Delete a leftover ".old" that a previous self-replace renamed the running
// exe to (a running exe can be renamed but not deleted; we clean it up next
// launch). Port of cleanupStaleDownloads, scoped to our own rename.
inline void cleanupSelfReplace() {
    wchar_t exe[MAX_PATH]{}; GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::error_code ec;
    std::filesystem::remove(std::filesystem::path(exe).concat(L".old"), ec);
}

// Rename the running exe aside and move the verified download into its place.
// Presets and workspace live elsewhere and are untouched. Returns false (and
// rolls back) when the exe's folder is not writable — the caller then falls
// back to opening the release page. Relaunch is separate (relaunchSelf) so the
// caller can release its single-instance mutex in between: otherwise the fresh
// process races the still-closing old one for the mutex and bows out, leaving
// nothing running after an update.
inline bool selfReplace(const std::filesystem::path& downloaded, const std::string& expectedHash, std::string* err) {
    std::string want = expectedHash;
    for (char& c : want) c = char(std::tolower(static_cast<unsigned char>(c)));
    if (sha256File(downloaded) != want) {
        if (err) *err = "the downloaded file changed (checksum mismatch)";
        return false;
    }
    wchar_t exeBuf[MAX_PATH]{}; GetModuleFileNameW(nullptr, exeBuf, MAX_PATH);
    std::filesystem::path exe = exeBuf, old = std::filesystem::path(exe).concat(L".old");
    std::filesystem::path stage = std::filesystem::path(exe).concat(L".new");
    std::error_code ec;
    std::filesystem::copy_file(downloaded, stage, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) { if (err) *err = "cannot stage update beside the exe"; return false; }
    if (sha256File(stage) != want) {
        std::filesystem::remove(stage, ec);
        if (err) *err = "the staged file changed (checksum mismatch)";
        return false;
    }
    std::filesystem::remove(old, ec);
    if (!MoveFileExW(exe.c_str(), old.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        std::filesystem::remove(stage, ec);
        if (err) *err = "cannot update in place (folder not writable)"; return false;
    }
    if (!MoveFileExW(stage.c_str(), exe.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        MoveFileExW(old.c_str(), exe.c_str(), MOVEFILE_REPLACE_EXISTING);   // roll back
        std::filesystem::remove(stage, ec);
        if (err) *err = "cannot write the new version"; return false;
    }
    std::filesystem::remove(downloaded, ec);
    return true;
}
inline void relaunchSelf() {
    wchar_t exe[MAX_PATH]{}; GetModuleFileNameW(nullptr, exe, MAX_PATH);
    STARTUPINFOW si{sizeof(si)}; PROCESS_INFORMATION pi{};
    std::wstring cmd = L"\"" + std::wstring(exe) + L"\"";
    if (CreateProcessW(exe, cmd.data(), nullptr, nullptr, FALSE, 0, nullptr,
                       std::filesystem::path(exe).parent_path().c_str(), &si, &pi)) {
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
}

} // namespace ur

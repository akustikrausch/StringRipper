#include "file_read.hpp"
#include "session_store.hpp"
#include <chrono>
#include <fstream>
#include <iostream>
#include <stdexcept>

int main() {
    namespace fs = std::filesystem;
    auto root = fs::temp_directory_path() /
        ("stringripper-workspace-test-" +
         std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    auto require = [](bool value, const char* reason) {
        if (!value) throw std::runtime_error(reason);
    };
    fs::create_directories(root / "ignored");
    { std::ofstream(root / "one.txt") << "KEY-42";
      std::ofstream(root / "two.bin") << "1234567890";
      std::ofstream(root / "ignored" / "three.txt") << "hidden"; }
    ur::FileSelection f;
    f.include = "*.txt"; f.exclude = "ignored"; f.minSize = 5; f.maxSize = 8;
    auto files = ur::expandInputs({root}, 0, {}, f);
    require(files.size() == 1 && files[0].filename() == "one.txt", "file selection");
    require(ur::globMatch("*.TXT", "one.txt"), "case-insensitive glob");
    require(!ur::globMatch("*.bin", "one.txt"), "glob exclusion");
    require(ur::patternListMatch("ignored/*.txt", root / "ignored" / "three.txt"),
            "relative folder pattern");
    auto other = f; other.rangeStart = 3;
    require(ur::selectionContext(f) != ur::selectionContext(other), "filter comparison identity");

    ur::ScanJob job{"Text files", {root}, 0, {}, f, 5};
    auto parsed = ur::parseJob(ur::serializeJob(job));
    require(parsed && parsed->sources == job.sources && parsed->files.exclude == "ignored" &&
            parsed->monitorSeconds == 5, "job roundtrip");
    require(!ur::parseJob("SRJOB2 invalid"), "invalid job rejection");

    {
        ur::SessionStore db(root / "workspace.sqlite");
        db.saveJob(job);
        require(db.listJobs().size() == 1, "job listing");
        require(db.loadJob("Text files")->monitorSeconds == 5, "job load");
        db.setFavorite("source", root.string(), true);
        require(db.favorites("source").size() == 1, "favorite add");
        db.setFavorite("source", root.string(), false);
        require(db.favorites("source").empty(), "favorite remove");

        ur::Finding first{"KEY-42", ur::Enc::Ascii, "one.txt", "Key"};
        first.hasOffset = true; first.offset = 16; first.before = "abc";
        first.captures = {{"number", "42"}};
        auto id1 = db.saveSession({0, "before", "files", "", {{"Key", {first}}}});
        ur::Finding second{"KEY-43", ur::Enc::Ascii, "one.txt", "Key"};
        auto id2 = db.saveSession({0, "after", "files", "", {{"Key", {second}}}});
        auto loaded = db.loadSession(id1);
        require(loaded.groups.size() == 1 && loaded.groups[0].items[0].offset == 16, "session load");
        require(loaded.groups[0].items[0].captures[0].second == "42", "capture persistence");
        auto delta = ur::compareSessions(loaded.groups, db.loadSession(id2).groups);
        require(delta.added[0].items[0].value == "KEY-43", "added diff");
        require(delta.removed[0].items[0].value == "KEY-42", "removed diff");
        require(delta.unchanged.empty(), "unchanged diff");

        // several groups in one session
        ur::Finding ga1{"a1", ur::Enc::Ascii, "s", "GroupA"};
        ur::Finding ga2{"a2", ur::Enc::Ascii, "s", "GroupA"};
        ur::Finding gb1{"b1", ur::Enc::Ascii, "s", "GroupB"};
        ur::Finding gc1{"c1", ur::Enc::Ascii, "s", "GroupC"};
        auto id3 = db.saveSession({0, "multi", "files", "",
                                   {{"GroupA", {ga1, ga2}}, {"GroupB", {gb1}}, {"GroupC", {gc1}}}});
        auto multi = db.loadSession(id3);
        require(multi.groups.size() == 3, "multi-group session keeps distinct groups");
        require(multi.groups[0].name == "GroupA" && multi.groups[0].items.size() == 2,
                "multi-group session: first group intact");
        require(multi.groups[1].name == "GroupB" && multi.groups[1].items.size() == 1,
                "multi-group session: second group not merged into the first");
        require(multi.groups[2].name == "GroupC" && multi.groups[2].items.size() == 1,
                "multi-group session: third group intact");
    }
    fs::remove_all(root);
    std::cout << "workspace tests passed\n";
}

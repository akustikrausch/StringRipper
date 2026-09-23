#include "scan_driver.hpp"
#include <chrono>
#include <cstdio>
#include <cstring>
int main(int argc, char**) {
    ur::Options o;
    if (argc > 1) { o.utf16 = false; o.hex = false; o.base64 = false; }
    if (argc > 2) { o.mode = ur::Mode::Regex; o.customRegex = R"(https://[a-z.]+/[a-z/]+)"; }
    ur::Detector det(o);
    std::vector<uint8_t> data(32u << 20, 0);
    const char* s = "log entry: https://service.example.com/download/path timestamp=2026-09-23";
    for (size_t i = 0; i + 128 < data.size(); i += 128) std::memcpy(data.data()+i, s, std::strlen(s));
    std::vector<double> times;
    for (int run=0; run<5; ++run) {
        auto start = std::chrono::steady_clock::now();
        ur::ScanPool pool(det, 0, 64u << 20);
        ur::DriverLimits lim;
        for (size_t i=0; i<data.size(); i+=lim.window) {
            auto n=std::min(lim.window,data.size()-i);
            std::vector<uint8_t> buf(data.begin()+i,data.begin()+i+n);
            pool.submit(std::move(buf),"benchmark");
        }
        auto g=pool.finish();
        if (ur::countFindings(g)!=1) return 1;
        times.push_back(std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count());
    }
    std::sort(times.begin(),times.end());
    std::printf("median=%.4fs throughput=%.1f MiB/s\n", times[2],32.0/times[2]);
}

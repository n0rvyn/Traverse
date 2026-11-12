#include "capture_backend.hpp"
#include <gst/gst.h>
#include <iostream>
#include <limits>
#include <stdexcept>
static void require(bool result) { if (!result) throw std::runtime_error("Capture contract mismatch"); }
template<class F> static void rejected(F action) {
    try { action(); } catch (const std::invalid_argument &) { return; }
    throw std::runtime_error("Invalid capture input was accepted");
}
int main(int argc, char **argv) {
    gst_init(&argc, &argv);
    using Capture = traverse::PipeWireCapture;
    traverse::PortalSession::Stream stream{}; stream.node = 38;
    try {
        require(Capture::target(stream) == "38");
        stream.serial = 9007199254740993ULL;
        require(Capture::target(stream) == "9007199254740993");
        stream.serial = std::numeric_limits<std::uint64_t>::max();
        require(Capture::target(stream) == "18446744073709551615");
        stream.serial = 0; rejected([&] { Capture::target(stream); });
        stream.serial.reset(); stream.node = 0; rejected([&] { Capture::target(stream); });
        stream.node = std::numeric_limits<std::uint32_t>::max();
        rejected([&] { Capture::target(stream); }); stream.node = 38;
        Capture::Options options{"/tmp", "video/x-raw,format=I420,framerate=60/1"};
        Capture::validate(options);
        for (const char *caps : {"ANY", "audio/x-raw,format=S16LE,rate=48000", "video/x-raw",
             "video/x-raw,format=I420,framerate=0/1", "video/x-raw,format=BAD,framerate=60/1",
             "video/x-raw,format=I420,framerate=60/1,width=-1",
             "video/x-raw,format=I420,framerate=[1/1,60/1]"}) {
            auto invalid = options; invalid.output_caps = caps;
            rejected([&] { Capture::validate(invalid); });
        }
        rejected([&] { Capture capture({}, stream, options); });
        std::cout << "Exact 64-bit targets, explicit video settings and authority boundary passed\n";
    } catch (const std::exception &error) { std::cerr << error.what() << '\n'; return 1; }
}

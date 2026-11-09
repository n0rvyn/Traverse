#include <gst/gst.h>
#include <iostream>
#include <nlohmann/json.hpp>
int main(int argc, char **argv) {
    gst_init(&argc, &argv);
    nlohmann::json result = {{"gstreamer", gst_version_string()},
                             {"plugins", nlohmann::json::object()}};
    bool ok = true;
    for (const char *name :
         {"ximagesrc", "videoconvert", "unixfdsink", "unixfdsrc", "vp8enc", "rtpvp8pay",
          "webrtcbin", "nicesrc", "dtlsenc", "srtpenc", "sctpenc"}) {
        auto *factory = gst_element_factory_find(name);
        result["plugins"][name] = factory != nullptr;
        ok = ok && factory;
        if (factory)
            gst_object_unref(factory);
    }
    result["ok"] = ok;
    std::cout << result.dump(2) << '\n';
    return ok ? 0 : 1;
}

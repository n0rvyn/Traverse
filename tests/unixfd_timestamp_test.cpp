#include <gst/app/gstappsink.h>
#include <gst/gst.h>
#include <cmath>
#include <filesystem>
#include <grp.h>
#include <iostream>
#include <stdexcept>
#include <unistd.h>
// An actual non-system pipeline clock, not a stub transport or fake buffer.
struct OffsetClock { GstSystemClock parent; };
struct OffsetClockClass { GstSystemClockClass parent; };
static gint64 clock_offset = 0;
G_DEFINE_TYPE(OffsetClock, offset_clock, GST_TYPE_SYSTEM_CLOCK)
static GstClockTime offset_time(GstClock *) { return g_get_monotonic_time() * GST_USECOND + clock_offset; }
static void offset_clock_class_init(OffsetClockClass *klass) { GST_CLOCK_CLASS(klass)->get_internal_time = offset_time; }
static void offset_clock_init(OffsetClock *) {}
struct Pipeline {
    GstElement *value = nullptr;
    explicit Pipeline(const std::string &description) {
        GError *error = nullptr; value = gst_parse_launch(description.c_str(), &error);
        if (error || !value) {
            std::string message = error ? error->message : "Pipeline unavailable";
            g_clear_error(&error); if (value) gst_object_unref(value);
            value = nullptr; throw std::runtime_error(message);
        }
    }
    ~Pipeline() { gst_element_set_state(value, GST_STATE_NULL); gst_object_unref(value); }
    void start() { if (gst_element_set_state(value, GST_STATE_PLAYING) == GST_STATE_CHANGE_FAILURE) throw std::runtime_error("Timestamp transport start failed"); }
};
int main(int argc, char **argv) {
    if (!geteuid() && (setgroups(0, nullptr) || setgid(65534) || setuid(65534))) return 1;
    gst_init(&argc, &argv);
    char pattern[] = "/tmp/unixfd-time-XXXXXX";
    const char *created = mkdtemp(pattern); if (!created) return 1;
    const std::string root = created, path = root + "/f";
    try {
        for (const gint64 offset : {30 * static_cast<gint64>(GST_SECOND), -30 * static_cast<gint64>(GST_SECOND)}) {
            clock_offset = offset;
            Pipeline sender("videotestsrc is-live=true ! video/x-raw,format=I420,width=64,height=48,framerate=30/1 ! unixfdsink socket-path=" + path + " wait-for-connection=false sync=false");
            auto *clock = GST_CLOCK(g_object_new(offset_clock_get_type(), nullptr));
            gst_pipeline_use_clock(GST_PIPELINE(sender.value), clock); gst_object_unref(clock);
            sender.start();
            Pipeline receiver("unixfdsrc socket-path=" + path + " ! appsink name=result sync=false");
            receiver.start();
            auto *sink = gst_bin_get_by_name(GST_BIN(receiver.value), "result");
            GstClockTime first = GST_CLOCK_TIME_NONE, last = GST_CLOCK_TIME_NONE;
            for (int i = 0; i < 4; ++i) {
                auto *sample = gst_app_sink_try_pull_sample(GST_APP_SINK(sink), 5 * GST_SECOND);
                if (!sample) { gst_object_unref(sink); throw std::runtime_error("Actual receiver sample watchdog expired"); }
                last = GST_BUFFER_PTS(gst_sample_get_buffer(sample));
                if (i == 0) first = last;
                gst_sample_unref(sample);
            }
            gst_object_unref(sink);
            const auto running = gst_element_get_current_running_time(receiver.value);
            std::cout << "clockOffset=" << offset << " first=" << first << " last=" << last << " receiverRunning=" << running << std::endl;
            if (!GST_CLOCK_TIME_IS_VALID(first) || !GST_CLOCK_TIME_IS_VALID(last) || last <= first ||
                std::fabs(static_cast<double>(last) - static_cast<double>(running)) > GST_SECOND / 2.0)
                throw std::runtime_error("Unix-FD transport did not preserve monotonic presentation timing");
        }
        std::filesystem::remove(root); return 0;
    } catch (const std::exception &error) {
        std::filesystem::remove(root); std::cerr << error.what() << '\n'; return 1;
    }
}

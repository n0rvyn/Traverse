#include "conversion_policy.hpp"
#include <gst/app/gstappsrc.h>
#include <gst/app/gstappsink.h>
#include <gst/video/video.h>
#include <sys/wait.h>
#include <unistd.h>
#include <array>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>

static void require(bool value, const char *message) {
    if (!value) throw std::runtime_error(message);
}

static void affinity_test() {
    cpu_set_t original;
    require(sched_getaffinity(0, sizeof(original), &original) == 0, "read affinity");
    const pid_t child = fork();
    require(child >= 0, "fork affinity child");
    if (child == 0) {
        cpu_set_t single;
        CPU_ZERO(&single);
        for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
            if (CPU_ISSET(cpu, &original)) { CPU_SET(cpu, &single); break; }
        }
        if (sched_setaffinity(0, sizeof(single), &single) != 0) _exit(2);
        _exit(traverse::conversion_threads() == 1 ? 0 : 3);
    }
    int status = 0;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "one CPU must use one conversion worker");
    cpu_set_t after;
    require(sched_getaffinity(0, sizeof(after), &after) == 0 && CPU_EQUAL(&original, &after),
            "parent affinity changed");
    require(traverse::conversion_threads() == (CPU_COUNT(&original) >= 2 ? 2U : 1U),
            "effective affinity policy");
}

struct Pipeline {
    GstElement *value = nullptr;
    ~Pipeline() { if (value) { gst_element_set_state(value, GST_STATE_NULL); gst_object_unref(value); } }
};
struct Sample {
    GstSample *value = nullptr;
    ~Sample() { if (value) gst_sample_unref(value); }
};

static std::vector<std::vector<guint8>> convert(const char *format, int width, int height, unsigned threads) {
    Pipeline pipeline;
    pipeline.value = gst_pipeline_new(nullptr);
    require(pipeline.value, "pipeline allocation");
    auto *source = gst_element_factory_make("appsrc", nullptr);
    auto *converter = gst_element_factory_make("videoconvert", nullptr);
    auto *sink = gst_element_factory_make("appsink", nullptr);
    require(source && converter && sink, "conversion plugins unavailable");
    gst_bin_add_many(GST_BIN(pipeline.value), source, converter, sink, nullptr);
    GstVideoInfo input;
    gst_video_info_init(&input);
    require(gst_video_info_set_format(&input, gst_video_format_from_string(format), width, height), "input format");
    input.fps_n = 60; input.fps_d = 1;
    GstCaps *caps = gst_video_info_to_caps(&input);
    gst_app_src_set_caps(GST_APP_SRC(source), caps);
    gst_caps_unref(caps);
    g_object_set(source, "format", GST_FORMAT_TIME, nullptr);
    g_object_set(converter, "n-threads", threads, nullptr);
    caps = gst_caps_new_simple("video/x-raw", "format", G_TYPE_STRING, "I420", nullptr);
    gst_app_sink_set_caps(GST_APP_SINK(sink), caps);
    gst_caps_unref(caps);
    g_object_set(sink, "sync", FALSE, "max-buffers", 1U, nullptr);
    require(gst_element_link_many(source, converter, sink, nullptr), "link conversion pipeline");
    require(gst_element_set_state(pipeline.value, GST_STATE_PLAYING) != GST_STATE_CHANGE_FAILURE, "start conversion");
    std::vector<std::vector<guint8>> frames;
    for (unsigned frame = 0; frame < 8; ++frame) {
        GstBuffer *buffer = gst_buffer_new_allocate(nullptr, input.size, nullptr);
        require(buffer, "input allocation");
        GstMapInfo map;
        if (!gst_buffer_map(buffer, &map, GST_MAP_WRITE)) { gst_buffer_unref(buffer); throw std::runtime_error("map input"); }
        std::memset(map.data, 0, map.size);
        for (int y = 0; y < height; ++y) for (int x = 0; x < width; ++x) {
            auto *pixel = map.data + input.offset[0] + y * input.stride[0] + x * 4;
            // Moving gradients, single-pixel edges and colored text-like boundaries.
            const unsigned edge = ((x + frame * 3) % 19 == 0 || (y + frame) % 13 == 0) ? 255 : 0;
            pixel[0] = static_cast<guint8>((x * 7 + y + frame * 31 + edge) % 256);
            pixel[1] = static_cast<guint8>((y * 11 + frame * 17 + edge) % 256);
            pixel[2] = static_cast<guint8>((x + y * 3 + frame * 43) % 256);
            if (frame < 2) { // Repeated grayscale high-frequency frame.
                pixel[0] = pixel[1] = pixel[2] = ((x + y) & 1) ? 255 : 0;
            }
            pixel[3] = 255;
        }
        gst_buffer_unmap(buffer, &map);
        GST_BUFFER_PTS(buffer) = frame * GST_SECOND / 60;
        GST_BUFFER_DURATION(buffer) = GST_SECOND / 60;
        require(gst_app_src_push_buffer(GST_APP_SRC(source), buffer) == GST_FLOW_OK, "push input");
        Sample sample;
        sample.value = gst_app_sink_try_pull_sample(GST_APP_SINK(sink), 5 * GST_SECOND);
        require(sample.value, "conversion output timeout");
        GstVideoInfo output;
        gst_video_info_init(&output);
        require(gst_video_info_from_caps(&output, gst_sample_get_caps(sample.value)), "output caps");
        require(GST_VIDEO_INFO_FORMAT(&output) == GST_VIDEO_FORMAT_I420 &&
                output.width == width && output.height == height && output.fps_n == 60 && output.fps_d == 1,
                "output profile changed");
        require(GST_BUFFER_PTS(gst_sample_get_buffer(sample.value)) == frame * GST_SECOND / 60, "output timestamp changed");
        GstVideoFrame view;
        require(gst_video_frame_map(&view, &output, gst_sample_get_buffer(sample.value), GST_MAP_READ), "map output");
        std::vector<guint8> active;
        active.reserve(width * height * 2);
        for (unsigned component = 0; component < 3; ++component) {
            const int rows = GST_VIDEO_FRAME_COMP_HEIGHT(&view, component);
            const int columns = GST_VIDEO_FRAME_COMP_WIDTH(&view, component);
            const int expected_width = component == 0 ? width : (width + 1) / 2;
            const int expected_height = component == 0 ? height : (height + 1) / 2;
            if (columns != expected_width || rows != expected_height) {
                gst_video_frame_unmap(&view); throw std::runtime_error("active plane dimensions");
            }
            const auto *data = GST_VIDEO_FRAME_COMP_DATA(&view, component);
            const int stride = GST_VIDEO_FRAME_COMP_STRIDE(&view, component);
            for (int row = 0; row < rows; ++row)
                active.insert(active.end(), data + row * stride, data + row * stride + columns);
        }
        gst_video_frame_unmap(&view);
        frames.push_back(std::move(active));
    }
    require(gst_app_src_end_of_stream(GST_APP_SRC(source)) == GST_FLOW_OK, "end input");
    require(frames[0] == frames[1], "repeated input changed output");
    require(frames.front() != frames.back(), "changing input produced unchanged output");
    return frames;
}

int main(int argc, char **argv) {
    try {
        affinity_test(); // Before GStreamer creates any worker threads.
        gst_init(&argc, &argv);
        unsigned cases = 0;
        for (const char *format : {"BGRx", "RGBx", "BGRA", "RGBA"})
            for (const auto &size : {std::array<int, 2>{1280, 720}, {641, 479}, {1279, 719}}) {
                const auto single = convert(format, size[0], size[1], 1);
                const auto parallel = convert(format, size[0], size[1], 2);
                require(single == parallel, "parallel conversion changed active pixels");
                ++cases;
            }
        std::cout << cases << " profiles, 96 changing frames: active pixels identical; affinity policy passed\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n'; return 1;
    }
}

#pragma once
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <filesystem>
#include <fstream>
#include <functional>
#include <gst/gst.h>
#include <httplib.h>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>
using json = nlohmann::json;
using Clock = std::chrono::steady_clock;
inline std::atomic<bool> stopping{false};
inline void signal_stop(int) {
    stopping.store(true);
}
inline std::string random_secret(size_t bytes) {
    std::vector<unsigned char> data(bytes);
    if (RAND_bytes(data.data(), static_cast<int>(bytes)) != 1)
        throw std::runtime_error("Random generator failed");
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    for (auto b : data) {
        result += hex[b >> 4];
        result += hex[b & 15];
    }
    return result;
}
inline bool equal_secret(const std::string &a, const std::string &b) {
    return !a.empty() && a.size() == b.size() && CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}
inline std::string bearer(const httplib::Request &r) {
    auto value = r.get_header_value("Authorization");
    return value.rfind("Bearer ", 0) == 0 ? value.substr(7) : "";
}
inline void reply(httplib::Response &r, const json &j, int status = 200) {
    r.status = status;
    r.set_content(j.dump(), "application/json");
    r.set_header("Cache-Control", "no-store");
}
inline json parse_body(const httplib::Request &r) {
    return json::parse(r.body);
}
struct Args {
    std::map<std::string, std::string> values;
    Args(int argc, char **argv) {
        for (int i = 1; i < argc; i++) {
            std::string key = argv[i];
            if (key.rfind("--", 0) != 0)
                throw std::runtime_error("Expected --option");
            if (i + 1 < argc && std::string(argv[i + 1]).rfind("--", 0) != 0)
                values[key] = argv[++i];
            else
                values[key] = "true";
        }
    }
    std::string get(const std::string &k, const std::string &fallback = "") const {
        auto it = values.find(k);
        return it == values.end() ? fallback : it->second;
    }
    bool has(const std::string &k) const {
        return values.count(k) > 0;
    }
};
inline std::string default_socket() {
    return "/run/user/" + std::to_string(getuid()) + "/traverse/adapter.sock";
}
struct Ipc {
    std::string path;
    explicit Ipc(std::string p) : path(std::move(p)) {}
    json call(const std::string &route, const json *body = nullptr,
              const std::string &token = "") const {
        httplib::Client client(path, 80);
        client.set_address_family(AF_UNIX);
        client.set_connection_timeout(1, 0);
        client.set_read_timeout(2, 0);
        client.set_write_timeout(2, 0);
        httplib::Headers headers;
        if (!token.empty())
            headers.emplace("Authorization", "Bearer " + token);
        auto result = body ? client.Post(route, headers, body->dump(), "application/json")
                           : client.Get(route, headers);
        if (!result)
            throw std::runtime_error("Desktop adapter unavailable");
        if (result->status != 200) {
            auto error = json::parse(result->body, nullptr, false);
            throw std::runtime_error(
                error.is_object() ? error.value("error", std::string("Desktop request rejected"))
                                  : "Desktop request rejected");
        }
        return json::parse(result->body);
    }
};
inline void check_bus(GstElement *pipeline) {
    GstBus *bus = gst_element_get_bus(pipeline);
    GstMessage *m =
        gst_bus_pop_filtered(bus, static_cast<GstMessageType>(GST_MESSAGE_ERROR | GST_MESSAGE_EOS));
    gst_object_unref(bus);
    if (m) {
        std::string message = "Media stream ended";
        if (GST_MESSAGE_TYPE(m) == GST_MESSAGE_ERROR) {
            GError *error = nullptr;
            gchar *debug = nullptr;
            gst_message_parse_error(m, &error, &debug);
            message = std::string(GST_OBJECT_NAME(GST_MESSAGE_SRC(m))) + ": " +
                      (error ? error->message : "Media error");
            if (debug)
                message += std::string(" [") + debug + "]";
            if (error)
                g_error_free(error);
            g_free(debug);
        }
        gst_message_unref(m);
        throw std::runtime_error(message);
    }
}
inline GstElement *parse_pipeline(const std::string &text) {
    GError *error = nullptr;
    auto *p = gst_parse_launch(text.c_str(), &error);
    if (error) {
        std::string msg = error->message;
        g_error_free(error);
        if (p)
            gst_object_unref(p);
        throw std::runtime_error(msg);
    }
    return p;
}
inline void stop_pipeline(GstElement *&p) {
    if (p) {
        gst_element_set_state(p, GST_STATE_NULL);
        gst_object_unref(p);
        p = nullptr;
    }
}
int input_worker(const std::string &display_name);

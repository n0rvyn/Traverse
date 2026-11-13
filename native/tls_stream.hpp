#pragma once
#include <array>
#include <atomic>
#include <cstddef>
#include <functional>
#include <openssl/ssl.h>
#include <vector>

namespace traverse {
using TlsStreamTransform = std::function<std::vector<unsigned char>(
    const unsigned char *, std::size_t, bool tls_to_plain)>;
struct TlsStreamBuffer {
    std::array<unsigned char, 16384> data{};
    std::size_t size = 0, offset = 0;
    std::vector<unsigned char> admitted;
    bool empty() const { return offset == size; }
    const unsigned char *pending() const {
        return (admitted.empty() ? data.data() : admitted.data()) + offset;
    }
};
// The existing unfiltered frontend flow and the probe TLS client share the
// same nonblocking, full-duplex forwarding. Only probes supply a transform.
void forward_tls_stream(SSL *ssl, int tls_fd, int plain_fd,
                        const std::atomic<bool> &stopped, TlsStreamBuffer &to_plain,
                        const TlsStreamTransform *transform = nullptr);
}

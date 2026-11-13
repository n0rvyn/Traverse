#include "tls_stream.hpp"
#include <cerrno>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace traverse {
namespace {
short ssl_wait(int error) { return error == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN; }
bool retryable(int error) { return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE; }
void received(TlsStreamBuffer &buffer, std::size_t size,
              const TlsStreamTransform *transform, bool from_tls) {
    buffer.offset = 0;
    buffer.size = size;
    buffer.admitted.clear();
    if (transform) {
        buffer.admitted = (*transform)(buffer.data.data(), size, from_tls);
        buffer.size = buffer.admitted.size();
    }
}
}
void forward_tls_stream(SSL *ssl, int tls_fd, int plain_fd,
                        const std::atomic<bool> &stopped, TlsStreamBuffer &outgoing,
                        const TlsStreamTransform *transform) {
    TlsStreamBuffer incoming;
    if (transform && !outgoing.empty()) {
        auto admitted = (*transform)(outgoing.pending(), outgoing.size - outgoing.offset, true);
        outgoing.admitted = std::move(admitted);
        outgoing.offset = 0;
        outgoing.size = outgoing.admitted.size();
    }
    bool front_eof = false, back_eof = false, back_write_closed = false;
    short read_wait = POLLIN, write_wait = POLLOUT;
    while (!stopped) {
        if (front_eof && outgoing.empty() && !back_write_closed) {
            shutdown(plain_fd, SHUT_WR);
            back_write_closed = true;
        }
        if (back_eof && incoming.empty()) {
            SSL_shutdown(ssl);
            return;
        }
        pollfd fds[2]{{tls_fd, 0, 0}, {plain_fd, 0, 0}};
        if (!front_eof && outgoing.empty())
            fds[0].events |= read_wait;
        if (!incoming.empty())
            fds[0].events |= write_wait;
        if (!back_eof && incoming.empty())
            fds[1].events |= POLLIN;
        if (!outgoing.empty())
            fds[1].events |= POLLOUT;
        bool pending = !front_eof && outgoing.empty() && SSL_pending(ssl) > 0;
        int ready = poll(fds, 2, pending ? 0 : 100);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            return;
        }
        if (!outgoing.empty() && (fds[1].revents & (POLLOUT | POLLHUP | POLLERR))) {
            ssize_t n = send(plain_fd, outgoing.pending(),
                             outgoing.size - outgoing.offset, MSG_NOSIGNAL);
            if (n > 0)
                outgoing.offset += n;
            else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                return;
        }
        if (!front_eof && outgoing.empty() &&
            (pending || (fds[0].revents & (read_wait | POLLHUP | POLLERR)))) {
            size_t n = 0;
            int result = SSL_read_ex(ssl, outgoing.data.data(), outgoing.data.size(), &n);
            if (result == 1) {
                received(outgoing, n, transform, true);
                read_wait = POLLIN;
            } else {
                int error = SSL_get_error(ssl, result);
                if (error == SSL_ERROR_ZERO_RETURN)
                    front_eof = true;
                else if (retryable(error))
                    read_wait = ssl_wait(error);
                else
                    return;
            }
        }
        if (!incoming.empty() && (fds[0].revents & (write_wait | POLLHUP | POLLERR))) {
            size_t n = 0;
            int result = SSL_write_ex(ssl, incoming.pending(),
                                      incoming.size - incoming.offset, &n);
            if (result == 1) {
                incoming.offset += n;
                write_wait = POLLOUT;
            } else {
                int error = SSL_get_error(ssl, result);
                if (retryable(error))
                    write_wait = ssl_wait(error);
                else
                    return;
            }
        }
        if (!back_eof && incoming.empty() && (fds[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n = recv(plain_fd, incoming.data.data(), incoming.data.size(), 0);
            if (n > 0) {
                received(incoming, static_cast<std::size_t>(n), transform, false);
            } else if (!n)
                back_eof = true;
            else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                return;
        }
    }
}
}

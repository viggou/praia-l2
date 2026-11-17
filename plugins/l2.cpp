#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#define _XOPEN_SOURCE 700

#include "praia_plugin.h"
#include "signal_state.h"

#include <atomic>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <csignal>
#include <cstring>
#include <mutex>
#include <poll.h>
#include <unordered_set>
#include <vector>

PRAIA_DECLARE_ABI();
PRAIA_PLUGIN_METADATA("l2", "1.1.1",
                     "Raw L2 (Ethernet) socket access");

#ifdef __linux__
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if_arp.h>
#elif defined(__APPLE__)
#include <sys/types.h>
#include <sys/socket.h>
#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <ifaddrs.h>
#endif

// A raw socket handle. Async tasks can share one, so:
//   recvMu serializes receives (held through a waiting recv()),
//   sendMu serializes sends, so a send isn't stuck behind a recv,
//   closing is set first thing in close(): a waiting recv() sees it
//   within one poll slice and returns, and no new call starts.
// close() then takes both locks before closing the fd, so neither side
// ever uses a closed (or reused) descriptor.
struct L2Socket {
    std::timed_mutex recvMu;
    std::timed_mutex sendMu;
    std::atomic<bool> closing{false};
    // close() wants the fd closed. Whoever holds sendMu when they see it,
    // close() itself or a send finishing, takes it (by exchange) and
    // closes: see close()
    std::atomic<bool> closePending{false};
    int fd = -1;
    int ifIndex = 0;
    // How long recv() waits; 0: until a frame arrives. Atomic, so
    // setTimeout() doesn't wait for a recv() in progress
    std::atomic<int> timeoutMs{0};
    std::string ifName;
    // macOS: one BPF read can hold several frames; recv() hands them out
    // one at a time from here
    std::vector<uint8_t> bpfBuf;
    size_t bpfOff = 0, bpfLen = 0;
};
static const char* kSocketType = "l2.socket";

// Live sockets, for the exit hook. Leaked on purpose: deleters can run
// during process teardown, after statics are destroyed
static std::mutex g_regMu;
static auto* g_sockets = new std::unordered_set<L2Socket*>();

// Closes the fd. Call with both locks held, or (close()) with sendMu
// held once closing is set and recvMu has been passed through
static void closeFd(L2Socket* s) {
    if (s->fd >= 0) ::close(s->fd);
    s->fd = -1;
}

// The handle's deleter. Nothing else can be using it (whoever did held a
// reference), so the locks are uncontended
static void freeSocket(L2Socket* s) {
    {
        std::lock_guard<std::mutex> reg(g_regMu);
        g_sockets->erase(s);
    }
    {
        std::lock_guard<std::timed_mutex> r(s->recvMu);
        std::lock_guard<std::timed_mutex> w(s->sendMu);
        closeFd(s);
    }
    delete s;
}

// Process-exit hook — close any raw sockets still open on script crashes
// or sys.exit(). An unawaited task may still be in recv(); it returns
// within one poll slice of seeing closing, so the wait here is short
extern "C" void praia_at_exit(void) {
    std::lock_guard<std::mutex> reg(g_regMu);
    for (auto* s : *g_sockets) {
        s->closing = true;
        std::unique_lock<std::timed_mutex> r(s->recvMu, std::chrono::milliseconds(250));
        std::unique_lock<std::timed_mutex> w(s->sendMu, std::chrono::milliseconds(250));
        if (r.owns_lock() && w.owns_lock()) closeFd(s);
    }
}

// ── Helpers ──

[[noreturn]] static void sysError(const std::string& what) {
    praia::error(what + ": " + std::strerror(errno));
}

static L2Socket* argSocket(const std::vector<Value>& args, size_t i, const std::string& fn) {
    if (i >= args.size() || !args[i].isExternal())
        praia::error(fn + "() argument " + std::to_string(i + 1) + " must be an l2 socket");
    return praia::getExternal<L2Socket>(args[i], kSocketType);
}

// Ctrl+C is pending. Calls then return nil promptly and leave the bit
// set: the engine takes it at its next yield point, once, and throws
// "Interrupted" or runs the script's SIGINT handler. Throwing here
// instead (without consuming the bit) interrupted again in the catch
// block, the next call and the engine's next check
static bool interrupted() {
    return g_pendingSignals.load(std::memory_order_relaxed) & (1u << SIGINT);
}

static bool cancelled() {
    auto c = praia::shouldCancel();
    return c && *c;
}

using Clock = std::chrono::steady_clock;

// Milliseconds left until deadline, rounded up, at most cap
static int sliceUntil(Clock::time_point deadline, int cap) {
    auto left = std::chrono::ceil<std::chrono::milliseconds>(deadline - Clock::now()).count();
    return static_cast<int>(std::max<long long>(0, std::min<long long>(left, cap)));
}

// Takes `lock` in short waits, giving up (false) if the call is cancelled,
// Ctrl+C is pending, or the deadline (if any) passes meanwhile. A socket
// already closed throws; one closed while waiting throws too, unless
// closedIsNil (recv, which returns nil when closed while it waits)
static bool acquire(std::unique_lock<std::timed_mutex>& lock, L2Socket* s,
                    const std::string& fn, const Clock::time_point* deadline = nullptr,
                    bool closedIsNil = false) {
    if (s->closing) praia::error(fn + "(): the socket is closed");
    while (true) {
        if (interrupted()) return false;
        if (s->closing) {
            if (closedIsNil) return false;
            praia::error(fn + "(): the socket is closed");
        }
        if (cancelled()) return false;
        if (lock.owns_lock()) return true;
        int wait = 50;
        if (deadline) {
            if (Clock::now() >= *deadline) return false;
            wait = std::max(1, sliceUntil(*deadline, 50));
        }
        if (lock.try_lock_for(std::chrono::milliseconds(wait)))
            continue;   // held: check once more
    }
}

#ifdef __APPLE__
// The next frame left in the BPF buffer, or false if none is
static bool nextBpfFrame(L2Socket* s, std::string& frame) {
    // The header as the kernel writes it ends at bh_hdrlen: 18 bytes, while
    // sizeof(struct bpf_hdr) adds padding to 20. bh_hdrlen itself is
    // often 18 (for Ethernet, so the frame's IP header lands aligned)
    const size_t kHdrMin = offsetof(struct bpf_hdr, bh_hdrlen) +
                           sizeof(((struct bpf_hdr*)nullptr)->bh_hdrlen);
    while (s->bpfOff < s->bpfLen) {
        size_t left = s->bpfLen - s->bpfOff;
        if (left < kHdrMin) break;
        auto* hdr = reinterpret_cast<const struct bpf_hdr*>(s->bpfBuf.data() + s->bpfOff);
        size_t total = static_cast<size_t>(hdr->bh_hdrlen) + hdr->bh_caplen;
        if (hdr->bh_hdrlen < kHdrMin || total > left) break;
        frame.assign(reinterpret_cast<const char*>(s->bpfBuf.data() + s->bpfOff + hdr->bh_hdrlen),
                     hdr->bh_caplen);
        s->bpfOff += BPF_WORDALIGN(total);
        return true;
    }
    s->bpfOff = s->bpfLen = 0;
    return false;
}
#endif

static bool getIfaceMac(const std::string& ifName, uint8_t* mac) {
#ifdef __linux__
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return false;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifName.c_str(), IFNAMSIZ - 1);
    bool ok = ioctl(fd, SIOCGIFHWADDR, &ifr) == 0;
    if (ok) memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return ok;
#elif defined(__APPLE__)
    struct ifaddrs* ifap;
    if (getifaddrs(&ifap) != 0) return false;
    bool found = false;
    for (auto* ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_LINK &&
            ifName == ifa->ifa_name) {
            auto* sdl = (struct sockaddr_dl*)ifa->ifa_addr;
            if (sdl->sdl_alen == 6) {
                memcpy(mac, LLADDR(sdl), 6);
                found = true;
                break;
            }
        }
    }
    freeifaddrs(ifap);
    return found;
#else
    return false;
#endif
}

extern "C" void praia_register(PraiaMap* module) {
    // l2.open(interface) -> handle
    module->entries["open"] = Value(makeNative("l2.open", 1,
        [](const std::vector<Value>& args) -> Value {
            const std::string fn = "l2.open";
            const auto& ifName = praia::requireString(args, 0, fn);
            if (ifName.empty() || ifName.size() >= IFNAMSIZ)
                praia::error(fn + "(): invalid interface name: " + ifName);
            int fd = -1;
            int ifIndex = 0;
            std::vector<uint8_t> bpfBuf;

#ifdef __linux__
            fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
            if (fd < 0)
                sysError(fn + "(): can't create a raw socket (need root or CAP_NET_RAW?)");

            ifIndex = static_cast<int>(if_nametoindex(ifName.c_str()));
            if (ifIndex == 0) {
                // It needs a socket itself, so it can also fail for want
                // of a file descriptor; only ENXIO/ENODEV mean "no such"
                int err = errno;
                ::close(fd);
                if (err == ENXIO || err == ENODEV)
                    praia::error(fn + "(): unknown interface: " + ifName);
                errno = err;
                sysError(fn + "(): can't look up interface " + ifName);
            }

            struct sockaddr_ll sll;
            memset(&sll, 0, sizeof(sll));
            sll.sll_family = AF_PACKET;
            sll.sll_ifindex = ifIndex;
            sll.sll_protocol = htons(ETH_P_ALL);
            if (bind(fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
                int err = errno;
                ::close(fd);
                errno = err;
                sysError(fn + "(): bind to " + ifName + " failed");
            }
#elif defined(__APPLE__)
            for (int i = 0; i < 256 && fd < 0; i++) {
                std::string dev = "/dev/bpf" + std::to_string(i);
                fd = ::open(dev.c_str(), O_RDWR | O_CLOEXEC);
                if (fd < 0 && errno != EBUSY) break;   // EBUSY: try the next one
            }
            if (fd < 0)
                sysError(fn + "(): no BPF device available (need root?)");

            auto fail = [&](const std::string& what) {
                int err = errno;
                ::close(fd);
                errno = err;
                sysError(fn + "(): " + what);
            };
            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, ifName.c_str(), IFNAMSIZ - 1);
            if (ioctl(fd, BIOCSETIF, &ifr) < 0) fail("can't bind to " + ifName);
            u_int bufLen = 0;
            if (ioctl(fd, BIOCGBLEN, &bufLen) < 0 || bufLen == 0) fail("BIOCGBLEN");
            u_int one = 1;
            // Frames are readable as they arrive, not once the buffer fills
            if (ioctl(fd, BIOCIMMEDIATE, &one) < 0) fail("BIOCIMMEDIATE");
            // Send source MACs as given instead of the interface's
            if (ioctl(fd, BIOCSHDRCMPLT, &one) < 0) fail("BIOCSHDRCMPLT");
            // recv() only reads after poll says so; non-blocking makes sure
            // a read after a spurious wakeup can't block
            int flags = fcntl(fd, F_GETFL);
            if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) fail("O_NONBLOCK");
            bpfBuf.resize(bufLen);
#endif

            auto* s = new L2Socket();
            s->fd = fd;
            s->ifIndex = ifIndex;
            s->ifName = ifName;
            s->bpfBuf = std::move(bpfBuf);
            {
                std::lock_guard<std::mutex> reg(g_regMu);
                g_sockets->insert(s);
            }
            return praia::makeExternal<L2Socket>(s, kSocketType, freeSocket);
        }));

    // l2.send(handle, frameData) -> bytes sent
    module->entries["send"] = Value(makeNative("l2.send", 2,
        [](const std::vector<Value>& args) -> Value {
            const std::string fn = "l2.send";
            auto* s = argSocket(args, 0, fn);
            const auto& data = praia::requireString(args, 1, fn);
            if (data.size() < 14)
                praia::error(fn + "(): frame too small (need at least 14 bytes)");
            if (data.size() > 65535)
                praia::error(fn + "(): frame too large");

            std::unique_lock<std::timed_mutex> w(s->sendMu, std::defer_lock);
            if (!acquire(w, s, fn)) return Value();
            // However this send ends, if close() gave up waiting for it,
            // the fd is closed here, now that no write is using it
            struct CloseIfPending {
                L2Socket* s;
                ~CloseIfPending() {
                    if (s->closePending.exchange(false)) closeFd(s);
                }
            } closeIfPending{s};
#ifdef __linux__
            struct sockaddr_ll sll;
            memset(&sll, 0, sizeof(sll));
            sll.sll_family = AF_PACKET;
            sll.sll_ifindex = s->ifIndex;
            sll.sll_halen = 6;
            memcpy(sll.sll_addr, data.data(), 6);
#endif
            // Never blocks while holding sendMu: a full queue (EAGAIN or
            // ENOBUFS, after which nothing was sent) is waited out in short
            // slices, so close(), cancellation and Ctrl+C still get
            // through. They're checked before every attempt, so a send
            // ended by one transmits nothing. A frame goes out whole or not
            // at all, so retrying can't send it twice
            while (true) {
                if (interrupted() || cancelled()) return Value();
                if (s->closing) praia::error(fn + "(): the socket is closed");
#ifdef __linux__
                ssize_t sent = sendto(s->fd, data.data(), data.size(), MSG_DONTWAIT,
                                      (struct sockaddr*)&sll, sizeof(sll));
#elif defined(__APPLE__)
                ssize_t sent = write(s->fd, data.data(), data.size());
#endif
                if (sent >= 0) return Value(static_cast<int64_t>(sent));
                int err = errno;
                if (err != EAGAIN && err != EWOULDBLOCK && err != ENOBUFS && err != EINTR) {
                    errno = err;
                    sysError(fn + "(): write failed");
                }
                if (err == ENOBUFS) {
                    // The driver queue is full, which the fd may not show
                    // by polling unwritable: just give it a moment
                    ::usleep(10000);
                } else {
                    struct pollfd pfd = {s->fd, POLLOUT, 0};
                    ::poll(&pfd, 1, 100);
                }
            }
        }));

    // l2.recv(handle, maxBytes?) -> frame data, or nil on timeout or when
    // cancelled. Waits in short slices, so close() from another task,
    // cancellation and Ctrl+C all end the wait
    module->entries["recv"] = Value(makeNative("l2.recv", -1,
        [](const std::vector<Value>& args) -> Value {
            const std::string fn = "l2.recv";
            praia::requireArityRange(args, 1, 2, fn);
            auto* s = argSocket(args, 0, fn);
            int64_t maxBytes = 65536;
            if (args.size() > 1 && !args[1].isNil()) {
                maxBytes = praia::requireInt(args, 1, fn);
                if (maxBytes < 1 || maxBytes > 65536)
                    praia::error(fn + "(): maxBytes must be between 1 and 65536");
            }

            // The timeout covers waiting for another task's recv() too
            const int timeoutMs = s->timeoutMs;
            const auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
            std::unique_lock<std::timed_mutex> r(s->recvMu, std::defer_lock);
            if (!acquire(r, s, fn, timeoutMs > 0 ? &deadline : nullptr, true)) return Value();

            std::string frame;
#ifdef __APPLE__
            if (nextBpfFrame(s, frame)) {
                if (frame.size() > static_cast<size_t>(maxBytes)) frame.resize(maxBytes);
                return Value(frame);
            }
#endif
            while (true) {
                if (interrupted() || cancelled() || s->closing) return Value();
                int slice = 100;
                if (timeoutMs > 0) {
                    if (Clock::now() >= deadline) return Value();   // timeout
                    slice = sliceUntil(deadline, 100);              // rounded up
                }
                struct pollfd pfd = {s->fd, POLLIN, 0};
                int ready = ::poll(&pfd, 1, slice);
                if (ready < 0 && errno != EINTR) sysError(fn + "()");
                if (ready <= 0) continue;
                // Whatever arrived during the wait, these end the call
                // without reading it
                if (interrupted() || cancelled() || s->closing) return Value();
                if (pfd.revents & (POLLERR | POLLNVAL))
                    praia::error(fn + "(): the socket reported an error");
#ifdef __linux__
                frame.resize(static_cast<size_t>(maxBytes));
                ssize_t n = ::recv(s->fd, frame.data(), frame.size(), MSG_DONTWAIT);
                if (n < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
                    sysError(fn + "()");
                }
                frame.resize(static_cast<size_t>(n));
                return Value(frame);
#elif defined(__APPLE__)
                ssize_t n = ::read(s->fd, s->bpfBuf.data(), s->bpfBuf.size());
                if (n < 0) {
                    if (errno == EAGAIN || errno == EINTR) continue;
                    sysError(fn + "()");
                }
                s->bpfOff = 0;
                s->bpfLen = static_cast<size_t>(n);
                if (nextBpfFrame(s, frame)) {
                    if (frame.size() > static_cast<size_t>(maxBytes)) frame.resize(maxBytes);
                    return Value(frame);
                }
#endif
            }
        }));

    // l2.close(handle). Closing twice is fine
    module->entries["close"] = Value(makeNative("l2.close", 1,
        [](const std::vector<Value>& args) -> Value {
            auto* s = argSocket(args, 0, "l2.close");
            // A recv() waiting in another task sees this within one slice,
            // and no new call starts
            s->closing = true;
            // A barrier: once close() has held recvMu, any recv() that was
            // running has returned, and every later one sees closing before
            // touching the fd. So the fd can be closed without recvMu, and
            // close() never holds it while waiting for sendMu
            { std::lock_guard<std::timed_mutex> r(s->recvMu); }
            // A send can be stuck in the kernel: on macOS a BPF write waits
            // without limit for packet buffers when the system is out of
            // them, and nothing interrupts that. So close() doesn't wait for
            // it: it marks the close pending, then closes the fd only if it
            // gets sendMu soon. Otherwise the send closes it as it returns,
            // so the fd is never closed (and its number reused) under a write.
            // Set before trying the lock, so a send finishing meanwhile sees it
            s->closePending = true;
            std::unique_lock<std::timed_mutex> w(s->sendMu, std::chrono::milliseconds(250));
            if (w.owns_lock() && s->closePending.exchange(false)) closeFd(s);
            return Value();
        }));

    // l2.mac(interface) -> "aa:bb:cc:dd:ee:ff"
    module->entries["mac"] = Value(makeNative("l2.mac", 1,
        [](const std::vector<Value>& args) -> Value {
            const std::string fn = "l2.mac";
            const auto& ifName = praia::requireString(args, 0, fn);
            uint8_t mac[6];
            if (!getIfaceMac(ifName, mac))
                praia::error(fn + "(): could not get MAC for " + ifName);

            char buf[18];
            snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return Value(std::string(buf));
        }));

    // l2.setTimeout(handle, ms): how long recv() waits; 0 waits until a
    // frame arrives (or close, cancellation or Ctrl+C)
    module->entries["setTimeout"] = Value(makeNative("l2.setTimeout", 2,
        [](const std::vector<Value>& args) -> Value {
            const std::string fn = "l2.setTimeout";
            auto* s = argSocket(args, 0, fn);
            int64_t ms = praia::requireInt(args, 1, fn);
            if (ms < 0 || ms > 3600000)
                praia::error(fn + "(): timeout must be between 0 and 3600000 ms");
            if (s->closing) praia::error(fn + "(): the socket is closed");
            s->timeoutMs = static_cast<int>(ms);
            return Value();
        }));
}

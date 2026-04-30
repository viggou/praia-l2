#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#define _XOPEN_SOURCE 700

#include "praia_plugin.h"

#include <cerrno>
#include <cstring>
#include <unordered_map>
#include <vector>

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

struct L2Socket {
    int fd = -1;
    int ifIndex = 0;
    int bpfBufLen = 4096;
    std::string ifName;
};

static std::unordered_map<int64_t, L2Socket> sockets;
static int64_t nextId = 1;

static bool getIfaceMac(const std::string& ifName, uint8_t* mac) {
#ifdef __linux__
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
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
            if (!args[0].isString())
                throw RuntimeError("l2.open() requires interface name", 0);

            const auto& ifName = args[0].asString();
            L2Socket sock;
            sock.ifName = ifName;

#ifdef __linux__
            sock.fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
            if (sock.fd < 0)
                throw RuntimeError("l2.open(): failed to create socket (need root?)", 0);

            sock.ifIndex = if_nametoindex(ifName.c_str());
            if (sock.ifIndex == 0) {
                close(sock.fd);
                throw RuntimeError("l2.open(): unknown interface: " + ifName, 0);
            }

            struct sockaddr_ll sll;
            memset(&sll, 0, sizeof(sll));
            sll.sll_family = AF_PACKET;
            sll.sll_ifindex = sock.ifIndex;
            sll.sll_protocol = htons(ETH_P_ALL);

            if (bind(sock.fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
                close(sock.fd);
                throw RuntimeError("l2.open(): bind failed", 0);
            }
#elif defined(__APPLE__)
            sock.fd = -1;
            for (int i = 0; i < 256; i++) {
                std::string dev = "/dev/bpf" + std::to_string(i);
                sock.fd = ::open(dev.c_str(), O_RDWR);
                if (sock.fd >= 0) break;
            }
            if (sock.fd < 0)
                throw RuntimeError("l2.open(): no available BPF device (need root?)", 0);

            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, ifName.c_str(), IFNAMSIZ - 1);
            if (ioctl(sock.fd, BIOCSETIF, &ifr) < 0) {
                close(sock.fd);
                throw RuntimeError("l2.open(): failed to bind to " + ifName, 0);
            }

            ioctl(sock.fd, BIOCGBLEN, &sock.bpfBufLen);

            int val = 1;
            ioctl(sock.fd, BIOCIMMEDIATE, &val);
            ioctl(sock.fd, BIOCSHDRCMPLT, &val);
#endif

            int64_t id = nextId++;
            sockets[id] = std::move(sock);
            return Value(id);
        }));

    // l2.send(handle, frameData) -> bytes sent
    module->entries["send"] = Value(makeNative("l2.send", 2,
        [](const std::vector<Value>& args) -> Value {
            if (!args[0].isInt())
                throw RuntimeError("l2.send() requires socket handle", 0);
            if (!args[1].isString())
                throw RuntimeError("l2.send() requires frame data", 0);

            auto it = sockets.find(args[0].asInt());
            if (it == sockets.end())
                throw RuntimeError("l2.send(): invalid handle", 0);

            auto& sock = it->second;
            const auto& data = args[1].asString();

            if (data.size() < 14)
                throw RuntimeError("l2.send(): frame too small (need at least 14 bytes)", 0);

#ifdef __linux__
            struct sockaddr_ll sll;
            memset(&sll, 0, sizeof(sll));
            sll.sll_family = AF_PACKET;
            sll.sll_ifindex = sock.ifIndex;
            sll.sll_halen = 6;
            if (data.size() >= 6)
                memcpy(sll.sll_addr, data.data(), 6);

            ssize_t sent = sendto(sock.fd, data.data(), data.size(), 0,
                                  (struct sockaddr*)&sll, sizeof(sll));
#elif defined(__APPLE__)
            ssize_t sent = write(sock.fd, data.data(), data.size());
#endif
            if (sent < 0)
                throw RuntimeError("l2.send(): write failed: " + std::string(strerror(errno)), 0);

            return Value(static_cast<int64_t>(sent));
        }));

    // l2.recv(handle, maxBytes?) -> frame data or nil
    module->entries["recv"] = Value(makeNative("l2.recv", -1,
        [](const std::vector<Value>& args) -> Value {
            if (args.empty() || !args[0].isInt())
                throw RuntimeError("l2.recv() requires socket handle", 0);

            auto it = sockets.find(args[0].asInt());
            if (it == sockets.end())
                throw RuntimeError("l2.recv(): invalid handle", 0);

            auto& sock = it->second;

#ifdef __linux__
            int maxBytes = 65536;
            if (args.size() > 1 && args[1].isInt())
                maxBytes = static_cast<int>(args[1].asInt());

            std::vector<uint8_t> buf(maxBytes);
            ssize_t n = recv(sock.fd, buf.data(), buf.size(), 0);
            if (n <= 0) return Value();

            return Value(std::string(reinterpret_cast<char*>(buf.data()), n));
#elif defined(__APPLE__)
            std::vector<uint8_t> buf(sock.bpfBufLen);
            ssize_t n = read(sock.fd, buf.data(), buf.size());
            if (n <= 0) return Value();

            // Parse BPF header to extract the first packet
            if (n >= static_cast<ssize_t>(sizeof(struct bpf_hdr))) {
                auto* hdr = reinterpret_cast<struct bpf_hdr*>(buf.data());
                uint32_t caplen = hdr->bh_caplen;
                uint32_t hdrlen = hdr->bh_hdrlen;
                if (hdrlen + caplen <= static_cast<uint32_t>(n)) {
                    return Value(std::string(
                        reinterpret_cast<char*>(buf.data() + hdrlen), caplen));
                }
            }
            return Value();
#endif
        }));

    // l2.close(handle)
    module->entries["close"] = Value(makeNative("l2.close", 1,
        [](const std::vector<Value>& args) -> Value {
            if (!args[0].isInt())
                throw RuntimeError("l2.close() requires socket handle", 0);

            auto it = sockets.find(args[0].asInt());
            if (it == sockets.end()) return Value();

            if (it->second.fd >= 0)
                ::close(it->second.fd);
            sockets.erase(it);
            return Value();
        }));

    // l2.mac(interface) -> "aa:bb:cc:dd:ee:ff"
    module->entries["mac"] = Value(makeNative("l2.mac", 1,
        [](const std::vector<Value>& args) -> Value {
            if (!args[0].isString())
                throw RuntimeError("l2.mac() requires interface name", 0);

            uint8_t mac[6];
            if (!getIfaceMac(args[0].asString(), mac))
                throw RuntimeError("l2.mac(): could not get MAC for " + args[0].asString(), 0);

            char buf[18];
            snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return Value(std::string(buf));
        }));

    // l2.setTimeout(handle, ms)
    module->entries["setTimeout"] = Value(makeNative("l2.setTimeout", 2,
        [](const std::vector<Value>& args) -> Value {
            if (!args[0].isInt())
                throw RuntimeError("l2.setTimeout() requires socket handle", 0);
            if (!args[1].isInt())
                throw RuntimeError("l2.setTimeout() requires timeout in ms", 0);

            auto it = sockets.find(args[0].asInt());
            if (it == sockets.end())
                throw RuntimeError("l2.setTimeout(): invalid handle", 0);

            int ms = static_cast<int>(args[1].asInt());
            struct timeval tv;
            tv.tv_sec = ms / 1000;
            tv.tv_usec = (ms % 1000) * 1000;

#ifdef __linux__
            setsockopt(it->second.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#elif defined(__APPLE__)
            ioctl(it->second.fd, BIOCSRTIMEOUT, &tv);
#endif
            return Value();
        }));
}

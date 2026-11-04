#include <cstring>
#include <vector>
#include <sys/socket.h>
#include "felix86/common/log.hpp"
#include "felix86/hle/socket32.hpp"

#ifndef SO_RCVTIMEO_OLD
#define SO_RCVTIMEO_OLD 20
#endif
#ifndef SO_SNDTIMEO_OLD
#define SO_SNDTIMEO_OLD 21
#endif
#ifndef SO_TIMESTAMP_OLD
#define SO_TIMESTAMP_OLD 29
#endif
#ifndef SO_TIMESTAMPNS_OLD
#define SO_TIMESTAMPNS_OLD 35
#endif
#ifndef SO_TIMESTAMPING_OLD
#define SO_TIMESTAMPING_OLD 37
#endif
#ifndef SO_MEMINFO
#define SO_MEMINFO 55
#endif
#ifndef SO_INCOMING_NAPI_ID
#define SO_INCOMING_NAPI_ID 56
#endif
#ifndef SO_PEERGROUPS
#define SO_PEERGROUPS 59
#endif
#ifndef SO_ZEROCOPY
#define SO_ZEROCOPY 60
#endif
#ifndef SO_TXTIME
#define SO_TXTIME 61
#endif
#ifndef SO_BINDTOIFINDEX
#define SO_BINDTOIFINDEX 62
#endif
#ifndef SO_TIMESTAMP_NEW
#define SO_TIMESTAMP_NEW 63
#endif
#ifndef SO_TIMESTAMPNS_NEW
#define SO_TIMESTAMPNS_NEW 64
#endif
#ifndef SO_TIMESTAMPING_NEW
#define SO_TIMESTAMPING_NEW 65
#endif
#ifndef SO_RCVTIMEO_NEW
#define SO_RCVTIMEO_NEW 66
#endif
#ifndef SO_SNDTIMEO_NEW
#define SO_SNDTIMEO_NEW 67
#endif
#ifndef SO_DETACH_REUSEPORT_BPF
#define SO_DETACH_REUSEPORT_BPF 68
#endif
#ifndef SO_PREFER_BUSY_POLL
#define SO_PREFER_BUSY_POLL 69
#endif
#ifndef SO_BUSY_POLL_BUDGET
#define SO_BUSY_POLL_BUDGET 70
#endif
#ifndef SO_NETNS_COOKIE
#define SO_NETNS_COOKIE 71
#endif
#ifndef SO_BUF_LOCK
#define SO_BUF_LOCK 72
#endif
#ifndef SO_RESERVE_MEM
#define SO_RESERVE_MEM 73
#endif
#ifndef SO_TXREHASH
#define SO_TXREHASH 74
#endif
#ifndef SO_RCVMARK
#define SO_RCVMARK 75
#endif
#ifndef SO_PASSPIDFD
#define SO_PASSPIDFD 76
#endif
#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif

static void cmsgs_to_guest(msghdr& host_msghdr, x86_msghdr& guest_msghdr) {
    size_t guest_used = 0;
    for (cmsghdr* host_cmsghdr = CMSG_FIRSTHDR(&host_msghdr); host_cmsghdr != nullptr; host_cmsghdr = CMSG_NXTHDR(&host_msghdr, host_cmsghdr)) {
        size_t guest_left = guest_msghdr.msg_controllen - guest_used;
        size_t data_len = host_cmsghdr->cmsg_len - CMSG_LEN(0);
        size_t copied = guest_left < sizeof(x86_cmsghdr) ? 0 : std::min(data_len, guest_left - sizeof(x86_cmsghdr));
        bool is_rights = host_cmsghdr->cmsg_level == SOL_SOCKET && host_cmsghdr->cmsg_type == SCM_RIGHTS;
        if (is_rights) {
            copied &= ~(sizeof(int) - 1);
            for (size_t i = copied; i + sizeof(int) <= data_len; i += sizeof(int)) {
                int dropped_fd;
                memcpy(&dropped_fd, CMSG_DATA(host_cmsghdr) + i, sizeof(int));
                close(dropped_fd);
            }
        }
        if (copied < data_len) {
            guest_msghdr.msg_flags |= MSG_CTRUNC;
        }
        if (guest_left < sizeof(x86_cmsghdr) || (is_rights && copied == 0)) {
            continue;
        }

        x86_cmsghdr* guest_cmsghdr = (x86_cmsghdr*)(u64)(guest_msghdr.msg_control + guest_used);
        guest_cmsghdr->cmsg_len = sizeof(x86_cmsghdr) + copied;
        guest_cmsghdr->cmsg_level = host_cmsghdr->cmsg_level;
        guest_cmsghdr->cmsg_type = host_cmsghdr->cmsg_type;
        memcpy(guest_cmsghdr->cmsg_data, CMSG_DATA(host_cmsghdr), copied);
        guest_used += std::min<size_t>((guest_cmsghdr->cmsg_len + 3) & ~3u, guest_left);
    }
    guest_msghdr.msg_controllen = guest_used;
}

int recvmsg32(int fd, x86_msghdr* guest_msghdr, int flags) {
    struct msghdr host_msghdr;
    host_msghdr.msg_flags = guest_msghdr->msg_flags;
    host_msghdr.msg_name = (void*)(u64)guest_msghdr->msg_name;
    host_msghdr.msg_namelen = guest_msghdr->msg_namelen;

    x86_iovec* iovecs32 = (x86_iovec*)(u64)guest_msghdr->msg_iov;
    std::vector<iovec> iovecs(iovecs32, iovecs32 + guest_msghdr->msg_iovlen);
    host_msghdr.msg_iov = iovecs.data();
    host_msghdr.msg_iovlen = guest_msghdr->msg_iovlen;

    host_msghdr.msg_control = alloca(guest_msghdr->msg_controllen * 2);
    host_msghdr.msg_controllen = guest_msghdr->msg_controllen * 2;

    int result = ::recvmsg(fd, &host_msghdr, flags);
    if (result != -1) {
        for (u32 i = 0; i < guest_msghdr->msg_iovlen; i++) {
            x86_iovec* guest_iovec = (x86_iovec*)(guest_msghdr->msg_iov + (i * sizeof(x86_iovec)));
            *guest_iovec = host_msghdr.msg_iov[i];
        }

        guest_msghdr->msg_namelen = host_msghdr.msg_namelen;
        guest_msghdr->msg_flags = host_msghdr.msg_flags;
        cmsgs_to_guest(host_msghdr, *guest_msghdr);
    }
    return result;
}

static int cmsgs_to_host(const x86_msghdr& guest_msghdr, msghdr& host_msghdr) {
    u8* guest_control = (u8*)(u64)guest_msghdr.msg_control;
    size_t guest_offset = 0;
    u8* host_ptr = (u8*)host_msghdr.msg_control;
    while (guest_offset < guest_msghdr.msg_controllen) {
        size_t guest_left = guest_msghdr.msg_controllen - guest_offset;
        x86_cmsghdr* guest_cmsghdr = (x86_cmsghdr*)(guest_control + guest_offset);
        if (guest_left < sizeof(x86_cmsghdr) || guest_cmsghdr->cmsg_len < sizeof(x86_cmsghdr) || guest_cmsghdr->cmsg_len > guest_left) {
            return -EINVAL;
        }

        size_t data_len = guest_cmsghdr->cmsg_len - sizeof(x86_cmsghdr);
        cmsghdr* host_cmsghdr = (cmsghdr*)host_ptr;
        host_cmsghdr->cmsg_len = CMSG_LEN(data_len);
        host_cmsghdr->cmsg_level = guest_cmsghdr->cmsg_level;
        host_cmsghdr->cmsg_type = guest_cmsghdr->cmsg_type;
        memcpy(CMSG_DATA(host_cmsghdr), guest_cmsghdr->cmsg_data, data_len);
        host_ptr += CMSG_SPACE(data_len);
        guest_offset += (guest_cmsghdr->cmsg_len + 3) & ~3u;
    }
    host_msghdr.msg_controllen = host_ptr - (u8*)host_msghdr.msg_control;
    return 0;
}

int sendmsg32(int fd, const x86_msghdr* guest_msghdr, int flags) {
    struct msghdr host_msghdr;
    host_msghdr.msg_flags = guest_msghdr->msg_flags;
    host_msghdr.msg_name = (void*)(u64)guest_msghdr->msg_name;
    host_msghdr.msg_namelen = guest_msghdr->msg_namelen;

    x86_iovec* iovecs32 = (x86_iovec*)(u64)guest_msghdr->msg_iov;
    std::vector<iovec> iovecs(iovecs32, iovecs32 + guest_msghdr->msg_iovlen);
    host_msghdr.msg_iov = iovecs.data();
    host_msghdr.msg_iovlen = guest_msghdr->msg_iovlen;

    host_msghdr.msg_control = alloca(guest_msghdr->msg_controllen * 2);
    int result = cmsgs_to_host(*guest_msghdr, host_msghdr);
    if (result != 0) {
        return result;
    }

    return ::sendmsg(fd, &host_msghdr, flags);
}

int recvmmsg32(int fd, x86_mmsghdr* messages, u32 n, int flags, x86_timespec* timeout) {
    std::vector<iovec> host_iovecs;
    ASSERT(n > 0);
    std::vector<struct mmsghdr> host_mmsgs(n);
    struct timespec host_timeout;
    struct timespec* host_timeout_ptr = nullptr;
    if (timeout) {
        host_timeout = *timeout;
        host_timeout_ptr = &host_timeout;
    }

    size_t total_iovecs = 0;
    for (u32 i = 0; i < n; i++) {
        total_iovecs += messages[i].header.msg_iovlen;
    }
    host_iovecs.reserve(total_iovecs);

    for (u32 i = 0; i < n; i++) {
        struct msghdr& host_msghdr = host_mmsgs[i].msg_hdr;
        x86_msghdr& guest_msghdr = messages[i].header;
        u32 size = host_iovecs.size();
        host_iovecs.resize(size + guest_msghdr.msg_iovlen);
        for (size_t i = 0; i < guest_msghdr.msg_iovlen; ++i) {
            host_iovecs[size + i] = ((x86_iovec*)(u64)guest_msghdr.msg_iov)[i];
        }

        host_msghdr.msg_name = (void*)(u64)guest_msghdr.msg_name;
        host_msghdr.msg_namelen = guest_msghdr.msg_namelen;
        host_msghdr.msg_iov = host_iovecs.data() + size;
        host_msghdr.msg_iovlen = guest_msghdr.msg_iovlen;
        host_msghdr.msg_control = alloca(guest_msghdr.msg_controllen * 2);
        host_msghdr.msg_controllen = guest_msghdr.msg_controllen * 2;
        host_msghdr.msg_flags = guest_msghdr.msg_flags;

        host_mmsgs[i].msg_len = messages[i].msg_len;
    }

    int result = ::recvmmsg(fd, host_mmsgs.data(), n, flags, host_timeout_ptr);

    if (result != -1) {
        for (int i = 0; i < result; i++) {
            struct msghdr& host_msghdr = host_mmsgs[i].msg_hdr;
            x86_msghdr& guest_msghdr = messages[i].header;
            for (size_t i = 0; i < guest_msghdr.msg_iovlen; ++i) {
                ((x86_iovec*)(u64)guest_msghdr.msg_iov)[i] = host_msghdr.msg_iov[i];
            }

            guest_msghdr.msg_namelen = host_msghdr.msg_namelen;
            guest_msghdr.msg_flags = host_msghdr.msg_flags;
            cmsgs_to_guest(host_msghdr, guest_msghdr);
            messages[i].msg_len = host_mmsgs[i].msg_len;
        }
    }

    if (timeout) {
        *timeout = host_timeout;
    }

    return result;
}

// Thanks FEX-Emu for these
int sendmmsg32(int fd, x86_mmsghdr* messages, u32 n, int flags) {
    std::vector<iovec> host_iovecs;
    std::vector<struct mmsghdr> host_mmsgs(n);

    u32 len = 0;
    for (u32 i = 0; i < n; i++) {
        x86_msghdr& guest_msghdr = messages[i].header;
        len += guest_msghdr.msg_controllen * 2;
        for (size_t j = 0; j < guest_msghdr.msg_iovlen; ++j) {
            host_iovecs.push_back(((x86_iovec*)(u64)(guest_msghdr.msg_iov))[j]);
        }
    }

    std::vector<u8> buffer(len);
    u32 current_iov = 0;
    u32 current_controllen_offset = 0;
    for (u32 i = 0; i < n; i++) {
        x86_msghdr& guest_msghdr = messages[i].header;
        struct msghdr& host_msghdr = host_mmsgs[i].msg_hdr;
        host_mmsgs[i].msg_len = messages[i].msg_len;
        host_msghdr.msg_name = (void*)(u64)guest_msghdr.msg_name;
        host_msghdr.msg_namelen = guest_msghdr.msg_namelen;
        host_msghdr.msg_controllen = guest_msghdr.msg_controllen;
        host_msghdr.msg_flags = guest_msghdr.msg_flags;
        host_msghdr.msg_iov = host_iovecs.data() + current_iov;
        host_msghdr.msg_iovlen = guest_msghdr.msg_iovlen;
        current_iov += host_msghdr.msg_iovlen;

        if (guest_msghdr.msg_controllen) {
            host_msghdr.msg_control = &buffer.at(current_controllen_offset);
            current_controllen_offset += guest_msghdr.msg_controllen * 2;
            int result = cmsgs_to_host(guest_msghdr, host_msghdr);
            if (result != 0) {
                if (i == 0) {
                    return result;
                }
                n = i;
                break;
            }
        }
    }

    int result = ::sendmmsg(fd, host_mmsgs.data(), n, flags);

    if (result != -1) {
        for (int i = 0; i < result; i++) {
            messages[i].msg_len = host_mmsgs[i].msg_len;
        }
    }

    return result;
}

int getsockopt32(int fd, int level, int optname, char* optval, u32* optlen) {
    if (level != SOL_SOCKET) {
        return ::getsockopt(fd, level, optname, optval, optlen);
    } else {
        switch (optname) {
        case SO_RCVTIMEO_OLD:
        case SO_SNDTIMEO_OLD: {
            struct timeval host_timeval;
            socklen_t host_optlen = sizeof(host_timeval);
            int result = ::getsockopt(fd, level, optname, &host_timeval, &host_optlen);
            if (result == 0) {
                x86_timeval guest_timeval = host_timeval;
                *optlen = std::min<u32>(*optlen, sizeof(x86_timeval));
                memcpy(optval, &guest_timeval, *optlen);
            }
            return result;
        }
        case SO_DEBUG:
        case SO_REUSEADDR:
        case SO_TYPE:
        case SO_ERROR:
        case SO_DONTROUTE:
        case SO_BROADCAST:
        case SO_SNDBUF:
        case SO_RCVBUF:
        case SO_SNDBUFFORCE:
        case SO_RCVBUFFORCE:
        case SO_KEEPALIVE:
        case SO_OOBINLINE:
        case SO_NO_CHECK:
        case SO_PRIORITY:
        case SO_LINGER:
        case SO_BSDCOMPAT:
        case SO_REUSEPORT:
        case SO_PASSCRED:
        case SO_PEERCRED:
        case SO_RCVLOWAT:
        case SO_SNDLOWAT:
        case SO_SECURITY_AUTHENTICATION:
        case SO_SECURITY_ENCRYPTION_TRANSPORT:
        case SO_SECURITY_ENCRYPTION_NETWORK:
        case SO_ATTACH_FILTER:
        case SO_DETACH_FILTER:
        case SO_PEERNAME:
        case SO_TIMESTAMP_OLD:
        case SO_ACCEPTCONN:
        case SO_PEERSEC:
        case SO_PASSSEC:
        case SO_TIMESTAMPNS_OLD:
        case SO_MARK:
        case SO_TIMESTAMPING_OLD:
        case SO_PROTOCOL:
        case SO_DOMAIN:
        case SO_RXQ_OVFL:
        case SO_WIFI_STATUS:
        case SO_PEEK_OFF:
        case SO_NOFCS:
        case SO_LOCK_FILTER:
        case SO_SELECT_ERR_QUEUE:
        case SO_BUSY_POLL:
        case SO_MAX_PACING_RATE:
        case SO_BPF_EXTENSIONS:
        case SO_INCOMING_CPU:
        case SO_ATTACH_BPF:
        case SO_ATTACH_REUSEPORT_CBPF:
        case SO_ATTACH_REUSEPORT_EBPF:
        case SO_CNX_ADVICE:
        case SO_MEMINFO:
        case SO_INCOMING_NAPI_ID:
        case SO_COOKIE:
        case SO_PEERGROUPS:
        case SO_ZEROCOPY:
        case SO_TXTIME:
        case SO_BINDTOIFINDEX:
        case SO_TIMESTAMP_NEW:
        case SO_TIMESTAMPNS_NEW:
        case SO_TIMESTAMPING_NEW:
        case SO_RCVTIMEO_NEW:
        case SO_SNDTIMEO_NEW:
        case SO_DETACH_REUSEPORT_BPF:
        case SO_PREFER_BUSY_POLL:
        case SO_BUSY_POLL_BUDGET:
        case SO_NETNS_COOKIE:
        case SO_BUF_LOCK:
        case SO_RESERVE_MEM:
        case SO_TXREHASH:
        case SO_RCVMARK:
        case SO_PASSPIDFD:
        case SO_PEERPIDFD: {
            return ::getsockopt(fd, level, optname, optval, optlen);
        }
        default: {
            ERROR("Unhandled getsockopt optname: %d", optname);
            return -ENOSYS;
        }
        }
    }
}

int setsockopt32(int fd, int level, int optname, char* optval, int optlen) {
    if (level != SOL_SOCKET) {
        return ::setsockopt(fd, level, optname, optval, optlen);
    } else {
        switch (optname) {
        case SO_ATTACH_FILTER:
        case SO_ATTACH_REUSEPORT_CBPF: {
            struct sock_fprog32 {
                uint16_t len;
                uint32_t filter;
            };
            struct sock_fprog64 {
                uint16_t len;
                uint64_t filter;
            };

            if (optlen != sizeof(sock_fprog32)) {
                return -EINVAL;
            }

            sock_fprog32* prog = (sock_fprog32*)optval;
            sock_fprog64 prog64{};
            prog64.len = prog->len;
            prog64.filter = prog->filter;

            return ::setsockopt(fd, level, optname, &prog64, sizeof(sock_fprog64));
        }
        case SO_RCVTIMEO_OLD: {
            struct timeval timeval = *(x86_timeval*)optval;
            return ::setsockopt(fd, level, SO_RCVTIMEO_NEW, &timeval, sizeof(timeval));
        }
        case SO_SNDTIMEO_OLD: {
            struct timeval timeval = *(x86_timeval*)optval;
            return ::setsockopt(fd, level, SO_SNDTIMEO_NEW, &timeval, sizeof(timeval));
        }
        case SO_DEBUG:
        case SO_REUSEADDR:
        case SO_TYPE:
        case SO_ERROR:
        case SO_DONTROUTE:
        case SO_BROADCAST:
        case SO_SNDBUF:
        case SO_RCVBUF:
        case SO_SNDBUFFORCE:
        case SO_RCVBUFFORCE:
        case SO_KEEPALIVE:
        case SO_OOBINLINE:
        case SO_NO_CHECK:
        case SO_PRIORITY:
        case SO_LINGER:
        case SO_BSDCOMPAT:
        case SO_REUSEPORT:
        case SO_PASSCRED:
        case SO_PEERCRED:
        case SO_RCVLOWAT:
        case SO_SNDLOWAT:
        case SO_SECURITY_AUTHENTICATION:
        case SO_SECURITY_ENCRYPTION_TRANSPORT:
        case SO_SECURITY_ENCRYPTION_NETWORK:
        case SO_DETACH_FILTER:
        case SO_PEERNAME:
        case SO_TIMESTAMP_OLD:
        case SO_ACCEPTCONN:
        case SO_PEERSEC:
        case SO_PASSSEC:
        case SO_TIMESTAMPNS_OLD:
        case SO_MARK:
        case SO_TIMESTAMPING_OLD:
        case SO_PROTOCOL:
        case SO_DOMAIN:
        case SO_RXQ_OVFL:
        case SO_WIFI_STATUS:
        case SO_PEEK_OFF:
        case SO_NOFCS:
        case SO_LOCK_FILTER:
        case SO_SELECT_ERR_QUEUE:
        case SO_BUSY_POLL:
        case SO_MAX_PACING_RATE:
        case SO_BPF_EXTENSIONS:
        case SO_INCOMING_CPU:
        case SO_ATTACH_BPF:
        case SO_ATTACH_REUSEPORT_EBPF:
        case SO_CNX_ADVICE:
        case SO_MEMINFO:
        case SO_INCOMING_NAPI_ID:
        case SO_COOKIE:
        case SO_PEERGROUPS:
        case SO_ZEROCOPY:
        case SO_TXTIME:
        case SO_BINDTOIFINDEX:
        case SO_TIMESTAMP_NEW:
        case SO_TIMESTAMPNS_NEW:
        case SO_TIMESTAMPING_NEW:
        case SO_RCVTIMEO_NEW:
        case SO_SNDTIMEO_NEW:
        case SO_DETACH_REUSEPORT_BPF:
        case SO_PREFER_BUSY_POLL:
        case SO_BUSY_POLL_BUDGET:
        case SO_NETNS_COOKIE:
        case SO_BUF_LOCK:
        case SO_RESERVE_MEM:
        case SO_TXREHASH:
        case SO_RCVMARK:
        case SO_PASSPIDFD:
        case SO_PEERPIDFD: {
            return ::setsockopt(fd, level, optname, optval, optlen);
        }
        default: {
            ERROR("Unhandled setsockopt optname: %d", optname);
            return -ENOSYS;
        }
        }
    }
}

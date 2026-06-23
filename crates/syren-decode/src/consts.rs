use syren_common::{ArgInfo, SyscallEvent};

pub(crate) fn render(
    syscall: &str,
    metas: &[ArgInfo],
    i: usize,
    ev: &SyscallEvent,
) -> Option<String> {
    let raw = ev.args[i];
    match (syscall, metas[i].name) {
        ("socket" | "socketpair", "family") => address_family(raw).map(str::to_string),
        ("socket" | "socketpair", "type") => socket_type(raw),
        ("socket" | "socketpair", "protocol") => protocol(ev.args[0], raw).map(str::to_string),
        ("setsockopt" | "getsockopt", "level") => sockopt_level(raw).map(str::to_string),
        ("setsockopt" | "getsockopt", "optname") => {
            sockopt_name(ev.args[1], raw).map(str::to_string)
        }
        ("kill" | "tkill" | "tgkill" | "rt_sigaction" | "rt_sigqueueinfo", "sig") => {
            syren_common::signal_name(raw as u32 as i32).map(str::to_string)
        }
        _ => None,
    }
}

fn address_family(value: u64) -> Option<&'static str> {
    Some(match value {
        0 => "AF_UNSPEC",
        1 => "AF_UNIX",
        2 => "AF_INET",
        10 => "AF_INET6",
        15 => "AF_KEY",
        16 => "AF_NETLINK",
        17 => "AF_PACKET",
        25 => "AF_WANPIPE",
        27 => "AF_IB",
        29 => "AF_CAN",
        31 => "AF_BLUETOOTH",
        38 => "AF_ALG",
        40 => "AF_VSOCK",
        44 => "AF_XDP",
        _ => return None,
    })
}

const SOCK_NONBLOCK: u64 = 0o4000;
const SOCK_CLOEXEC: u64 = 0o2000000;

fn socket_type(value: u64) -> Option<String> {
    let base = match value & !(SOCK_CLOEXEC | SOCK_NONBLOCK) {
        1 => "SOCK_STREAM",
        2 => "SOCK_DGRAM",
        3 => "SOCK_RAW",
        4 => "SOCK_RDM",
        5 => "SOCK_SEQPACKET",
        6 => "SOCK_DCCP",
        10 => "SOCK_PACKET",
        _ => return None,
    };
    let mut out = String::from(base);
    if value & SOCK_CLOEXEC != 0 {
        out.push_str("|SOCK_CLOEXEC");
    }
    if value & SOCK_NONBLOCK != 0 {
        out.push_str("|SOCK_NONBLOCK");
    }
    Some(out)
}

fn protocol(family: u64, value: u64) -> Option<&'static str> {
    if !matches!(family, 0 | 2 | 10) {
        return None;
    }
    Some(match value {
        0 => "IPPROTO_IP",
        1 => "IPPROTO_ICMP",
        2 => "IPPROTO_IGMP",
        6 => "IPPROTO_TCP",
        17 => "IPPROTO_UDP",
        41 => "IPPROTO_IPV6",
        58 => "IPPROTO_ICMPV6",
        132 => "IPPROTO_SCTP",
        136 => "IPPROTO_UDPLITE",
        255 => "IPPROTO_RAW",
        _ => return None,
    })
}

fn sockopt_level(value: u64) -> Option<&'static str> {
    Some(match value {
        0 => "SOL_IP",
        1 => "SOL_SOCKET",
        6 => "SOL_TCP",
        17 => "SOL_UDP",
        41 => "SOL_IPV6",
        58 => "SOL_ICMPV6",
        132 => "SOL_SCTP",
        255 => "SOL_RAW",
        263 => "SOL_PACKET",
        270 => "SOL_NETLINK",
        _ => return None,
    })
}

fn sockopt_name(level: u64, value: u64) -> Option<&'static str> {
    match level {
        1 => so_socket(value),
        6 => so_tcp(value),
        0 => so_ip(value),
        41 => so_ipv6(value),
        _ => None,
    }
}

fn so_socket(value: u64) -> Option<&'static str> {
    Some(match value {
        1 => "SO_DEBUG",
        2 => "SO_REUSEADDR",
        3 => "SO_TYPE",
        4 => "SO_ERROR",
        5 => "SO_DONTROUTE",
        6 => "SO_BROADCAST",
        7 => "SO_SNDBUF",
        8 => "SO_RCVBUF",
        9 => "SO_KEEPALIVE",
        10 => "SO_OOBINLINE",
        11 => "SO_NO_CHECK",
        12 => "SO_PRIORITY",
        13 => "SO_LINGER",
        14 => "SO_BSDCOMPAT",
        15 => "SO_REUSEPORT",
        16 => "SO_PASSCRED",
        17 => "SO_PEERCRED",
        18 => "SO_RCVLOWAT",
        19 => "SO_SNDLOWAT",
        20 => "SO_RCVTIMEO",
        21 => "SO_SNDTIMEO",
        25 => "SO_BINDTODEVICE",
        _ => return None,
    })
}

fn so_tcp(value: u64) -> Option<&'static str> {
    Some(match value {
        1 => "TCP_NODELAY",
        2 => "TCP_MAXSEG",
        3 => "TCP_CORK",
        4 => "TCP_KEEPIDLE",
        5 => "TCP_KEEPINTVL",
        6 => "TCP_KEEPCNT",
        7 => "TCP_SYNCNT",
        8 => "TCP_LINGER2",
        9 => "TCP_DEFER_ACCEPT",
        10 => "TCP_WINDOW_CLAMP",
        11 => "TCP_INFO",
        12 => "TCP_QUICKACK",
        13 => "TCP_CONGESTION",
        _ => return None,
    })
}

fn so_ip(value: u64) -> Option<&'static str> {
    Some(match value {
        1 => "IP_TOS",
        2 => "IP_TTL",
        3 => "IP_HDRINCL",
        4 => "IP_OPTIONS",
        8 => "IP_PKTINFO",
        10 => "IP_MTU_DISCOVER",
        11 => "IP_RECVERR",
        14 => "IP_MTU",
        15 => "IP_FREEBIND",
        32 => "IP_MULTICAST_IF",
        33 => "IP_MULTICAST_TTL",
        34 => "IP_MULTICAST_LOOP",
        35 => "IP_ADD_MEMBERSHIP",
        36 => "IP_DROP_MEMBERSHIP",
        _ => return None,
    })
}

fn so_ipv6(value: u64) -> Option<&'static str> {
    Some(match value {
        16 => "IPV6_MULTICAST_IF",
        18 => "IPV6_MULTICAST_LOOP",
        20 => "IPV6_ADD_MEMBERSHIP",
        26 => "IPV6_V6ONLY",
        49 => "IPV6_RECVPKTINFO",
        67 => "IPV6_TCLASS",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(name: &str, args: [u64; 6]) -> SyscallEvent {
        let nr = u64::from(syren_common::syscall_by_name(name).unwrap().number);
        SyscallEvent { pid: 1, tid: 1, nr, args, retval: 0, ts_enter_ns: 0, duration_ns: 0 }
    }

    fn render_at(name: &str, args: [u64; 6], i: usize) -> Option<String> {
        let info = syren_common::syscall_by_name(name).unwrap();
        render(name, info.args, i, &ev(name, args))
    }

    #[test]
    fn socket_family_type_protocol() {
        // socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP)
        let args = [10, 2, 0, 0, 0, 0];
        assert_eq!(render_at("socket", args, 0).as_deref(), Some("AF_INET6"));
        assert_eq!(render_at("socket", args, 1).as_deref(), Some("SOCK_DGRAM"));
        assert_eq!(render_at("socket", args, 2).as_deref(), Some("IPPROTO_IP"));
    }

    #[test]
    fn socket_type_carries_flags_in_strace_order() {
        // 526337 == SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK
        let args = [10, 526337, 6, 0, 0, 0];
        assert_eq!(
            render_at("socket", args, 1).as_deref(),
            Some("SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK")
        );
        assert_eq!(render_at("socket", args, 2).as_deref(), Some("IPPROTO_TCP"));
    }

    #[test]
    fn protocol_is_family_aware() {
        assert_eq!(render_at("socket", [16, 3, 0, 0, 0, 0], 2), None);
    }

    #[test]
    fn setsockopt_level_and_name() {
        // setsockopt(fd, SOL_TCP, TCP_NODELAY, ...)
        let tcp = [4, 6, 1, 0, 4, 0];
        assert_eq!(render_at("setsockopt", tcp, 1).as_deref(), Some("SOL_TCP"));
        assert_eq!(render_at("setsockopt", tcp, 2).as_deref(), Some("TCP_NODELAY"));

        // setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, ...)
        let so = [4, 1, 9, 0, 4, 0];
        assert_eq!(render_at("setsockopt", so, 1).as_deref(), Some("SOL_SOCKET"));
        assert_eq!(render_at("setsockopt", so, 2).as_deref(), Some("SO_KEEPALIVE"));
    }

    #[test]
    fn signal_arguments() {
        // kill(pid, SIGTERM)
        assert_eq!(render_at("kill", [1234, 15, 0, 0, 0, 0], 1).as_deref(), Some("SIGTERM"));
        // kill(pid, 0)
        assert_eq!(render_at("kill", [1234, 0, 0, 0, 0, 0], 1), None);
    }

    #[test]
    fn unknown_constants_fall_through() {
        assert_eq!(address_family(0xabcd), None);
        assert_eq!(socket_type(0xabcd), None);
        assert_eq!(sockopt_level(9999), None);
    }
}

/// The conventional name for signal `sig`, e.g. `SIGINT` for `2`.
pub fn signal_name(sig: i32) -> Option<&'static str> {
    Some(match sig {
        1 => "SIGHUP",
        2 => "SIGINT",
        3 => "SIGQUIT",
        4 => "SIGILL",
        5 => "SIGTRAP",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        9 => "SIGKILL",
        10 => "SIGUSR1",
        11 => "SIGSEGV",
        12 => "SIGUSR2",
        13 => "SIGPIPE",
        14 => "SIGALRM",
        15 => "SIGTERM",
        16 => "SIGSTKFLT",
        17 => "SIGCHLD",
        18 => "SIGCONT",
        19 => "SIGSTOP",
        20 => "SIGTSTP",
        21 => "SIGTTIN",
        22 => "SIGTTOU",
        23 => "SIGURG",
        24 => "SIGXCPU",
        25 => "SIGXFSZ",
        26 => "SIGVTALRM",
        27 => "SIGPROF",
        28 => "SIGWINCH",
        29 => "SIGIO",
        30 => "SIGPWR",
        31 => "SIGSYS",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_known_signals() {
        assert_eq!(signal_name(2), Some("SIGINT"));
        assert_eq!(signal_name(9), Some("SIGKILL"));
        assert_eq!(signal_name(28), Some("SIGWINCH"));
        assert_eq!(signal_name(31), Some("SIGSYS"));
    }

    #[test]
    fn leaves_zero_and_realtime_unnamed() {
        assert_eq!(signal_name(0), None);
        assert_eq!(signal_name(34), None);
        assert_eq!(signal_name(64), None);
        assert_eq!(signal_name(99), None);
    }
}

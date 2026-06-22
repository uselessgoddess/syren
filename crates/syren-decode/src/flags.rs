/// A named bit (or bitmask group) within a flag set.
struct Flag {
    name: &'static str,
    bits: u64,
}

macro_rules! flags {
    ($($name:ident = $bits:expr),* $(,)?) => {
        &[$(Flag { name: stringify!($name), bits: $bits }),*]
    };
}

/// `O_*` flags for `open`/`openat`/`openat2`. The low two bits are the access
/// mode and are decoded separately.
const OPEN_FLAGS: &[Flag] = flags![
    O_CREAT = 0o100,
    O_EXCL = 0o200,
    O_NOCTTY = 0o400,
    O_TRUNC = 0o1000,
    O_APPEND = 0o2000,
    O_NONBLOCK = 0o4000,
    O_DSYNC = 0o10000,
    O_ASYNC = 0o20000,
    O_DIRECT = 0o40000,
    O_LARGEFILE = 0o100000,
    O_DIRECTORY = 0o200000,
    O_NOFOLLOW = 0o400000,
    O_NOATIME = 0o1000000,
    O_CLOEXEC = 0o2000000,
    O_PATH = 0o10000000,
    // O_SYNC is O_DSYNC|0o4000000; check it before the bare bit below.
    O_SYNC = 0o4010000,
    O_TMPFILE = 0o20200000,
];

/// `PROT_*` flags for `mmap`/`mprotect`/`pkey_mprotect`.
const PROT_FLAGS: &[Flag] = flags![
    PROT_READ = 0x1,
    PROT_WRITE = 0x2,
    PROT_EXEC = 0x4,
    PROT_SEM = 0x8,
    PROT_GROWSDOWN = 0x0100_0000,
    PROT_GROWSUP = 0x0200_0000,
];

/// `MAP_*` flags for `mmap`. The low bits are the mapping type.
const MAP_FLAGS: &[Flag] = flags![
    MAP_SHARED = 0x01,
    MAP_PRIVATE = 0x02,
    MAP_FIXED = 0x10,
    MAP_ANONYMOUS = 0x20,
    MAP_32BIT = 0x40,
    MAP_GROWSDOWN = 0x0100,
    MAP_DENYWRITE = 0x0800,
    MAP_EXECUTABLE = 0x1000,
    MAP_LOCKED = 0x2000,
    MAP_NORESERVE = 0x4000,
    MAP_POPULATE = 0x8000,
    MAP_NONBLOCK = 0x1_0000,
    MAP_STACK = 0x2_0000,
    MAP_HUGETLB = 0x4_0000,
    MAP_SYNC = 0x8_0000,
    MAP_FIXED_NOREPLACE = 0x10_0000,
];

/// Decode `value` as the flag set used by `arg` of `syscall`, if recognised.
pub(crate) fn render(syscall: &str, arg: &str, value: u64) -> Option<String> {
    match (syscall, arg) {
        ("open" | "openat" | "openat2", "flags") => Some(render_open(value)),
        ("mmap" | "mprotect" | "pkey_mprotect", "prot") => {
            Some(render_set(PROT_FLAGS, value, "PROT_NONE"))
        }
        ("mmap", "flags") => Some(render_map(value)),
        _ => None,
    }
}

/// Decode open flags, including the access-mode in the low two bits.
fn render_open(value: u64) -> String {
    let mode = match value & 0o3 {
        0 => "O_RDONLY",
        1 => "O_WRONLY",
        2 => "O_RDWR",
        _ => "O_ACCMODE",
    };
    let rest = decode_bits(OPEN_FLAGS, value & !0o3);
    join(mode, rest, value & !0o3, OPEN_FLAGS)
}

/// Decode `mmap` flags, including the mapping type in the low bits.
fn render_map(value: u64) -> String {
    let kind = match value & 0xf {
        0x1 => Some("MAP_SHARED"),
        0x2 => Some("MAP_PRIVATE"),
        0x3 => Some("MAP_SHARED_VALIDATE"),
        _ => None,
    };
    let masked = value & !0xf;
    let rest = decode_bits(MAP_FLAGS, masked);
    match kind {
        Some(k) => join(k, rest, masked, MAP_FLAGS),
        None => render_set(MAP_FLAGS, value, "0"),
    }
}

/// Render a pure flag set (no special low bits), using `zero` when empty.
fn render_set(set: &[Flag], value: u64, zero: &str) -> String {
    if value == 0 {
        return zero.to_string();
    }
    let named = decode_bits(set, value);
    let leftover = value & !covered(set);
    match (named.is_empty(), leftover) {
        (true, _) => format!("{value:#x}"),
        (false, 0) => named.join("|"),
        (false, _) => format!("{}|{leftover:#x}", named.join("|")),
    }
}

/// Collect the names of all flags present in `value`.
fn decode_bits(set: &[Flag], value: u64) -> Vec<&'static str> {
    set.iter().filter(|f| f.bits != 0 && value & f.bits == f.bits).map(|f| f.name).collect()
}

/// The union of all bits any flag in `set` can account for.
fn covered(set: &[Flag]) -> u64 {
    set.iter().fold(0, |acc, f| acc | f.bits)
}

/// Combine a mandatory leading token (access mode / mapping type) with the
/// remaining decoded flags and any leftover bits.
fn join(lead: &str, rest: Vec<&'static str>, masked: u64, set: &[Flag]) -> String {
    let leftover = masked & !covered(set);
    let mut out = String::from(lead);
    for name in rest {
        out.push('|');
        out.push_str(name);
    }
    if leftover != 0 {
        out.push_str(&format!("|{leftover:#x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_flags_match_strace() {
        assert_eq!(render("openat", "flags", 0), Some("O_RDONLY".into()));
        assert_eq!(render("openat", "flags", 0o2000000), Some("O_RDONLY|O_CLOEXEC".into()));
        assert_eq!(
            render("openat", "flags", 0o2000000 | 0o200000),
            Some("O_RDONLY|O_DIRECTORY|O_CLOEXEC".into())
        );
        assert_eq!(render("open", "flags", 1), Some("O_WRONLY".into()));
        // O_WRONLY|O_CREAT|O_TRUNC == 0x241
        assert_eq!(render("open", "flags", 0o1101), Some("O_WRONLY|O_CREAT|O_TRUNC".into()));
    }

    #[test]
    fn unknown_open_bits_kept_as_hex() {
        // O_CLOEXEC plus an undefined high bit.
        let got = render("openat", "flags", 0o2000000 | 0x8000_0000).unwrap();
        assert_eq!(got, "O_RDONLY|O_CLOEXEC|0x80000000");
    }

    #[test]
    fn prot_flags() {
        assert_eq!(render("mmap", "prot", 0), Some("PROT_NONE".into()));
        assert_eq!(render("mmap", "prot", 0x1), Some("PROT_READ".into()));
        assert_eq!(render("mprotect", "prot", 0x3), Some("PROT_READ|PROT_WRITE".into()));
    }

    #[test]
    fn map_flags() {
        assert_eq!(render("mmap", "flags", 0x2), Some("MAP_PRIVATE".into()));
        assert_eq!(render("mmap", "flags", 0x2 | 0x20), Some("MAP_PRIVATE|MAP_ANONYMOUS".into()));
    }

    #[test]
    fn unrecognised_pair_is_none() {
        assert_eq!(render("ioctl", "request", 0x5401), None);
    }
}

use crate::MemoryReader;

/// Maximum number of bytes shown for a string/buffer argument before it is
/// truncated with `...` (mirrors strace's default `-s 32`).
pub(crate) const MAX_STR: usize = 32;

/// How far a `Path` argument is followed before giving up.
pub(crate) const PATH_CAP: usize = 4096;

/// Read a NUL-terminated C string from tracee memory at `addr`.
///
/// Returns the bytes up to (not including) the terminator, or `None` if nothing
/// could be read. Reads in small chunks so a short string near an unmapped page
/// boundary still succeeds.
pub(crate) fn read_cstr(mem: &dyn MemoryReader, addr: u64, cap: usize) -> Option<Vec<u8>> {
    if addr == 0 {
        return None;
    }
    let mut out = Vec::new();
    let mut cursor = addr;
    while out.len() < cap {
        let want = 256.min(cap - out.len());
        let chunk = match mem.read(cursor, want) {
            Some(chunk) if !chunk.is_empty() => chunk,
            _ => return (!out.is_empty()).then_some(out),
        };
        if let Some(pos) = chunk.iter().position(|&b| b == 0) {
            out.extend_from_slice(&chunk[..pos]);
            return Some(out);
        }
        cursor += chunk.len() as u64;
        out.extend_from_slice(&chunk);
    }
    Some(out)
}

/// Quote a byte string strace-style: wrap in quotes, escape non-printables and
/// truncate to [`MAX_STR`] visible bytes (appending `...` when truncated).
pub(crate) fn quote_bytes(bytes: &[u8]) -> String {
    let truncated = bytes.len() > MAX_STR;
    let mut s = String::with_capacity(bytes.len() + 2);
    s.push('"');
    for &b in bytes.iter().take(MAX_STR) {
        match b {
            b'"' => s.push_str("\\\""),
            b'\\' => s.push_str("\\\\"),
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            b'\t' => s.push_str("\\t"),
            0x20..=0x7e => s.push(b as char),
            _ => s.push_str(&format!("\\{b:o}")),
        }
    }
    s.push('"');
    if truncated {
        s.push_str("...");
    }
    s
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    struct MockMem(HashMap<u64, Vec<u8>>);

    impl MemoryReader for MockMem {
        fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
            for (&base, bytes) in &self.0 {
                if addr >= base && addr < base + bytes.len() as u64 {
                    let off = (addr - base) as usize;
                    let end = (off + len).min(bytes.len());
                    return Some(bytes[off..end].to_vec());
                }
            }
            None
        }
    }

    fn mem(pairs: &[(u64, &[u8])]) -> MockMem {
        MockMem(pairs.iter().map(|(a, b)| (*a, b.to_vec())).collect())
    }

    #[test]
    fn nul_terminated_string() {
        let m = mem(&[(0x1000, b"/etc/passwd\0and beyond")]);
        assert_eq!(read_cstr(&m, 0x1000, PATH_CAP).unwrap(), b"/etc/passwd");
    }

    #[test]
    fn null_pointer() {
        let m = mem(&[]);
        assert!(read_cstr(&m, 0, PATH_CAP).is_none());
    }

    #[test]
    fn unmapped_pointer() {
        let m = mem(&[(0x1000, b"x\0")]);
        assert!(read_cstr(&m, 0x9999, PATH_CAP).is_none());
    }

    #[test]
    fn quoting_escapes_and_truncates() {
        assert_eq!(quote_bytes(b"hi\n"), r#""hi\n""#);
        assert_eq!(quote_bytes(b"a\tb"), r#""a\tb""#);
        let long = vec![b'a'; 40];
        let q = quote_bytes(&long);
        assert!(q.ends_with("\"..."), "expected truncation marker, got {q}");
        assert_eq!(q.matches('a').count(), MAX_STR);
    }
}

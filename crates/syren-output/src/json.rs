use std::io::{self, Write};

use serde::Serialize;
use syren_decode::DecodedSyscall;

use crate::{Record, Sink};

/// Writes each record as a single-line JSON object, newline-delimited (NDJSON),
/// which streams cleanly and is trivially consumed line-by-line.
pub struct JsonSink<W> {
    out: W,
}

impl<W> std::fmt::Debug for JsonSink<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonSink").finish_non_exhaustive()
    }
}

impl<W: Write> JsonSink<W> {
    /// Wrap a writer.
    pub fn new(out: W) -> Self {
        Self { out }
    }
}

/// The on-the-wire JSON shape. Internally tagged so a syscall object gains a
/// `"type":"syscall"` field alongside its decoded fields.
#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum JsonRecord<'a> {
    Syscall(&'a DecodedSyscall),
    Exit { pid: u32, code: i32 },
    Signal { pid: u32, signal: i32 },
}

impl<W: Write> Sink for JsonSink<W> {
    fn record(&mut self, rec: Record<'_>) -> io::Result<()> {
        let json = match rec {
            Record::Syscall(s) => JsonRecord::Syscall(s),
            Record::Exit { pid, code } => JsonRecord::Exit { pid, code },
            Record::Signal { pid, signal } => JsonRecord::Signal { pid, signal },
        };
        serde_json::to_writer(&mut self.out, &json).map_err(io::Error::other)?;
        self.out.write_all(b"\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{arg, syscall};

    #[test]
    fn emits_one_json_object_per_line() {
        let mut buf = Vec::new();
        {
            let mut sink = JsonSink::new(&mut buf);
            let s = syscall("read", vec![arg("fd", "3")], 10);
            sink.record(Record::Syscall(&s)).unwrap();
            sink.record(Record::Signal { pid: 100, signal: 2 }).unwrap();
            sink.record(Record::Exit { pid: 100, code: 0 }).unwrap();
        }
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<_> = out.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains(r#""type":"syscall""#));
        assert!(lines[0].contains(r#""name":"read""#));
        assert!(lines[1].contains(r#""type":"signal""#));
        assert!(lines[1].contains(r#""signal":2"#));
        assert!(lines[2].contains(r#""type":"exit""#));
        assert!(lines[2].contains(r#""code":0"#));
    }

    #[test]
    fn syscall_line_is_valid_json() {
        let mut buf = Vec::new();
        {
            let mut sink = JsonSink::new(&mut buf);
            let s = syscall("read", vec![arg("fd", "3")], 10);
            sink.record(Record::Syscall(&s)).unwrap();
        }
        let out = String::from_utf8(buf).unwrap();
        let value: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(value["type"], "syscall");
        assert_eq!(value["retval"], 10);
        assert_eq!(value["args"][0]["value"], "3");
    }
}

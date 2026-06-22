use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{self, Write};

use crate::{Record, Sink};

#[derive(Default, Clone, Copy)]
struct Stat {
    calls: u64,
    errors: u64,
    total_ns: u128,
}

/// Accumulates statistics while recording and prints a summary table on
/// [`finish`](Sink::finish). Individual syscalls are *not* printed.
pub struct SummarySink<W> {
    out: W,
    stats: HashMap<Cow<'static, str>, Stat>,
}

impl<W> std::fmt::Debug for SummarySink<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SummarySink").field("syscalls", &self.stats.len()).finish_non_exhaustive()
    }
}

impl<W: Write> SummarySink<W> {
    /// Wrap a writer.
    pub fn new(out: W) -> Self {
        Self { out, stats: HashMap::new() }
    }
}

impl<W: Write> Sink for SummarySink<W> {
    fn record(&mut self, rec: Record<'_>) -> io::Result<()> {
        if let Record::Syscall(s) = rec {
            let stat = self.stats.entry(s.name.clone()).or_default();
            stat.calls += 1;
            stat.total_ns += u128::from(s.duration_ns);
            if s.error.is_some() {
                stat.errors += 1;
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> io::Result<()> {
        let grand: u128 = self.stats.values().map(|s| s.total_ns).sum();
        let mut rows: Vec<_> = self.stats.iter().collect();
        rows.sort_by(|a, b| {
            b.1.total_ns.cmp(&a.1.total_ns).then(b.1.calls.cmp(&a.1.calls)).then(a.0.cmp(b.0))
        });

        writeln!(
            self.out,
            "{:>6} {:>11} {:>11} {:>9} {:>9} syscall",
            "% time", "seconds", "usecs/call", "calls", "errors"
        )?;
        writeln!(self.out, "{:->6} {:->11} {:->11} {:->9} {:->9} {:-<16}", "", "", "", "", "", "")?;

        let (mut total_calls, mut total_errors) = (0u64, 0u64);
        for (name, s) in &rows {
            let pct = if grand == 0 { 0.0 } else { s.total_ns as f64 / grand as f64 * 100.0 };
            let secs = s.total_ns as f64 / 1e9;
            let usecs = if s.calls == 0 { 0 } else { s.total_ns / u128::from(s.calls) / 1_000 };
            writeln!(
                self.out,
                "{pct:>6.2} {secs:>11.6} {usecs:>11} {:>9} {:>9} {name}",
                s.calls,
                errors(s.errors),
            )?;
            total_calls += s.calls;
            total_errors += s.errors;
        }

        writeln!(self.out, "{:->6} {:->11} {:->11} {:->9} {:->9} {:-<16}", "", "", "", "", "", "")?;
        let total_secs = grand as f64 / 1e9;
        writeln!(
            self.out,
            "{:>6} {total_secs:>11.6} {:>11} {total_calls:>9} {:>9} total",
            "100.00",
            "",
            errors(total_errors),
        )
    }
}

fn errors(n: u64) -> String {
    if n == 0 { String::new() } else { n.to_string() }
}

#[cfg(test)]
mod tests {
    use syren_decode::DecodedError;

    use super::*;
    use crate::test_support::syscall;

    #[test]
    fn aggregates_counts_and_errors() {
        let mut buf = Vec::new();
        {
            let mut sink = SummarySink::new(&mut buf);
            for _ in 0..3 {
                sink.record(Record::Syscall(&syscall("read", vec![], 1))).unwrap();
            }
            let mut bad = syscall("openat", vec![], -2);
            bad.error =
                Some(DecodedError { errno: 2, name: "ENOENT", description: "No such file" });
            sink.record(Record::Syscall(&bad)).unwrap();
            sink.record(Record::Exit { pid: 100, code: 0 }).unwrap();
            sink.finish().unwrap();
        }
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("% time"));
        assert!(out.contains("usecs/call"));
        assert!(out.lines().last().unwrap().contains("total"));

        let read_row = out.lines().find(|l| l.trim_end().ends_with("read")).unwrap();
        let fields: Vec<_> = read_row.split_whitespace().collect();
        assert_eq!(fields[3], "3", "read should have 3 calls: {read_row:?}");

        let open_row = out.lines().find(|l| l.trim_end().ends_with("openat")).unwrap();
        let fields: Vec<_> = open_row.split_whitespace().collect();
        assert_eq!(fields[3], "1", "openat should have 1 call: {open_row:?}");
        assert_eq!(fields[4], "1", "openat should have 1 error: {open_row:?}");
    }

    #[test]
    fn empty_summary() {
        let mut buf = Vec::new();
        {
            let mut sink = SummarySink::new(&mut buf);
            sink.finish().unwrap();
        }
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("% time"));
        assert!(out.contains("total"));
    }
}

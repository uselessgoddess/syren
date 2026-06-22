use std::collections::HashSet;

use anyhow::{Result, bail};
use syren_common::{Category, SYSCALLS, syscall_by_name};

/// Which syscalls to report.
#[derive(Debug)]
pub(crate) enum Filter {
    /// Report everything (the default, and the `all` keyword).
    All,
    /// Report only syscalls whose number is in this set.
    Numbers(HashSet<u32>),
}

impl Filter {
    /// Build a filter from the raw `-e` expressions.
    ///
    /// Each expression is an optional `trace=` qualifier followed by a
    /// comma-separated set of tokens; each token is a syscall name, a
    /// `%category` (the leading `%` is optional), or the keyword `all`.
    pub(crate) fn from_exprs(exprs: &[String]) -> Result<Filter> {
        if exprs.is_empty() {
            return Ok(Filter::All);
        }
        let mut numbers = HashSet::new();
        for spec in exprs {
            let set = match spec.split_once('=') {
                Some(("trace", rest)) => rest,
                Some((qualifier, _)) => {
                    bail!("unsupported `-e` qualifier `{qualifier}=` (only `trace=` is supported)")
                }
                None => spec.as_str(),
            };
            for token in set.split(',').map(str::trim).filter(|t| !t.is_empty()) {
                if token.eq_ignore_ascii_case("all") {
                    return Ok(Filter::All);
                }
                let bare = token.strip_prefix('%').unwrap_or(token);
                if let Some(category) = Category::parse(bare) {
                    let in_category = SYSCALLS.iter().filter(|s| s.category == category);
                    numbers.extend(in_category.map(|s| s.number));
                } else if let Some(info) = syscall_by_name(token) {
                    numbers.insert(info.number);
                } else {
                    bail!("unknown syscall or category in `-e`: `{token}`");
                }
            }
        }
        Ok(Filter::Numbers(numbers))
    }

    /// Whether the syscall with raw number `nr` should be reported.
    pub(crate) fn allows(&self, nr: u64) -> bool {
        match self {
            Filter::All => true,
            Filter::Numbers(set) => u32::try_from(nr).is_ok_and(|n| set.contains(&n)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nr(name: &str) -> u64 {
        u64::from(syscall_by_name(name).expect("known syscall").number)
    }

    #[test]
    fn empty_exprs() {
        let f = Filter::from_exprs(&[]).unwrap();
        assert!(matches!(f, Filter::All));
        assert!(f.allows(nr("read")));
        assert!(f.allows(nr("openat")));
    }

    #[test]
    fn trace_named_syscalls() {
        let f = Filter::from_exprs(&["trace=read,write".into()]).unwrap();
        assert!(f.allows(nr("read")));
        assert!(f.allows(nr("write")));
        assert!(!f.allows(nr("openat")));
    }

    #[test]
    fn omitting_trace_qualifier() {
        let f = Filter::from_exprs(&["openat".into()]).unwrap();
        assert!(f.allows(nr("openat")));
        assert!(!f.allows(nr("read")));
    }

    #[test]
    fn category_expands_to_members() {
        let f = Filter::from_exprs(&["%fs".into()]).unwrap();
        let fs = SYSCALLS.iter().find(|s| s.category == Category::Fs).expect("an fs syscall");
        assert!(f.allows(u64::from(fs.number)));
        let other = SYSCALLS.iter().find(|s| s.category != Category::Fs).expect("a non-fs syscall");
        assert!(!f.allows(u64::from(other.number)));
    }

    #[test]
    fn all_to_all() {
        let f = Filter::from_exprs(&["trace=read,all".into()]).unwrap();
        assert!(matches!(f, Filter::All));
    }

    #[test]
    fn unknown_token() {
        assert!(Filter::from_exprs(&["trace=definitely_not_a_syscall".into()]).is_err());
    }

    #[test]
    fn unsupported_qualifier() {
        assert!(Filter::from_exprs(&["signal=SIGINT".into()]).is_err());
    }
}

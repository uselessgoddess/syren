//! `syren` — a modern, strace-compatible syscall tracer.
//!
//! This binary wires the library crates together: [`syren_trace`] turns a
//! spawned (or attached) process into a stream of events, [`syren_decode`]
//! renders each raw syscall — reading the stopped tracee's memory for string and
//! buffer arguments — and [`syren_output`] writes the result as strace-style
//! text, NDJSON or a `-c` summary table.
//!
//! Like strace, trace output goes to **stderr** by default so the traced
//! program's own stdout/stderr pass through untouched; use `-o FILE` to redirect
//! it to a file (handy for piping NDJSON into `jq`).

mod filter;

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use clap::{Parser, ValueEnum};
use filter::Filter;
use syren_common::{Event, SYSCALLS};
use syren_decode::{NullMemory, ProcMemReader, decode};
use syren_output::{JsonSink, Record, Sink, SummarySink, TextOptions, TextSink};
use syren_trace::{Backend, Target, TraceOptions, tracer};

/// A modern, eBPF-ready strace alternative: run a program (or attach to one) and
/// trace, decode and aggregate the system calls it makes.
#[derive(Debug, Parser)]
#[command(name = "syren", version, about, long_about = None)]
struct Cli {
    /// Attach to an already-running process by pid. Mutually
    /// exclusive with spawning a COMMAND.
    #[arg(short = 'p', long = "pid", value_name = "PID")]
    pids: Vec<i32>,

    /// Follow `fork`/`vfork`/`clone` into child processes and new threads.
    #[arg(short = 'f', long = "follow")]
    follow: bool,

    /// Show each syscall's duration as `<seconds>`.
    #[arg(short = 'T', long = "timing")]
    timing: bool,

    /// Emit newline-delimited JSON instead of text.
    #[arg(long, conflicts_with = "summary")]
    json: bool,

    /// Print an aggregate `strace -c` style summary instead of each call.
    #[arg(short = 'c', long = "summary")]
    summary: bool,

    /// Restrict tracing to a set of syscalls: comma-separated names and/or
    /// `%categories`, e.g. `-e trace=openat,read` or `-e %fs`. Repeatable.
    #[arg(short = 'e', long = "expr", value_name = "EXPR")]
    exprs: Vec<String>,

    /// Write trace output to FILE instead of stderr.
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = ColorArg::Auto, value_name = "WHEN")]
    color: ColorArg,

    #[arg(long, value_enum, default_value_t = BackendArg::Ptrace)]
    backend: BackendArg,

    /// List the known syscall table (number, name, category) and exit.
    #[arg(long)]
    list_syscalls: bool,

    /// Program to run and trace, followed by its arguments.
    #[arg(trailing_var_arg = true, value_name = "COMMAND")]
    command: Vec<String>,
}

/// CLI mirror of [`syren_trace::Backend`] so clap can derive `--backend`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum BackendArg {
    /// Unprivileged `ptrace(2)` engine.
    Ptrace,
    /// Privilegeded BPF engine
    Ebpf,
}

impl From<BackendArg> for Backend {
    fn from(b: BackendArg) -> Self {
        match b {
            BackendArg::Ptrace => Backend::Ptrace,
            BackendArg::Ebpf => Backend::Ebpf,
        }
    }
}

/// When to colourise the text output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
enum ColorArg {
    #[default]
    Auto,
    Always,
    Never,
}

impl ColorArg {
    fn resolve(self, is_terminal: bool) -> bool {
        match self {
            ColorArg::Always => true,
            ColorArg::Never => false,
            ColorArg::Auto => is_terminal && std::env::var_os("NO_COLOR").is_none(),
        }
    }
}

fn main() -> ExitCode {
    init_logging();
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(err) if is_broken_pipe(&err) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("syren: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn is_broken_pipe(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause.downcast_ref::<io::Error>().is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
    })
}

fn init_logging() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("off"));
    let _ = fmt().with_env_filter(filter).with_writer(io::stderr).try_init();
}

fn run(cli: Cli) -> Result<ExitCode> {
    if cli.list_syscalls {
        list_syscalls()?;
        return Ok(ExitCode::SUCCESS);
    }

    let target = build_target(&cli)?;
    let options = TraceOptions { follow_forks: cli.follow };
    let filter = Filter::from_exprs(&cli.exprs)?;

    let mut tracer =
        tracer(cli.backend.into(), target, options).context("failed to start tracer")?;
    let leader = tracer.leader();

    let output = open_output(&cli)?;
    let color = cli.color.resolve(output.is_terminal);
    let mut sink = build_sink(&cli, output.writer, color);

    let mut exit_code: i32 = 0;
    while let Some(event) = tracer.next_event()? {
        match event {
            Event::Syscall(ev) => {
                if !filter.allows(ev.nr) {
                    continue;
                }
                let decoded = match ProcMemReader::open(ev.tid) {
                    Ok(mem) => decode(&ev, &mem),
                    Err(_) => decode(&ev, &NullMemory),
                };
                sink.record(Record::Syscall(&decoded))?;
            }
            Event::ProcessExit { pid, code } => {
                if Some(pid) == leader {
                    exit_code = code;
                }
                sink.record(Record::Exit { pid, code })?;
            }
            Event::Signal { pid, signal } => {
                sink.record(Record::Signal { pid, signal })?;
            }
        }
    }
    sink.finish()?;
    drop(sink);

    Ok(ExitCode::from(exit_code.clamp(0, 255) as u8))
}

fn build_target(cli: &Cli) -> Result<Target> {
    match (cli.pids.is_empty(), cli.command.is_empty()) {
        (false, false) => bail!("cannot both attach with `-p` and spawn a COMMAND; choose one"),
        (true, true) => bail!(
            "nothing to trace: give a COMMAND to run, or `-p PID` to attach.\n\
             Try `syren --help`."
        ),
        (false, true) => Ok(Target::Attach { pids: cli.pids.clone() }),
        (true, false) => {
            let mut argv = cli.command.iter().cloned();
            let program = PathBuf::from(argv.next().expect("command is non-empty"));
            Ok(Target::Spawn { program, args: argv.collect() })
        }
    }
}

struct Output {
    writer: Box<dyn Write>,
    is_terminal: bool,
}

fn open_output(cli: &Cli) -> Result<Output> {
    use std::io::IsTerminal;
    match cli.output.as_deref() {
        Some(path) if path.as_os_str() == "-" => {
            Ok(Output { writer: Box::new(io::stdout()), is_terminal: io::stdout().is_terminal() })
        }
        Some(path) => {
            let file = File::create(path)
                .with_context(|| format!("cannot create output file `{}`", path.display()))?;
            Ok(Output { writer: Box::new(BufWriter::new(file)), is_terminal: false })
        }
        None => {
            Ok(Output { writer: Box::new(io::stderr()), is_terminal: io::stderr().is_terminal() })
        }
    }
}

fn build_sink(cli: &Cli, writer: Box<dyn Write>, color: bool) -> Box<dyn Sink> {
    if cli.summary {
        Box::new(SummarySink::new(writer))
    } else if cli.json {
        Box::new(JsonSink::new(writer))
    } else {
        let opts = TextOptions { show_pid: cli.follow, show_timing: cli.timing, color };
        Box::new(TextSink::with_options(writer, opts))
    }
}

fn list_syscalls() -> Result<()> {
    let mut out = BufWriter::new(io::stdout());
    writeln!(out, "{:>4}  {:<24} category", "nr", "name")?;
    for s in SYSCALLS {
        writeln!(out, "{:>4}  {:<24} {}", s.number, s.name, s.category.as_str())?;
    }
    out.flush()?;
    Ok(())
}

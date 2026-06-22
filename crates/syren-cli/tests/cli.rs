use assert_cmd::Command;
use predicates::prelude::*;

fn syren() -> Command {
    assert_cmd::cargo::cargo_bin_cmd!("syren")
}

#[test]
fn traces_true_to_completion() {
    syren()
        .arg("true")
        .assert()
        .success()
        .stderr(predicate::str::contains("+++ exited with 0 +++"));
}

#[test]
fn propagates_stdout() {
    syren()
        .args(["echo", "hello"])
        .assert()
        .success()
        .stdout("hello\n")
        .stderr(predicate::str::contains("write(1, "))
        .stderr(predicate::str::contains("+++ exited with 0 +++"));
}

#[test]
fn propagates_exit_status() {
    syren()
        .arg("false")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("+++ exited with 1 +++"));
}

#[test]
fn json_emits_typed_records() {
    syren()
        .args(["--json", "true"])
        .assert()
        .success()
        .stderr(predicate::str::contains(r#""type":"syscall""#))
        .stderr(predicate::str::contains(r#""type":"exit""#));
}

#[test]
fn summar_prints_table() {
    syren()
        .args(["-c", "true"])
        .assert()
        .success()
        .stderr(predicate::str::contains("% time"))
        .stderr(predicate::str::contains("syscall"))
        .stderr(predicate::str::contains("total"));
}

#[test]
fn filter_named_syscalls() {
    syren()
        .args(["-e", "trace=write", "echo", "hi"])
        .assert()
        .success()
        .stderr(predicate::str::contains("write("))
        .stderr(predicate::str::contains("openat(").not());
}

#[test]
fn list_syscalls_dumps_table() {
    syren()
        .arg("--list-syscalls")
        .assert()
        .success()
        .stdout(predicate::str::contains("openat"))
        .stdout(predicate::str::contains("read"));
}

#[test]
fn no_target() {
    syren().assert().failure().stderr(predicate::str::contains("nothing to trace"));
}

#[test]
fn attaching_and_spawning() {
    syren()
        .args(["-p", "1", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("choose one"));
}

#[test]
fn unknown_program() {
    syren()
        .arg("syren-no-such-program-xyzzy")
        .assert()
        .failure()
        .stderr(predicate::str::contains("syren-no-such-program-xyzzy"));
}

#[test]
fn unknown_filter_token() {
    syren()
        .args(["-e", "trace=definitely_not_a_syscall", "true"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unknown syscall or category"));
}

#[test]
fn pipe_exits_quietly() {
    use std::process::Command;

    let bin = assert_cmd::cargo::cargo_bin!("syren");
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("'{}' --list-syscalls | head -n1", bin.display()))
        .output()
        .expect("run syren through a shell pipe");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("Broken pipe"), "unexpected broken-pipe error: {stderr}");
    assert!(output.status.success(), "pipeline should succeed, got {:?}", output.status);
}

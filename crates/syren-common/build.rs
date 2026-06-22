use std::path::Path;
use std::{env, fs};

fn main() {
    let tbl_path = "data/syscall_64.tbl";
    println!("cargo:rerun-if-changed={tbl_path}");
    println!("cargo:rerun-if-changed=build.rs");

    let tbl =
        fs::read_to_string(tbl_path).unwrap_or_else(|e| panic!("failed to read {tbl_path}: {e}"));

    let generated = syren_gen::generate(&tbl);

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let dest = Path::new(&out_dir).join("syscalls_generated.rs");
    fs::write(&dest, generated)
        .unwrap_or_else(|e| panic!("failed to write {}: {e}", dest.display()));
}

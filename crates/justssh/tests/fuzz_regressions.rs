//! Every input kept in `fuzz/regressions/<target>/` through the check that fuzz target runs
//! (`fuzz/src/lib.rs`), on the stable toolchain.

use std::path::Path;

#[path = "../../../fuzz/src/lib.rs"]
mod fuzz;

fn replay(target: &str, check: fn(&[u8])) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/regressions")
        .join(target);
    let mut kept = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let input = std::fs::read(&path).unwrap();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if std::panic::catch_unwind(|| check(&input)).is_err() {
            panic!("{target}: {name}");
        }
        kept += 1;
    }
    assert!(kept > 0, "nothing kept in {}", dir.display());
}

#[test]
fn every_kept_wire_input_passes_the_wire_check() {
    replay("wire", fuzz::wire);
}

#[test]
fn every_kept_transport_input_passes_the_transport_check() {
    replay("transport", fuzz::transport);
}

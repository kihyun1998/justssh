//! Shredding the paths an ATTACH hands over (acwbroker `infrastructure/shred/shred_test.go`).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use justssh_broker::shred::Shredder;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("justssh-shred-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn admit_takes_only_direct_entries_of_a_root() {
    let root = scratch("admit-root");
    let other = scratch("admit-other");
    let shredder = Shredder::new(vec![root.clone()]);
    write(&root.join("a1b2").join("x.exp"), "token");
    write(&root.join("s.ini"), "token");
    write(&other.join("s.ini"), "token");
    let escape = root
        .join("a1b2")
        .join("..")
        .join("..")
        .join(other.file_name().unwrap())
        .join("s.ini");
    let dotted = root.join("a1b2").join("..").join("s.ini");
    for (name, path, ok) in [
        ("a folder under the root", root.join("a1b2"), true),
        ("a file under the root", root.join("s.ini"), true),
        ("through a dot dot that stays under", dotted, true),
        ("the root itself", root.clone(), false),
        (
            "a file one level deeper",
            root.join("a1b2").join("x.exp"),
            false,
        ),
        ("a parent escape", escape, false),
        ("a relative path", PathBuf::from("s.ini"), false),
        ("another folder's entry", other.join("s.ini"), false),
        ("an entry that is missing", root.join("gone"), false),
    ] {
        let got = shredder.admit(s(&path));
        assert_eq!(got.is_ok(), ok, "{name}: {got:?}");
    }
}

#[cfg(windows)]
#[test]
fn admit_ignores_case_on_windows() {
    let root = scratch("case");
    write(&root.join("s.ini"), "token");
    let upper = PathBuf::from(s(&root).to_uppercase());
    let shredder = Shredder::new(vec![upper]);
    let lower = format!("{}\\s.ini", s(&root).to_lowercase());
    assert_eq!(shredder.admit(&lower), Ok(()));
}

#[test]
fn admit_refuses_a_link() {
    let root = scratch("link-root");
    let target = scratch("link-target");
    let link = root.join("l");
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_dir(&target, &link);
    #[cfg(not(windows))]
    let made = std::os::unix::fs::symlink(&target, &link);
    if made.is_err() {
        #[cfg(windows)]
        {
            let junction = std::process::Command::new("cmd")
                .args(["/c", "mklink", "/J"])
                .arg(&link)
                .arg(&target)
                .output()
                .unwrap();
            assert!(junction.status.success(), "{junction:?}");
        }
    }
    let shredder = Shredder::new(vec![root.clone()]);
    assert_eq!(
        shredder.admit(s(&link)),
        Err("acwbroker: the path is a link".to_owned())
    );
    assert!(shredder.shred(s(&link)).is_err());
    assert!(target.exists(), "the link's target was removed");
}

#[test]
fn shred_zero_fills_and_removes_a_file_and_a_folder_and_keeps_the_root() {
    let root = scratch("remove");
    let file = root.join("s.ini");
    let dir = root.join("a1b2");
    write(&file, "token");
    write(&dir.join("x.xsh"), "token");
    let shredder = Shredder::new(vec![root.clone()]);
    for p in [&file, &dir] {
        assert_eq!(shredder.shred(s(p)), Ok(()), "{}", p.display());
        assert!(
            fs::symlink_metadata(p).is_err(),
            "{} is still there",
            p.display()
        );
    }
    assert!(root.exists(), "the root went with its entries");
}

#[test]
fn a_file_that_cannot_be_zero_filled_is_left_whole() {
    let root = scratch("readonly");
    let dir = root.join("a1b2");
    let ro = dir.join("x.exp");
    write(&ro, "send token");
    let mut perm = fs::metadata(&ro).unwrap().permissions();
    perm.set_readonly(true);
    fs::set_permissions(&ro, perm.clone()).unwrap();
    let mut shredder = Shredder::new(vec![root.clone()]);
    shredder.retry = Duration::from_millis(20);
    shredder.every = Duration::from_millis(5);
    assert!(shredder.shred(s(&dir)).is_err());
    assert_eq!(fs::read_to_string(&ro).unwrap(), "send token");
    #[allow(clippy::permissions_set_readonly_false)]
    perm.set_readonly(false);
    fs::set_permissions(&ro, perm).unwrap();
}

#[test]
fn shred_of_a_gone_path_is_done_and_one_outside_the_roots_is_refused() {
    let root = scratch("gone");
    let shredder = Shredder::new(vec![root.clone()]);
    assert_eq!(shredder.shred(s(&root.join("gone"))), Ok(()));
    let keep = scratch("keep").join("keep.txt");
    write(&keep, "user data");
    assert!(shredder.shred(s(&keep)).is_err());
    assert_eq!(fs::read_to_string(&keep).unwrap(), "user data");
    let missing_outside = scratch("keep").join("missing.txt");
    assert!(shredder.shred(s(&missing_outside)).is_err());
}

#[cfg(windows)]
#[test]
fn shred_tries_again_until_a_holder_lets_go() {
    use std::os::windows::fs::OpenOptionsExt;
    let root = scratch("held");
    let p = root.join("s.ini");
    write(&p, "token");
    let held = fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&p)
        .unwrap();
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        drop(held);
    });
    let mut shredder = Shredder::new(vec![root.clone()]);
    shredder.retry = Duration::from_secs(3);
    shredder.every = Duration::from_millis(20);
    assert_eq!(shredder.shred(s(&p)), Ok(()));
    assert!(!p.exists());
    release.join().unwrap();
}

#[test]
fn a_relative_path_is_refused_even_under_a_relative_root() {
    let shredder = Shredder::new(vec![PathBuf::from(".")]);
    assert!(shredder.admit("Cargo.toml").is_err());
}

#[test]
fn a_shredded_file_is_zeroed_before_it_goes() {
    let root = scratch("zeroed");
    let watcher = scratch("zeroed-watch").join("same.ini");
    let file = root.join("s.ini");
    write(&file, "Password V2=02:abcdef");
    fs::hard_link(&file, &watcher).unwrap();
    assert_eq!(Shredder::new(vec![root]).shred(s(&file)), Ok(()));
    assert!(!file.exists());
    assert_eq!(fs::read(&watcher).unwrap(), [0u8; 21]);
}

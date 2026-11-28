//! The score's write: through a new staging file beside the target, renamed over it, with mode 0666
//! less the umask; a write that fails leaves no staging file.

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use std::io::Write;

use super::{
    Creation, Staging, UNANNOUNCED, conclude, publish, publish_staged, publish_with, staging_with,
    umask as read_umask,
};
use crate::paths::tests::Scratch;

fn umask() -> u32 {
    let status = fs::read_to_string("/proc/thread-self/status").expect("the status reads");
    let line = status
        .lines()
        .find(|line| line.starts_with("Umask:"))
        .expect("a Umask line");
    u32::from_str_radix(line.trim_start_matches("Umask:").trim(), 8).expect("an octal umask")
}

fn staged(dir: &std::path::Path) -> usize {
    fs::read_dir(dir)
        .expect("lists")
        .filter(|entry| {
            entry
                .as_ref()
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".score.json.")
        })
        .count()
}

/// A link at the score's path is replaced and its target stays; the score takes mode 0666 less the
/// umask, and no staging file stays.
#[test]
fn a_score_replaces_a_link_and_takes_its_mode() {
    let scratch = Scratch::new("publish");
    let (target, elsewhere) = (scratch.0.join("score.json"), scratch.0.join("elsewhere"));
    fs::write(&elsewhere, "kept\n").expect("written");
    symlink(&elsewhere, &target).expect("linked");
    publish(&target, "{}\n", read_umask().expect("the mask reads")).expect("the score is written");
    assert_eq!(fs::read_to_string(&target).expect("reads"), "{}\n");
    assert_eq!(fs::read_to_string(&elsewhere).expect("reads"), "kept\n");
    let mode = fs::symlink_metadata(&target)
        .expect("stats")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o666 & !umask());
    assert_eq!(staged(&scratch.0), 0);
}

/// A file published with a creation mode takes the permission bits of any file created there with that
/// mode, as `elsewhere` and `beside` are, whether the kernel applies the umask or the directory's default
/// ACL, and replaces a link at its path while the link's target stays.
#[test]
fn a_file_published_with_a_creation_mode_takes_the_bits_of_a_file_created_beside_it() {
    let scratch = Scratch::new("publish-mode");
    let (target, elsewhere) = (scratch.0.join("report.json"), scratch.0.join("elsewhere"));
    fs::write(&elsewhere, "kept\n").expect("written");
    symlink(&elsewhere, &target).expect("linked");
    publish_with(&target, "{}\n", Creation::Mode(0o666)).expect("the report is written");
    assert_eq!(fs::read_to_string(&target).expect("reads"), "{}\n");
    assert_eq!(fs::read_to_string(&elsewhere).expect("reads"), "kept\n");
    let status = fs::symlink_metadata(&target).expect("stats");
    assert!(status.is_file());
    let control = fs::metadata(&elsewhere)
        .expect("stats")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(status.permissions().mode() & 0o777, control);
    let leftover = fs::read_dir(&scratch.0)
        .expect("lists")
        .filter(|entry| {
            let name = entry.as_ref().expect("an entry").file_name();
            name.to_string_lossy().starts_with(".report.json.")
        })
        .count();
    assert_eq!(leftover, 0);
    let (narrow, beside) = (scratch.0.join("narrow.json"), scratch.0.join("beside"));
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .open(&beside)
            .expect("the control is made");
    }
    publish_with(&narrow, "{}\n", Creation::Mode(0o640)).expect("the file is written");
    let mode =
        |path: &std::path::Path| fs::metadata(path).expect("stats").permissions().mode() & 0o777;
    assert_eq!(
        mode(&narrow),
        mode(&beside),
        "the mode, not 0666, is created"
    );
}

#[test]
fn a_score_takes_the_publishing_thread_s_mask() {
    let scratch = Scratch::new("publish");
    let target = scratch.0.join("score.json");
    let mode = std::thread::spawn(move || {
        // SAFETY: on success, `unshare(CLONE_FS)` gives the calling thread a private filesystem
        // context.
        let unshared = unsafe { libc::unshare(libc::CLONE_FS) };
        assert_eq!(
            unshared, 0,
            "the thread takes a filesystem context of its own"
        );
        // SAFETY: `umask` sets the mask of the private context unshared above.
        unsafe { libc::umask(0o077) };
        publish(&target, "{}\n", read_umask().expect("the mask reads"))
            .expect("the score is written");
        fs::symlink_metadata(&target)
            .expect("stats")
            .permissions()
            .mode()
            & 0o777
    })
    .join()
    .expect("the thread ends");
    assert_eq!(mode, 0o600);
}

/// A staging name that is taken, by a regular file or by a link, is left as it is, and the next name
/// drawn takes the staging file.
#[test]
fn a_taken_staging_name_is_left_as_it_is() {
    let scratch = Scratch::new("publish-taken");
    let target = scratch.0.join("score.json");
    let elsewhere = scratch.0.join("elsewhere");
    fs::write(&elsewhere, "outside\n").expect("written");
    fs::write(scratch.0.join(".score.json.aaaaaaaa"), "taken\n").expect("written");
    symlink(&elsewhere, scratch.0.join(".score.json.bbbbbbbb")).expect("linked");
    let mut names = b"abc".iter().copied();
    let (path, mut file) = staging_with(&target, 0o600, "", |letters| {
        letters.fill(names.next().expect("three names are drawn at most"));
        Ok(())
    })
    .expect("a free name is found");
    assert_eq!(path, scratch.0.join(".score.json.cccccccc"));
    file.write_all(b"staged\n").expect("written");
    assert_eq!(
        fs::read_to_string(scratch.0.join(".score.json.aaaaaaaa")).expect("reads"),
        "taken\n"
    );
    let link = scratch.0.join(".score.json.bbbbbbbb");
    assert!(
        fs::symlink_metadata(&link)
            .expect("stats")
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_to_string(&elsewhere).expect("reads"), "outside\n");
    assert_eq!(fs::read_to_string(&path).expect("reads"), "staged\n");
}

/// A directory at the score's path fails the write, which leaves the directory and no staging file.
#[test]
fn a_score_that_cannot_be_renamed_leaves_no_staging_file() {
    let scratch = Scratch::new("publish-blocked");
    let target = scratch.0.join("score.json");
    fs::create_dir(&target).expect("made");
    let error = publish(&target, "{}\n", 0o022).expect_err("a directory takes no score");
    assert!(error.to_string().contains("score.json"), "{error}");
    assert!(target.is_dir());
    assert_eq!(staged(&scratch.0), 0);
}

struct Refusing;

impl Write for Refusing {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from_raw_os_error(libc::EPIPE))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// `publish` renames the staging file over the target before `conclude` writes the score lines to
/// standard output.
#[test]
fn a_refused_write_of_the_score_s_lines_exits_120_and_keeps_the_score() {
    let scratch = Scratch::new("announce");
    let target = scratch.0.join("score.json");
    let mut err = Vec::new();
    let code = conclude(
        "h",
        &target,
        &[],
        "{}\n",
        |target, bytes| publish(target, bytes, 0o022),
        &mut Refusing,
        &mut err,
    );
    assert_eq!(code, UNANNOUNCED);
    assert_eq!(fs::read_to_string(&target).expect("reads"), "{}\n");
    assert!(err.is_empty());
}

/// A staging with a suffix, an exact mode and a time writes a new file under a name that ends in the
/// suffix, gives the published file the mode as it stands, the set-user-id bit that a write clears and
/// the group and other write bits that the umask clears included, and the time as its
/// modification and access time, and replaces a link at the target while the link's target stays.
#[test]
fn a_staged_file_takes_its_suffix_its_exact_mode_and_its_time() {
    use std::os::unix::fs::MetadataExt;
    let scratch = Scratch::new("publish-staged");
    let (target, elsewhere) = (scratch.0.join("f.rs"), scratch.0.join("elsewhere"));
    fs::write(&elsewhere, "kept\n").expect("written");
    symlink(&elsewhere, &target).expect("linked");
    let later: i128 = 4_102_444_800_123_456_789;
    assert_ne!(
        read_umask().expect("the umask reads") & 0o022,
        0,
        "the umask clears group write"
    );
    let staging = Staging::new(Creation::Exact(0o4766))
        .suffix(".weaken")
        .modified(later);
    publish_staged(&target, b"planted\n", staging).expect("the file is written");
    let status = fs::symlink_metadata(&target).expect("stats");
    assert!(status.is_file());
    assert_eq!(status.permissions().mode() & 0o7777, 0o4766);
    let at = |seconds: i64, nanoseconds: i64| {
        i128::from(seconds) * 1_000_000_000 + i128::from(nanoseconds)
    };
    assert_eq!(at(status.mtime(), status.mtime_nsec()), later);
    assert_eq!(at(status.atime(), status.atime_nsec()), later);
    assert_eq!(fs::read_to_string(&target).expect("reads"), "planted\n");
    assert_eq!(fs::read_to_string(&elsewhere).expect("reads"), "kept\n");
    let mut names = b"ab".iter().copied();
    fs::write(scratch.0.join(".g.rs.aaaaaaaa.weaken"), "taken\n").expect("written");
    let (path, _) = staging_with(&scratch.0.join("g.rs"), 0o600, ".weaken", |letters| {
        letters.fill(names.next().expect("two names are drawn at most"));
        Ok(())
    })
    .expect("a free name is found");
    assert_eq!(path, scratch.0.join(".g.rs.bbbbbbbb.weaken"));
    let left: Vec<String> = fs::read_dir(&scratch.0)
        .expect("lists")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.starts_with(".f.rs."))
        .collect();
    assert_eq!(
        left,
        Vec::<String>::new(),
        "no staging file of the write stays"
    );
}

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use crate::git::{GitError, batch_texts, blob_texts, git, label, merge_base};
use crate::text::strip_str;

fn specs(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

#[test]
fn a_batch_reply_reads_each_blob_and_an_absent_name_as_empty_text() {
    let reply = b"1111 blob 3\nabc\nHEAD:gone missing\nHEAD:a b.rs missing\n3333 tree 4\n\x01\x02\x03\x04\n4444 blob 0\n\n";
    let names = specs(&[
        "HEAD:x",
        "HEAD:gone",
        "HEAD:a b.rs",
        "HEAD:dir",
        "HEAD:empty",
    ]);
    let texts = batch_texts(reply, &names).expect("the reply reads");
    assert_eq!(texts, ["abc", "", "", "", ""]);
}

#[test]
fn a_blob_that_is_not_utf8_names_the_blob() {
    let error = batch_texts(b"1111 blob 2\n\xff\xfe\n", &specs(&["abc:src/model.rs"]))
        .expect_err("the blob is not UTF-8");
    assert!(matches!(error, GitError::NotUtf8(_)), "{error:?}");
    assert_eq!(
        error.to_string(),
        "abc:src/model.rs: invalid utf-8 sequence of 1 bytes from index 0"
    );
}

#[test]
fn a_reply_that_ends_before_an_answer_is_truncated() {
    let error = batch_texts(b"1111 blob 1\na\n", &specs(&["HEAD:a", "HEAD:b"]))
        .expect_err("the second answer is missing");
    assert!(matches!(error, GitError::Truncated(_)), "{error:?}");
}

/// A reply is `<id> <type> <size>`, a line feed, `size` bytes and a line feed, or `<name> missing` for its own
/// request's name. A body cut before its size or its line feed, a header of another form, a `missing` line for
/// another name and bytes after the last reply are each the reader's truncation error, which names the request.
#[test]
fn a_reply_of_another_form_is_truncated() {
    for (reply, name) in [
        (&b"1111 blob 99\nab"[..], "HEAD:a"),
        (b"1111 blob 2\nab", "HEAD:a"),
        (b"1111 blob 2\nabc\n", "HEAD:a"),
        (b"1111 blob\nab\n", "HEAD:a"),
        (b"1111\x0bblob\x0c2\nhi\n", "HEAD:a"),
        (b"1111  blob 2\nhi\n", "HEAD:a"),
        (b"1111 blob -2\nhi\n", "HEAD:a"),
        (b"HEAD:b missing\n", "HEAD:a"),
        (b"HEAD:a  missing\n", "HEAD:a"),
    ] {
        let error = batch_texts(reply, &specs(&[name])).expect_err("the reply is refused");
        assert!(
            matches!(error, GitError::Truncated(_)),
            "{reply:?}: {error:?}"
        );
        assert!(error.to_string().contains(name), "{error}");
    }
    let error = batch_texts(b"HEAD:a missing\n1111 blob 1\nx\n", &specs(&["HEAD:a"]))
        .expect_err("the reply goes on");
    assert_eq!(
        error.to_string(),
        "git cat-file --batch: the reply goes on after its 1 answers"
    );
    let error =
        batch_texts(b"1111 blob 99\nab", &specs(&["HEAD:a"])).expect_err("the body is short");
    assert_eq!(
        error.to_string(),
        "git cat-file --batch: the reply ends before its answer for HEAD:a"
    );
}

/// A name that holds a line feed would be two requests, so `blob_texts` refuses it before Git starts.
#[test]
fn a_name_that_holds_a_line_feed_is_refused_before_git_starts() {
    let error = blob_texts(&specs(&["HEAD:a", "HEAD:a\nb"])).expect_err("the name is refused");
    assert!(matches!(error, GitError::Name(_)), "{error:?}");
    assert_eq!(
        error.to_string(),
        "git cat-file --batch: the name 'HEAD:a\\nb' holds a line feed"
    );
}

#[test]
fn strip_removes_python_white_space_at_both_ends() {
    assert_eq!(strip_str("\u{1c}\u{3000} a b\t\u{85}\n"), "a b");
    assert_eq!(strip_str("\u{200b}x"), "\u{200b}x");
}

#[test]
fn a_label_writes_a_byte_outside_utf8_as_its_surrogate_escape() {
    let args = [
        OsStr::new("diff"),
        OsStr::from_bytes(b":(top,literal)caf\xe9.rs"),
    ];
    assert_eq!(label(&args), "git diff :(top,literal)caf\\udce9.rs");
}

#[test]
fn a_failed_command_names_itself_and_its_stripped_standard_error() {
    let error = git(&[
        "rev-parse",
        "--verify",
        "--end-of-options",
        "no-such-rev-365^{commit}",
    ])
    .expect_err("the revision does not exist");
    let GitError::Failed(text) = error else {
        panic!("the command fails: {error:?}");
    };
    assert!(
        text.starts_with(
            "git rev-parse --verify --end-of-options no-such-rev-365^{commit}: fatal: "
        ),
        "{text}"
    );
    assert!(!text.ends_with('\n'), "{text:?}");
}

#[test]
fn an_unknown_commit_has_no_merge_base_but_fails() {
    let error = merge_base("HEAD", "f".repeat(40).as_str()).expect_err("the commit does not exist");
    assert!(matches!(error, GitError::Failed(_)), "{error:?}");
}

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use crate::git::{GitError, batch_texts, git, label, merge_base};
use crate::text::strip_str;

fn specs(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

#[test]
fn a_batch_reply_reads_each_blob_and_an_absent_name_as_empty_text() {
    let reply = b"1111 blob 3\nabc\n2222 missing\nHEAD:a b.rs missing\n3333 tree 4\n\x01\x02\x03\x04\n4444 blob 0\n\n";
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
fn a_header_split_by_vertical_tab_or_form_feed_names_a_blob() {
    let texts =
        batch_texts(b"1111\x0bblob\x0c2\nhi\n", &specs(&["HEAD:x"])).expect("the reply reads");
    assert_eq!(texts, ["hi"]);
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

#[test]
fn a_size_past_the_reply_takes_the_rest_of_the_reply() {
    let texts = batch_texts(b"1111 blob 99\nab", &specs(&["HEAD:a"])).expect("the reply reads");
    assert_eq!(texts, ["ab"]);
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

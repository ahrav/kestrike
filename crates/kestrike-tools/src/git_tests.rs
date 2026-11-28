use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

use crate::environ::{Environ, first_of_each, get};
use crate::git::{
    Bodyless, GitError, batch_texts, blob_bytes, blob_texts, caller_environ, command, git, label,
    merge_base, push_environ, replies, without_pathspec_modes,
};
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
/// request's name. A body cut before its size or its line feed, a header of another form and a `missing` line
/// for another name are each the reader's truncation error, which names the request with its control
/// characters escaped; bytes after the last reply are a truncation error that names the count of answers.
#[test]
fn a_reply_of_another_form_is_truncated() {
    for (reply, name) in [
        (&b"1111 blob 2\nab"[..], "HEAD:a"),
        (b"1111 blob 2\nabc\n", "HEAD:a"),
        (b"1111 blob\nab\n", "HEAD:a"),
        (b"1111\x0bblob\x0c2\nhi\n", "HEAD:a"),
        (b"1111  blob 2\nhi\n", "HEAD:a"),
        (b"1111  2\nhi\n", "HEAD:a"),
        (b" blob 2\nhi\n", "HEAD:a"),
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
    let error =
        batch_texts(b"1111 blob 2\nab", &specs(&["HEAD:a\r::b"])).expect_err("the body is cut");
    assert_eq!(
        error.to_string(),
        "git cat-file --batch: the reply ends before its answer for HEAD:a\\r::b"
    );
}

/// Git reads a line feed in a batch name as a request separator, reads a name up to a NUL and strips a final
/// carriage return, so `blob_texts` refuses each such name as a name, wherever it stands in the batch.
#[test]
fn a_name_that_git_would_read_as_another_is_refused_as_a_name() {
    for (name, said) in [
        ("HEAD:a\nb", "'HEAD:a\\nb' holds a line feed"),
        ("HEAD:a\0b", "'HEAD:a\\x00b' holds a NUL"),
        ("HEAD:a\r\r", "'HEAD:a\\r\\r' ends in a carriage return"),
    ] {
        let error = blob_texts(&caller_environ(), &specs(&["HEAD:a", name]))
            .expect_err("the name is refused");
        assert!(matches!(error, GitError::Name(_)), "{error:?}");
        assert_eq!(
            error.to_string(),
            format!("git cat-file --batch: the name {said}")
        );
    }
    assert!(!matches!(
        blob_texts(&caller_environ(), &specs(&["HEAD:a\rb"])),
        Err(GitError::Name(_))
    ));
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
    let error = git(
        &caller_environ(),
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            "no-such-rev-365^{commit}",
        ],
    )
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
    let error = merge_base(&caller_environ(), "HEAD", "f".repeat(40).as_str())
        .expect_err("the commit does not exist");
    assert!(matches!(error, GitError::Failed(_)), "{error:?}");
}

/// The names are Git's repository, work tree, index, common directory and object store variables, in the
/// order a refusal lists them.
#[test]
fn the_repository_variables_are_the_five_in_order() {
    assert_eq!(
        crate::git::REPOSITORY_VARIABLES,
        [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY",
        ]
    );
}

/// `bytes` reads `reply` for `names` as the bytes reader does.
fn bytes(reply: &[u8], names: &[String]) -> Result<Vec<Option<Vec<u8>>>, GitError> {
    let read = replies(
        reply,
        names,
        Bodyless::Absent,
        |_, kind: &[u8], body: &[u8]| Ok((kind == b"blob").then(|| body.to_vec())),
    )?;
    Ok(read.into_iter().map(Option::flatten).collect())
}

/// The bytes reader answers a missing name and a tree with `None` and an empty blob with its empty bytes.
#[test]
fn a_batch_reply_of_bytes_tells_an_absent_name_and_a_tree_from_an_empty_blob() {
    let reply =
        b"1111 blob 3\nabc\nHEAD:gone missing\n3333 tree 4\n\x01\x02\x03\x04\n4444 blob 0\n\n";
    let names = specs(&["HEAD:a", "HEAD:gone", "HEAD:dir", "HEAD:empty"]);
    assert_eq!(
        bytes(reply, &names).expect("the reply reads"),
        [Some(b"abc".to_vec()), None, None, Some(Vec::new())]
    );
}

/// The bytes reader reads an ambiguous name and a submodule's answer, which carry no body, as absent and
/// pairs the next reply with the next name; the text reader refuses both, and the bytes reader refuses an
/// ambiguous reply for another name and a submodule answer whose id is no full object id.
#[test]
fn a_batch_reply_of_bytes_reads_an_ambiguous_name_and_a_submodule_as_absent() {
    let module = "c".repeat(40);
    let reply = format!("HEAD:x ambiguous\n{module} submodule\n1111 blob 2\nab\n");
    let names = specs(&["HEAD:x", "HEAD:m", "HEAD:a"]);
    assert_eq!(
        bytes(reply.as_bytes(), &names).expect("the reply reads"),
        [None, None, Some(b"ab".to_vec())]
    );
    assert!(matches!(
        batch_texts(reply.as_bytes(), &names),
        Err(GitError::Truncated(_))
    ));
    for refused in ["HEAD:y ambiguous\n", "cccc submodule\n"] {
        let error = bytes(refused.as_bytes(), &specs(&["HEAD:x"])).expect_err("another form");
        assert_eq!(
            error.to_string(),
            "git cat-file --batch: the answer for HEAD:x has another form"
        );
    }
    let asked = "a".repeat(40);
    let other = format!("{module} submodule\n");
    assert!(matches!(
        bytes(other.as_bytes(), &specs(&[&asked])),
        Err(GitError::Truncated(_))
    ));
}

/// A reply that answers a full object id with another id is refused, and a name that is no object id may be
/// answered with any id.
#[test]
fn a_reply_for_another_object_id_is_refused() {
    let asked = "a".repeat(40);
    let reply = format!("{} blob 1\nx\n", "b".repeat(40));
    let error = replies(
        reply.as_bytes(),
        &specs(&[&asked]),
        Bodyless::Refused,
        |_, _, _| Ok(()),
    )
    .expect_err("the id differs");
    assert!(matches!(error, GitError::Truncated(_)), "{error:?}");
    assert_eq!(
        error.to_string(),
        format!("git cat-file --batch: the answer for {asked} has another form")
    );
    assert!(
        replies(
            reply.as_bytes(),
            &specs(&["HEAD:a"]),
            Bodyless::Refused,
            |_, _, _| Ok(())
        )
        .is_ok()
    );
    let same = format!("{asked} blob 1\nx\n");
    assert!(
        replies(
            same.as_bytes(),
            &specs(&[&asked]),
            Bodyless::Refused,
            |_, _, _| Ok(())
        )
        .is_ok()
    );
}

/// The bytes reader refuses a name Git would split, cut or read without its final carriage return, and
/// keeps a carriage return inside a name.
#[test]
fn the_bytes_reader_refuses_a_line_feed_a_nul_or_a_final_carriage_return_in_a_name() {
    for (name, said) in [
        ("HEAD:a\nb", "'HEAD:a\\nb' holds a line feed"),
        ("HEAD:a\0b", "'HEAD:a\\x00b' holds a NUL"),
        ("HEAD:a\r", "'HEAD:a\\r' ends in a carriage return"),
    ] {
        let error = blob_bytes(&caller_environ(), &specs(&["HEAD:a", name])).expect_err("refused");
        assert!(matches!(error, GitError::Name(_)), "{error:?}");
        assert_eq!(
            error.to_string(),
            format!("git cat-file --batch: the name {said}")
        );
    }
    assert!(!matches!(
        blob_bytes(&caller_environ(), &specs(&["HEAD:a\rb"])),
        Err(GitError::Name(_))
    ));
}

/// Both environments set replace objects off; the push's drops each pathspec mode variable and keeps every
/// other variable in order.
#[test]
fn the_push_environment_removes_the_pathspec_modes() {
    assert_eq!(
        get(&caller_environ(), "GIT_NO_REPLACE_OBJECTS"),
        Some(&"1".into())
    );
    assert_eq!(
        get(&push_environ(), "GIT_NO_REPLACE_OBJECTS"),
        Some(&"1".into())
    );
    let pair = |name: &str, value: &str| (OsString::from(name), OsString::from(value));
    let given = vec![
        pair("A", "1"),
        pair("GIT_LITERAL_PATHSPECS", "1"),
        pair("GIT_GLOB_PATHSPECS", "1"),
        pair("B", "2"),
        pair("GIT_NOGLOB_PATHSPECS", "1"),
        pair("A", "3"),
        pair("GIT_ICASE_PATHSPECS", "1"),
        pair("GIT_GLOB_PATHSPECS", "1"),
    ];
    assert_eq!(
        without_pathspec_modes(first_of_each(given)),
        [pair("A", "1"), pair("B", "2")]
    );
}

/// A command started in an environment sets only the variables whose values differ from this process's
/// and removes those the environment lacks, so it leaves `PATH` to the process when the value's is the
/// same; of a repeated name it sets the last value.
#[test]
fn a_command_sets_only_the_variables_that_differ_from_the_process() {
    let mut environ: Environ = std::env::vars_os()
        .filter(|(name, _)| name != "HOME")
        .collect();
    environ.push((OsString::from("KESTRIKE_GIT_TEST_A"), OsString::from("1")));
    environ.push((OsString::from("KESTRIKE_GIT_TEST_A"), OsString::from("2")));
    let changed: Vec<(OsString, Option<OsString>)> = command(&environ, "git")
        .get_envs()
        .map(|(name, value)| (name.to_owned(), value.map(OsStr::to_owned)))
        .collect();
    let mut expected = vec![(
        OsString::from("KESTRIKE_GIT_TEST_A"),
        Some(OsString::from("2")),
    )];
    if std::env::var_os("HOME").is_some() {
        expected.push((OsString::from("HOME"), None));
    }
    expected.sort();
    let mut changed = changed;
    changed.sort();
    assert_eq!(changed, expected);
}

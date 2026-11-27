use super::{EXTERNAL, Kind, Op, Site, line_of, read, sites};

const FILL: &str = "crates/kestrike/src/storage/fill.rs";
const GRACE: &str = "crates/kestrike/src/storage/grace.rs";
const CREDIT: &str = "crates/kestrike/src/storage/credit.rs";
const SEQUENCE: &str = "crates/kestrike/src/index/sequence.rs";

/// A planted source and the sites its reading holds, each as (line, the production text the site spans,
/// its variant or `fence`, its op). The first column names the case whose planted source the row takes,
/// or the code check the row exercises.
type SiteRow = (
    &'static str,
    &'static str,
    &'static str,
    &'static [(usize, &'static str, &'static str, &'static str)],
);

/// A planted source and the defects its reading holds, in order.
type DefectRow = (
    &'static str,
    &'static str,
    &'static str,
    &'static [&'static str],
);

fn ordering_ops(scanned: &str) -> Vec<(&'static str, Op)> {
    sites(scanned)
        .iter()
        .map(|site| match site.kind() {
            Kind::Ordering { strength, op } => (strength.name(), op),
            Kind::Fence { .. } => ("fence", Op::Unread),
        })
        .collect()
}

fn described(text: &str, production: &str, found: &[Site]) -> Vec<(usize, String, String, String)> {
    found
        .iter()
        .map(|site| {
            let name = match site.kind() {
                Kind::Ordering { strength, .. } => strength.name(),
                Kind::Fence { .. } => "fence",
            };
            (
                line_of(text, site.start()),
                production[site.start()..site.end()].to_owned(),
                name.to_owned(),
                site.op_name().to_owned(),
            )
        })
        .collect()
}

/// An ordering passed to an associated function through a path is no method argument, so its op is
/// unread.
#[test]
fn a_path_call_compare_exchange_ordering_is_no_read_op() {
    let scanned = "AtomicU64::compare_exchange(&s, 0, 1, Ordering::SeqCst, Ordering::Acquire)";
    assert_eq!(
        ordering_ops(scanned),
        [("SeqCst", Op::Unread), ("Acquire", Op::Unread)]
    );
}

#[test]
fn the_matcher_reads_each_compare_exchange_ordering_by_position() {
    let cases: [(&str, &[(&str, Op)]); 5] = [
        (
            "s.compare_exchange(0,1,Ordering::Release,Ordering::Acquire)",
            &[("Release", Op::Rmw), ("Acquire", Op::Load)],
        ),
        (
            "s.fetch_update(Ordering::SeqCst, Ordering::SeqCst, f)",
            &[("SeqCst", Op::Rmw), ("SeqCst", Op::Load)],
        ),
        (
            "s.compare_exchange(word, word | BIT, Ordering::SeqCst, Ordering::Acquire)",
            &[("SeqCst", Op::Rmw), ("Acquire", Op::Load)],
        ),
        (
            "s.compare_exchange_weak(0, 1, Ordering::SeqCst, Ordering::Acquire)",
            &[("SeqCst", Op::Rmw), ("Acquire", Op::Load)],
        ),
        ("s.swap(1, Ordering::AcqRel)", &[("AcqRel", Op::Rmw)]),
    ];
    for (scanned, expected) in cases {
        assert_eq!(ordering_ops(scanned), expected, "{scanned}");
    }
}

/// A `<` or `>` outside brackets in an earlier argument may be a generic argument list whose commas the
/// count would take for argument separators, so neither ordering's op is read.
#[test]
fn an_earlier_operand_with_angle_brackets_leaves_a_compare_exchange_ordering_unread() {
    for method in ["compare_exchange", "compare_exchange_weak"] {
        for operand in ["pack::<A, B>(x)", "a < b"] {
            let scanned = format!("s.{method}({operand}, 1, Ordering::SeqCst, Ordering::Acquire)");
            assert_eq!(
                ordering_ops(&scanned),
                [("SeqCst", Op::Unread), ("Acquire", Op::Unread)],
                "{scanned}"
            );
        }
    }
}

/// Each row's planted source reads the sites listed beside it, which the script's reading gave for the
/// same source.
#[test]
fn each_planted_source_reads_its_recorded_sites() {
    for &(case, path, source, expected) in SITE_ROWS {
        let reading = read(path, source, EXTERNAL);
        let expected: Vec<(usize, String, String, String)> = expected
            .iter()
            .map(|&(line, token, name, op)| {
                (line, token.to_owned(), name.to_owned(), op.to_owned())
            })
            .collect();
        assert_eq!(
            described(source, reading.production(), reading.sites()),
            expected,
            "{case}: {source:?}"
        );
    }
}

/// Each row's planted source reads the defect sentences listed beside it, which the script's reading gave
/// for the same source.
#[test]
fn each_planted_source_reads_its_recorded_defects() {
    for &(case, path, source, expected) in DEFECT_ROWS {
        assert_eq!(
            read(path, source, EXTERNAL).defects(),
            expected,
            "{case}: {source:?}"
        );
    }
}

/// A text with no source reads as two empty texts, no site and no defect.
#[test]
fn an_empty_text_reads_as_nothing() {
    let reading = read(FILL, "", EXTERNAL);
    assert_eq!(
        (
            reading.production(),
            reading.scanned(),
            reading.sites().len()
        ),
        ("", "", 0)
    );
    assert!(reading.defects().is_empty());
}

/// A fence call's site records the offset of its opening bracket, and the ordering passed directly to it
/// belongs to the fence.
#[test]
fn a_fence_call_holds_its_opening_bracket_and_its_direct_ordering() {
    let text = "fn f() { std::sync::atomic::fence(Ordering::SeqCst); }";
    let found: Vec<(usize, usize, Kind)> = read(FILL, text, EXTERNAL)
        .sites()
        .iter()
        .map(|site| (site.start(), site.end(), site.kind()))
        .collect();
    assert_eq!(found, [(9, 52, Kind::Fence { open: 33 })]);
}

const NBSP: &str = "\u{a0}";

/// Each window spans its count of code points of the source. A no-break space is white space of two
/// bytes, so a window counted in bytes would end before the text these rows place at its edge; a `é` in a
/// comment is one code point of the source and two spaces of the scanned text, so a window counted over
/// the scanned text would end before it too.
#[test]
fn a_window_spans_its_count_of_code_points() {
    let method = |spaces: usize| {
        format!(
            "pub(crate) fn peek(state: &AtomicU64) -> u64 {{\n    state.load{}(Ordering::Acquire)\n}}\n",
            NBSP.repeat(spaces)
        )
    };
    let ops = |text: &str| -> Vec<&'static str> {
        read(FILL, text, EXTERNAL)
            .sites()
            .iter()
            .map(Site::op_name)
            .collect()
    };
    assert_eq!(
        ops(&method(195)),
        ["load"],
        "the method's `.` 200 code points back"
    );
    assert_eq!(
        ops(&method(196)),
        ["unread"],
        "the method's `.` 201 code points back"
    );
    let definition = |spaces: usize| format!("fn{}fence() {{}}\n", NBSP.repeat(spaces));
    assert_eq!(
        ops(&definition(198)),
        Vec::<&str>::new(),
        "`fn` 200 code points back"
    );
    assert_eq!(
        ops(&definition(199)),
        ["fence"],
        "`fn` 201 code points back"
    );
    let call = |spaces: usize| {
        format!(
            "fn extra() {{\n    fence{}(Ordering::SeqCst);\n}}\n",
            NBSP.repeat(spaces)
        )
    };
    assert!(
        read(FILL, &call(199), EXTERNAL).defects().is_empty(),
        "`(` within 200 code points"
    );
    assert_eq!(
        read(FILL, &call(200), EXTERNAL).defects(),
        [
            "crates/kestrike/src/storage/fill.rs:2: a fence path named outside a call hides the sites it names \
             from the matcher"
        ],
        "`(` 201 code points after the name"
    );
    let commented = |count: usize| "\u{e9}".repeat(count);
    let method = |count: usize| {
        format!(
            "pub(crate) fn peek(state: &AtomicU64) -> u64 {{\n    state.load/*{}*/(Ordering::Acquire)\n}}\n",
            commented(count)
        )
    };
    assert_eq!(
        ops(&method(191)),
        ["load"],
        "a comment's code points count once each"
    );
    assert_eq!(ops(&method(192)), ["unread"]);
    let definition = |count: usize| format!("fn/*{}*/fence() {{}}\n", commented(count));
    assert_eq!(ops(&definition(194)), Vec::<&str>::new());
    assert_eq!(ops(&definition(195)), ["fence"]);
    let call = |count: usize| {
        format!(
            "fn extra() {{\n    fence/*{}*/(Ordering::SeqCst);\n}}\n",
            commented(count)
        )
    };
    assert!(read(FILL, &call(195), EXTERNAL).defects().is_empty());
    assert_eq!(read(FILL, &call(196), EXTERNAL).defects().len(), 1);
}

#[rustfmt::skip]
const SITE_ROWS: &[SiteRow] = &[
    ("a_new_acquire_load_without_a_row_is_refused_by_file_and_token", FILL, "pub(crate) fn peek(state: &AtomicU64) -> u64 {\n    state.load(Ordering::Acquire)\n}\n", &[(2, "Ordering::Acquire", "Acquire", "load")]),
    ("a_new_acquire_load_without_a_row_is_refused_by_file_and_token", FILL, "pub(crate) fn peek(state: &AtomicU64) -> u64 {\n    state.store(1, Ordering::Release)\n}\n", &[(2, "Ordering::Release", "Release", "store")]),
    ("a_new_acquire_load_without_a_row_is_refused_by_file_and_token", FILL, "pub(crate) fn peek(state: &AtomicU64) -> u64 {\n    state.fetch_or(1, Ordering::AcqRel)\n}\n", &[(2, "Ordering::AcqRel", "AcqRel", "rmw")]),
    ("a_new_acquire_load_without_a_row_is_refused_by_file_and_token", FILL, "pub(crate) fn peek(state: &AtomicU64) -> u64 {\n    apply(Ordering::SeqCst)\n}\n", &[(2, "Ordering::SeqCst", "SeqCst", "unread")]),
    ("a_new_acquire_load_without_a_row_is_refused_by_file_and_token", FILL, "pub(crate) fn peek(state: &AtomicU64, #[cfg(test)] probe: u8) -> u64 {\n    state.load(Ordering::Acquire)\n}\n", &[(2, "Ordering::Acquire", "Acquire", "load")]),
    ("a_new_acquire_load_without_a_row_is_refused_by_file_and_token", FILL, "pub(crate) fn peek<A, #[cfg(test)] B>(state: &AtomicU64) -> u64 {\n    state.load(Ordering::Acquire)\n}\n", &[(2, "Ordering::Acquire", "Acquire", "load")]),
    ("an_ordering_inside_a_comment_or_a_test_item_is_no_site", FILL, "// state.load(Ordering::Acquire)\n#[cfg(test)]\nfn peek(state: &AtomicU64) -> u64 {\n    state.load(Ordering::Acquire)\n}\n", &[]),
    ("a_site_after_a_test_only_element_is_a_site", FILL, "pub(crate) trait Planted<T: Bound<{ true }>, #[cfg(test)] U> {\n    fn peek(state: &AtomicU64) -> u64 {\n        state.load(Ordering::Acquire)\n    }\n}\n", &[(3, "Ordering::Acquire", "Acquire", "load")]),
    ("a_site_after_a_test_only_element_is_a_site", FILL, "fn ready(state: &AtomicU64, a: bool, b: bool, n: u64) -> bool {\n    match n {\n        0 => a || b,\n        #[cfg(test)]\n        1 => n < 2,\n        _ => state.load(Ordering::Acquire) == n,\n    }\n}\n", &[(6, "Ordering::Acquire", "Acquire", "load")]),
    ("a_site_after_a_test_only_element_is_a_site", FILL, "fn probe(state: &AtomicU64) -> S {\n    S { a: x || y, #[cfg(test)] probe: n < 2, live: state.load(Ordering::Acquire) }\n}\n", &[(2, "Ordering::Acquire", "Acquire", "load")]),
    ("a_new_fence_without_a_row_is_refused", FILL, "fn extra<W: FillWord>() {\n    std::sync::atomic::fence(Ordering::SeqCst);\n}\n", &[(2, "std::sync::atomic::fence(Ordering::SeqCst);", "fence", "fence")]),
    ("a_new_fence_without_a_row_is_refused", FILL, "fn extra<W: FillWord>() {\n    std::sync::atomic::compiler_fence(Ordering::Release);\n}\n", &[(2, "std::sync::atomic::compiler_fence(Ordering::Release);", "fence", "fence")]),
    ("a_new_fence_without_a_row_is_refused", FILL, "fn extra<W: FillWord>() {\n    ::std::sync::atomic::fence(Ordering::SeqCst);\n}\n", &[(2, "::std::sync::atomic::fence(Ordering::SeqCst);", "fence", "fence")]),
    ("a_new_fence_without_a_row_is_refused", FILL, "fn extra<W: FillWord>() {\n    <W as FillWord>::acquire_fence();\n}\n", &[(2, "<W as FillWord>::acquire_fence();", "fence", "fence")]),
    ("a_new_fence_without_a_row_is_refused", FILL, "fn extra<W: FillWord>() {\n    <W as Into<u8>>::acquire_fence();\n}\n", &[(2, "<W as Into<u8>>::acquire_fence();", "fence", "fence")]),
    ("a_new_fence_without_a_row_is_refused", FILL, "fn extra<W: FillWord>() {\n    W::fence_clear();\n}\n", &[(2, "W::fence_clear();", "fence", "fence")]),
    ("a_rooted_fence_row_deletes_the_whole_path", FILL, "fn extra() {\n    ::std::sync::atomic::fence(Ordering::SeqCst);\n}\n", &[(2, "::std::sync::atomic::fence(Ordering::SeqCst);", "fence", "fence")]),
    ("an_ordering_nested_in_a_fence_named_call_is_its_own_site", FILL, "fn extra(state: &AtomicU64) {\n    record_fence_epoch(state.load(Ordering::Acquire));\n}\n", &[(2, "record_fence_epoch(state.load(Ordering::Acquire));", "fence", "fence"), (2, "Ordering::Acquire", "Acquire", "load")]),
    ("an_ordering_nested_in_a_fence_named_call_is_its_own_site", FILL, "fn extra(state: &AtomicU64) {\n    std::sync::atomic::fence(order_of(state.load(Ordering::Acquire)));\n}\n", &[(2, "std::sync::atomic::fence(order_of(state.load(Ordering::Acquire)));", "fence", "fence"), (2, "Ordering::Acquire", "Acquire", "load")]),
    ("a_hook_with_a_body_is_a_fence_site", GRACE, "trait Strength {\n    fn fence_pin() {\n        std::sync::atomic::fence(Ordering::SeqCst);\n    }\n}\nfn pin<S: Strength>() {\n    S::fence_pin();\n}\n", &[(3, "std::sync::atomic::fence(Ordering::SeqCst);", "fence", "fence"), (7, "S::fence_pin();", "fence", "fence")]),
    ("a_hook_with_a_body_is_a_fence_site", GRACE, "trait Strength {\n    fn fence_pin() {}\n}\nimpl Strength for Sequential {\n    fn fence_pin() {\n        std::sync::atomic::fence(Ordering::SeqCst);\n    }\n}\nfn pin<S: Strength>() {\n    S::fence_pin();\n}\n", &[(6, "std::sync::atomic::fence(Ordering::SeqCst);", "fence", "fence"), (10, "S::fence_pin();", "fence", "fence")]),
    ("a_hook_with_a_body_is_a_fence_site", GRACE, "trait Strength {\n    fn fence_pin() {}\n}\nfn pin<S: Strength>() {\n    S::fence_pin();\n}\n", &[]),
    ("a_hook_with_a_body_is_a_fence_site", GRACE, "fn pin<S: Strength>() {\n    S::fence_pin();\n}\n", &[(2, "S::fence_pin();", "fence", "fence")]),
    ("a_hook_with_a_body_is_a_fence_site", GRACE, "trait Hooks {\n    fn fence_pin();\n}\nfn pin<S: Strength>() {\n    S::fence_pin();\n}\n", &[(5, "S::fence_pin();", "fence", "fence")]),
    ("a_strength_constant_takes_its_op_from_the_code", GRACE, "impl Strength for Sequential {\n    const VISIT: Ordering = Ordering::SeqCst;\n}\nfn visit<W: EraWord, S: Strength>(record: &W) -> u64 {\n    record.load(S::VISIT)\n}\n", &[(2, "Ordering::SeqCst", "SeqCst", "load")]),
    ("a_strength_constant_takes_its_op_from_the_code", CREDIT, "impl Strength for Sequential {\n    const RELOAD: Ordering = Ordering::SeqCst;\n}\n", &[(2, "Ordering::SeqCst", "SeqCst", "load")]),
    ("a_strength_constant_takes_its_op_from_the_code", FILL, "impl Strength for Sequential {\n    const RELOAD: Ordering = Ordering::SeqCst;\n}\n", &[(2, "Ordering::SeqCst", "SeqCst", "unread")]),
    ("a_strength_constant_passed_to_two_ops_is_unread", GRACE, "impl Strength for Sequential {\n    const VISIT: Ordering = Ordering::SeqCst;\n}\nfn visit<W: EraWord, S: Strength>(record: &W) -> u64 {\n    record.load(S::VISIT)\n}\nfn spare<W: EraWord, S: Strength>(record: &W) {\n    record.store(0, S::VISIT);\n}\n", &[(2, "Ordering::SeqCst", "SeqCst", "unread")]),
    ("a_strength_constant_passed_to_two_ops_is_unread", GRACE, "impl Strength for Sequential {\n    const VISIT: Ordering = Ordering::SeqCst;\n}\nfn visit<W: EraWord, S: Strength>(record: &W) -> u64 {\n    record.load(S::VISIT)\n}\nfn spare<W: EraWord, S: Strength>(record: &W) {\n    record.store(0, S :: VISIT);\n}\n", &[(2, "Ordering::SeqCst", "SeqCst", "unread")]),
    ("a_site_whose_op_the_matcher_cannot_read_is_refused", CREDIT, "fn reset(map: &AtomicU64, bits: u64) {\n    let order = Ordering::SeqCst;\n    map.fetch_or(bits, order);\n}\n", &[(2, "Ordering::SeqCst", "SeqCst", "unread")]),
    ("the_text_of_a_test_only_element_after_its_first_block_is_a_stated_limit", GRACE, "pub(crate) fn unpin<W: EraWord>(record: &W) {\n    #[cfg(test)]\n    let _ = if skip() { 0 } else { record.store(INACTIVE, Ordering::Release); 1 };\n    record.store(INACTIVE, Ordering::Relaxed);\n}\n", &[(3, "Ordering::Release", "Release", "store")]),
    ("the_text_of_a_test_only_element_after_its_first_block_is_a_stated_limit", GRACE, "pub(crate) fn unpin<W: EraWord>(record: &W) {\n    #[cfg(test)]\n    for Probe { n } in probes() { record.store(INACTIVE, Ordering::Release); }\n    record.store(INACTIVE, Ordering::Relaxed);\n}\n", &[(3, "Ordering::Release", "Release", "store")]),
    ("a_test_only_element_the_matcher_cuts_is_refused", FILL, "with_probe!(; #[cfg(test)] B> fn extra(state: &AtomicU64) { state.load(Ordering::Acquire); });\n", &[(1, "Ordering::Acquire", "Acquire", "load")]),
    ("a_test_only_element_the_matcher_cuts_is_refused", GRACE, "impl Strength for Sequential {\n    #[cfg(not(test))]\n    const VISIT: Ordering = Ordering::Relaxed;\n    #[cfg(test)]\n    const VISIT: Ordering = if 1 > 0 {\n        const VISIT: Ordering = Ordering::SeqCst;\n        VISIT\n    } else {\n        Ordering::Relaxed\n    };\n}\n", &[]),
    ("a_test_only_element_the_matcher_cuts_is_refused", FILL, "pub(crate) fn observe<W: FillWord>(state: &W, next_serial: u64) -> Result<Record, Malformed> {\n    match next_serial {\n        #[cfg(test)]\n        0 | 1 => decode(state.load(Ordering::Acquire), next_serial),\n        _ => decode(state.load(Ordering::Relaxed), next_serial),\n    }\n}\n", &[]),
    ("a_test_only_element_the_matcher_cuts_is_refused", GRACE, "impl Strength for Sequential {\n    #[cfg(not(test))]\n    const VISIT: Ordering = Ordering::Relaxed;\n    #[cfg(test)]\n    const VISIT: Ordering = Ordering::SeqCst;\n}\n", &[]),
    ("ORDERING: a word character outside ASCII before it", FILL, "pub(crate) fn peek(state: &AtomicU64) -> u64 {\n    state.load(\u{b2}Ordering::Acquire)\n}\n", &[]),
    ("ORDERING: a mark outside ASCII after it", FILL, "pub(crate) fn peek(state: &AtomicU64) -> u64 {\n    state.load(Ordering::Acquire\u{301})\n}\n", &[(2, "Ordering::Acquire", "Acquire", "load")]),
    ("ORDERING: a word character outside ASCII after it", FILL, "pub(crate) fn peek(state: &AtomicU64) -> u64 {\n    state.load(Ordering::Acquire\u{b2})\n}\n", &[]),
    ("FENCE: a mark outside ASCII after the name", FILL, "fn extra() {\n    std::sync::atomic::fence\u{301}(Ordering::SeqCst);\n}\n", &[(2, "Ordering::SeqCst", "SeqCst", "unread")]),
    ("FENCE: a mark outside ASCII before the name", FILL, "fn extra() {\n    std::sync::atomic::\u{301}fence(Ordering::SeqCst);\n}\n", &[(2, "fence(Ordering::SeqCst);", "fence", "fence")]),
    ("a definition's `fn`: a mark outside ASCII before the name", FILL, "fn \u{301}fence() {}\nfn extra() {\n    fence();\n}\n", &[(1, "fence()", "fence", "fence"), (3, "fence();", "fence", "fence")]),
    ("a definition's `fn`: a word character outside ASCII after it", FILL, "fn\u{b2} fence() {}\n", &[(1, "fence()", "fence", "fence")]),
    ("a hook's `S::`: a mark outside ASCII before it", GRACE, "trait Strength {\n    fn fence_pin() {}\n}\nfn pin<S: Strength>() {\n    \u{301}S::fence_pin();\n}\n", &[]),
    ("a hook's `S::`: a word character outside ASCII before it", GRACE, "trait Strength {\n    fn fence_pin() {}\n}\nfn pin<S: Strength>() {\n    \u{b2}S::fence_pin();\n}\n", &[(5, "\u{b2}S::fence_pin();", "fence", "fence")]),
    ("a hook's definition: a mark outside ASCII after `fn`", GRACE, "trait Strength {\n    fn\u{301} fence_pin() {}\n}\nfn pin<S: Strength>() {\n    S::fence_pin();\n}\n", &[(2, "fence_pin()", "fence", "fence"), (5, "S::fence_pin();", "fence", "fence")]),
    ("a hook's definition: a word character outside ASCII after the name", GRACE, "trait Strength {\n    fn fence_pin\u{b2}() {}\n}\nfn pin<S: Strength>() {\n    S::fence_pin();\n}\n", &[(5, "S::fence_pin();", "fence", "fence")]),
    ("a hook's definition: a mark outside ASCII after the name", GRACE, "trait Strength {\n    fn fence_pin\u{301}() {}\n}\nfn pin<S: Strength>() {\n    S::fence_pin();\n}\n", &[]),
    ("CONSTANT: a word character outside ASCII before it", GRACE, "impl Strength for Sequential {\n    \u{b2}const VISIT: Ordering = Ordering::SeqCst;\n}\nfn v<S: Strength>(r: &W) -> u64 {\n    r.load(S::VISIT)\n}\n", &[(2, "Ordering::SeqCst", "SeqCst", "unread")]),
    ("CONSTANT: a mark outside ASCII before it", GRACE, "impl Strength for Sequential {\n    \u{301}const VISIT: Ordering = Ordering::SeqCst;\n}\nfn v<S: Strength>(r: &W) -> u64 {\n    r.load(S::VISIT)\n}\n", &[(2, "Ordering::SeqCst", "SeqCst", "load")]),
    ("a constant's `S::NAME`: a word character outside ASCII before it", GRACE, "impl Strength for Sequential {\n    const VISIT: Ordering = Ordering::SeqCst;\n}\nfn v<S: Strength>(r: &W) -> u64 {\n    r.load(\u{b2}S::VISIT)\n}\n", &[(2, "Ordering::SeqCst", "SeqCst", "unread")]),
    ("a constant's `S::NAME`: a mark outside ASCII after it", GRACE, "impl Strength for Sequential {\n    const VISIT: Ordering = Ordering::SeqCst;\n}\nfn v<S: Strength>(r: &W) -> u64 {\n    r.load(S::VISIT\u{301})\n}\n", &[(2, "Ordering::SeqCst", "SeqCst", "load")]),
    ("the callee's last character: a rooted path at column 0 after a line that ends in a word character", FILL, "fn extra() {\n    x\n::std::sync::atomic::fence(Ordering::SeqCst);\n}\n", &[(2, "x\n::std::sync::atomic::fence(Ordering::SeqCst);", "fence", "fence")]),
    ("the callee's last character: a rooted path at column 0 after a line that ends in a mark outside ASCII", FILL, "fn extra() {\n    x\u{301}\n::std::sync::atomic::fence(Ordering::SeqCst);\n}\n", &[(3, "::std::sync::atomic::fence(Ordering::SeqCst);", "fence", "fence")]),
    ("the callee's last character: a rooted path at column 0 after a line that ends in `;`", FILL, "fn extra() {\n    x;\n::std::sync::atomic::fence(Ordering::SeqCst);\n}\n", &[(3, "::std::sync::atomic::fence(Ordering::SeqCst);", "fence", "fence")]),
    ("FENCE_PATH: a path that ends in `::` and a newline", FILL, "fn extra() {\n    W::<u8>::\nfence(Ordering::SeqCst);\n}\n", &[(2, "W::<u8>::\nfence(Ordering::SeqCst);", "fence", "fence")]),
    ("FENCE_PATH: a path that ends in a word and a newline", FILL, "fn extra() {\n    <W>::x\nfence(Ordering::SeqCst);\n}\n", &[(2, "W>::x\nfence(Ordering::SeqCst);", "fence", "fence")]),
    ("FENCE_PATH: a callee word on the line before the name", FILL, "fn extra() {\n    y; foo\nfence(Ordering::SeqCst);\n}\n", &[(3, "Ordering::SeqCst", "SeqCst", "unread")]),
    ("the callee's last character: a qualified path at column 0 after a line that ends in a word character", FILL, "fn extra<W: FillWord>() {\n    x\n<W>::acquire_fence();\n}\n", &[]),
    ("the callee's last character: a qualified path at column 0 after a line that ends in `;`", FILL, "fn extra<W: FillWord>() {\n    x;\n<W>::acquire_fence();\n}\n", &[(3, "<W>::acquire_fence();", "fence", "fence")]),
    ("a definition's `fn`: a word character outside ASCII before it", FILL, "\u{b2}fn fence() {}\n", &[(1, "fence()", "fence", "fence")]),
    ("call_op: an earlier operand that holds `>` alone", FILL, "pub(crate) fn peek(state: &AtomicU64) -> u64 {\n    s.compare_exchange(a > b, 1, Ordering::SeqCst, Ordering::Acquire)\n}\n", &[(2, "Ordering::SeqCst", "SeqCst", "unread"), (2, "Ordering::Acquire", "Acquire", "unread")]),
];

#[rustfmt::skip]
const DEFECT_ROWS: &[DefectRow] = &[
    ("a_hidden_spelling_of_an_ordering_is_refused", FILL, "use std::sync::atomic::Ordering::{Acquire};\n", &["crates/kestrike/src/storage/fill.rs:1: Acquire outside an Ordering:: path hides its site from the matcher"]),
    ("a_hidden_spelling_of_an_ordering_is_refused", FILL, "use std::sync::atomic::Ordering::*;\n", &["crates/kestrike/src/storage/fill.rs:1: Ordering::* hides the sites it names from the matcher"]),
    ("a_hidden_spelling_of_an_ordering_is_refused", FILL, "use std::sync::atomic::Ordering as O;\n", &["crates/kestrike/src/storage/fill.rs:1: Ordering as hides the sites it names from the matcher"]),
    ("a_hidden_spelling_of_an_ordering_is_refused", FILL, "type O = Ordering;\nfn peek(s: &AtomicU64) -> u64 { s.load(O::Acquire) }\n", &["crates/kestrike/src/storage/fill.rs:2: Acquire outside an Ordering:: path hides its site from the matcher"]),
    ("a_hidden_spelling_of_an_ordering_is_refused", FILL, "type O<'a> = Ordering;\nfn peek(s: &AtomicU64) -> u64 { s.load(O::SeqCst) }\n", &["crates/kestrike/src/storage/fill.rs:2: SeqCst outside an Ordering:: path hides its site from the matcher"]),
    ("a_hidden_spelling_of_an_ordering_is_refused", FILL, "fn peek(s: &AtomicU64) -> u64 { s.load(<Ordering>::Acquire) }\n", &["crates/kestrike/src/storage/fill.rs:1: Acquire outside an Ordering:: path hides its site from the matcher"]),
    ("a_hidden_spelling_of_an_ordering_is_refused", FILL, "fn peek(s: &AtomicU64) -> u64 { s.load(<std::sync::atomic::Ordering>::Acquire) }\n", &["crates/kestrike/src/storage/fill.rs:1: Acquire outside an Ordering:: path hides its site from the matcher"]),
    ("a_hidden_spelling_of_an_ordering_is_refused", FILL, "fn peek(s: &AtomicU64) -> u64 { s.load(Ordering::r#Acquire) }\n", &["crates/kestrike/src/storage/fill.rs:1: Acquire outside an Ordering:: path hides its site from the matcher"]),
    ("a_hidden_spelling_of_an_ordering_is_refused", FILL, "macro_rules! o { ($t:ident) => { $t::SeqCst }; }\n", &["crates/kestrike/src/storage/fill.rs:1: SeqCst outside an Ordering:: path hides its site from the matcher"]),
    ("a_hidden_spelling_of_an_ordering_is_refused", FILL, "fn peek<W: FillWord>() { let f = W::acquire_fence; f(); }\n", &["crates/kestrike/src/storage/fill.rs:1: a fence path named outside a call hides the sites it names from the matcher"]),
    ("a_hidden_spelling_of_an_ordering_is_refused", FILL, "fn peek<W: FillWord>() { (W::acquire_fence)(); }\n", &["crates/kestrike/src/storage/fill.rs:1: a fence path named outside a call hides the sites it names from the matcher"]),
    ("a_hidden_spelling_of_an_ordering_is_refused", FILL, "fn peek() { std::convert::identity(std::sync::atomic::fence); }\n", &["crates/kestrike/src/storage/fill.rs:1: a fence path named outside a call hides the sites it names from the matcher"]),
    ("a_hidden_spelling_of_an_ordering_is_refused", FILL, "fn peek(order: Ordering) { apply(order, std::sync::atomic::fence); }\n", &["crates/kestrike/src/storage/fill.rs:1: a fence path named outside a call hides the sites it names from the matcher"]),
    ("a_hidden_spelling_of_an_ordering_is_refused", FILL, "fn peek(word: &W) { word.acquire_fence(); }\n", &["crates/kestrike/src/storage/fill.rs:1: a fence called as a method hides the sites it names from the matcher"]),
    ("a_hidden_spelling_of_an_ordering_is_refused", FILL, "fn peek() { $crate::x::settle_fence(); }\n", &["crates/kestrike/src/storage/fill.rs:1: a fence callee the matcher cannot delimit hides the sites it names from the matcher"]),
    ("a_hidden_spelling_of_an_ordering_is_refused", FILL, "fn peek<W>() { <W as Foo<Bar<Baz>>>::acquire_fence(); }\n", &["crates/kestrike/src/storage/fill.rs:1: a fence callee the matcher cannot delimit hides the sites it names from the matcher"]),
    ("an_ordering_type_in_a_type_position_is_no_spelling", FILL, "fn pick(_: Option<Ordering>) -> Option<Ordering> {\n    None\n}\n", &[]),
    ("a_forwarder_that_passes_another_fence_is_refused", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, settle);\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! holds a $fence call, and 0 of its 1 production invocations pass std::sync::atomic::fence"]),
    ("a_forwarder_that_passes_another_fence_is_refused", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nimpl FillWord for std::sync::atomic::AtomicU64 {\n    fn acquire_fence() {}\n}\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! holds a $fence call, and 0 of its 0 production invocations pass std::sync::atomic::fence"]),
    ("a_forwarder_that_passes_another_fence_is_refused", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, settle);\nstringify!(u8, std::sync::atomic::fence);\n", &["crates/kestrike/src/storage/fill.rs: stringify! receives std::sync::atomic::fence and holds no $fence call", "crates/kestrike/src/storage/fill.rs: forward_fill_word! holds a $fence call, and 0 of its 1 production invocations pass std::sync::atomic::fence"]),
    ("a_forwarder_that_passes_another_fence_is_refused", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\nfn stray() {\n    $fence(Ordering::Acquire);\n}\n", &["crates/kestrike/src/storage/fill.rs: line 13: a $fence call lies in no macro_rules! body"]),
    ("a_forwarder_that_passes_another_fence_is_refused", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\nforward_fill_word![std::sync::atomic::AtomicU32, settle];\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! holds a $fence call, and 1 of its 2 production invocations pass std::sync::atomic::fence"]),
    ("a_forwarder_that_passes_another_fence_is_refused", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\nforward_fill_word! {std::sync::atomic::AtomicU32, settle}\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! holds a $fence call, and 1 of its 2 production invocations pass std::sync::atomic::fence"]),
    ("a_forwarder_that_passes_another_fence_is_refused", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\nforward_fill_word ! (std::sync::atomic::AtomicU32, settle);\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! holds a $fence call, and 1 of its 2 production invocations pass std::sync::atomic::fence"]),
    ("a_forwarder_that_passes_another_fence_is_refused", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nimpl FillWord for std::sync::atomic::AtomicU64 {\n    fn acquire_fence() {}\n}\nmacro_rules! spare {\n    (unused) => {\n        forward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n    };\n    () => {};\n}\nspare!();\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! is invoked among another macro's tokens, which the matcher cannot expand", "crates/kestrike/src/storage/fill.rs: forward_fill_word! is not one arm ($name:ty, $fence:path) => {..} that its production invocations directly follow"]),
    ("a_forwarder_that_passes_another_fence_is_refused", FILL, "impl FillWord for std::sync::atomic::AtomicU64 {\n    fn acquire_fence() {}\n}\nmacro_rules! spare {\n    (unused) => {\nmacro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n    };\n    () => {};\n}\nspare!();\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! receives std::sync::atomic::fence and holds no $fence call", "crates/kestrike/src/storage/fill.rs: spare! holds a $fence call, and 0 of its 1 production invocations pass std::sync::atomic::fence", "crates/kestrike/src/storage/fill.rs: spare! is not one arm ($name:ty, $fence:path) => {..} that its production invocations directly follow"]),
    ("a_forwarder_that_passes_another_fence_is_refused", FILL, "impl FillWord for std::sync::atomic::AtomicU64 {\n    fn acquire_fence() {}\n}\nmacro_rules! r#spare {\n    (unused) => {\nmacro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n    };\n    () => {};\n}\nspare!();\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! receives std::sync::atomic::fence and holds no $fence call", "crates/kestrike/src/storage/fill.rs: spare! holds a $fence call, and 0 of its 1 production invocations pass std::sync::atomic::fence", "crates/kestrike/src/storage/fill.rs: spare! is not one arm ($name:ty, $fence:path) => {..} that its production invocations directly follow"]),
    ("a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused", FILL, "macro_rules! forward_fill_word {\n    ($fence:path, $_unused:path) => {\n        impl FillWord for std::sync::atomic::AtomicU64 {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nfn noop<T>(_: T) {}\nforward_fill_word!(noop, std::sync::atomic::fence);\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! is not one arm ($name:ty, $fence:path) => {..} that its production invocations directly follow"]),
    ("a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n        }\n    };\n    (unused, $fence:path) => {\n        fn acquire_fence() {\n            $fence(Ordering::Acquire);\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! is not one arm ($name:ty, $fence:path) => {..} that its production invocations directly follow"]),
    ("a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $($rest:tt)*) => {};\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! is not one arm ($name:ty, $fence:path) => {..} that its production invocations directly follow"]),
    ("a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused", FILL, "macro_rules! forward_fill_word {\n    (std::sync::atomic::AtomicU64, $other:path) => {};\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! is not one arm ($name:ty, $fence:path) => {..} that its production invocations directly follow"]),
    ("a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n    () => {};\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! is not one arm ($name:ty, $fence:path) => {..} that its production invocations directly follow"]),
    ("a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path, $spare:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! is not one arm ($name:ty, $fence:path) => {..} that its production invocations directly follow"]),
    ("a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nmacro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl Spare for $atomic {}\n    };\n}\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! is not one arm ($name:ty, $fence:path) => {..} that its production invocations directly follow"]),
    ("a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nmacro_rules ! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl Spare for $atomic {}\n    };\n}\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! is not one arm ($name:ty, $fence:path) => {..} that its production invocations directly follow"]),
    ("a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nmacro_rules! forward_fill_word (\n    ($atomic:ty, $fence:path) => {\n        impl Spare for $atomic {}\n    };\n);\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! is not one arm ($name:ty, $fence:path) => {..} that its production invocations directly follow"]),
    ("a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nmacro_rules! r#forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl Spare for $atomic {}\n    };\n}\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! is not one arm ($name:ty, $fence:path) => {..} that its production invocations directly follow"]),
    ("a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused", FILL, "forward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n\nmacro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! is not one arm ($name:ty, $fence:path) => {..} that its production invocations directly follow"]),
    ("a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused", FILL, "mod forwarders {\nmacro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! is not one arm ($name:ty, $fence:path) => {..} that its production invocations directly follow"]),
    ("a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforwarders::forward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! is not one arm ($name:ty, $fence:path) => {..} that its production invocations directly follow"]),
    ("a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nconst SPARE: u8 = 0;\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! is not one arm ($name:ty, $fence:path) => {..} that its production invocations directly follow"]),
    ("a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n", &[]),
    ("a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused", FILL, "macro_rules! forward_fill_word {\n    ($word:ty, $fence:path) => {\n        impl FillWord for $word {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n", &[]),
    ("a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    }\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n", &[]),
    ("a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused", FILL, "macro_rules! forward_fill_word {\n    // The arm.\n    (\n        $atomic:ty,\n        $fence:path\n    ) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n", &[]),
    ("a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n// Another word.\nforward_fill_word!(std::sync::atomic::AtomicUsize, std::sync::atomic::fence);\n", &[]),
    ("a_test_only_element_the_matcher_cuts_is_refused", FILL, "fn extra(n: u8) -> u8 {\n    match n {\n        2 | 3 => 2,\n        #[cfg(test)]\n        0 | 1 => 1,\n        _ => 0,\n    }\n}\n", &["crates/kestrike/src/storage/fill.rs:4: a test-only element whose end the matcher reads more than one way; parenthesize its `<`, `>` or `|`, or move it into a test-only block or module"]),
    ("a_test_only_element_the_matcher_cuts_is_refused", GRACE, "pub(crate) fn unpin<W: EraWord>(record: &W) {\n    #[cfg(test)]\n    pick::<u8, u8>({ record.store(INACTIVE, Ordering::Release); 1 });\n    record.store(INACTIVE, Ordering::Relaxed);\n}\n", &["crates/kestrike/src/storage/grace.rs:2: a test-only element whose end the matcher reads more than one way; parenthesize its `<`, `>` or `|`, or move it into a test-only block or module"]),
    ("a_test_only_element_the_matcher_cuts_is_refused", GRACE, "pub(crate) fn unpin<W: EraWord>(record: &W) {\n    #[cfg(test)]\n    hook = |a, b| { record.store(INACTIVE, Ordering::Release); };\n    record.store(INACTIVE, Ordering::Relaxed);\n}\n", &["crates/kestrike/src/storage/grace.rs:2: a test-only element whose end the matcher reads more than one way; parenthesize its `<`, `>` or `|`, or move it into a test-only block or module"]),
    ("a_test_only_element_the_matcher_cuts_is_refused", GRACE, "pub(crate) fn unpin<W: EraWord>(record: &W) {\n    struct _S(#[cfg(test)] fn() -> W<u8, { record.store(INACTIVE, Ordering::Release); 1 }>, u8);\n    record.store(INACTIVE, Ordering::Relaxed);\n}\n", &["crates/kestrike/src/storage/grace.rs:2: a test-only element whose end the matcher reads more than one way; parenthesize its `<`, `>` or `|`, or move it into a test-only block or module"]),
    ("a_test_only_element_the_matcher_cuts_is_refused", FILL, "pub(crate) fn observe<W: FillWord>(state: &W, next_serial: u64) -> Result<Record, Malformed> {\n    match next_serial {\n        #[cfg(test)]\n        0 => pick::<u8, u8>(decode(state.load(Ordering::Acquire), next_serial)),\n        _ => decode(state.load(Ordering::Relaxed), next_serial),\n    }\n}\n", &["crates/kestrike/src/storage/fill.rs:3: a test-only element whose end the matcher reads more than one way; parenthesize its `<`, `>` or `|`, or move it into a test-only block or module"]),
    ("a_test_only_element_the_matcher_cuts_is_refused", FILL, "with_probe!(; #[cfg(test)] B> fn extra(state: &AtomicU64) { state.load(Ordering::Relaxed); });\n", &["crates/kestrike/src/storage/fill.rs:1: a test-only element whose end the matcher reads more than one way; parenthesize its `<`, `>` or `|`, or move it into a test-only block or module"]),
    ("a_test_only_element_the_matcher_cuts_is_refused", FILL, "fn extra<A, #[cfg(test)] B>(a: A) -> A {\n    a\n}\n", &["crates/kestrike/src/storage/fill.rs:1: a test-only element whose end the matcher reads more than one way; parenthesize its `<`, `>` or `|`, or move it into a test-only block or module"]),
    ("a_test_only_element_the_matcher_cuts_is_refused", FILL, "fn extra() {\n    #[cfg(test)]\n    let sum = |a, b| a + b;\n}\n", &["crates/kestrike/src/storage/fill.rs:2: a test-only element whose end the matcher reads more than one way; parenthesize its `<`, `>` or `|`, or move it into a test-only block or module"]),
    ("a_test_only_element_the_matcher_cuts_is_refused", GRACE, "pub(crate) fn unpin<W: EraWord>(record: &W) {\n    let _ = (a | b, #[cfg(test)] if pick::<u8, u8>() { record.store(INACTIVE, Ordering::Release); 1 } else { 2 });\n    record.store(INACTIVE, Ordering::Relaxed);\n}\n", &["crates/kestrike/src/storage/grace.rs:2: a test-only element whose end the matcher reads more than one way; parenthesize its `<`, `>` or `|`, or move it into a test-only block or module"]),
    ("a_test_only_element_the_matcher_cuts_is_refused", FILL, "fn extra(n: u8) -> u8 {\n    match n {\n        #[cfg(test)]\n        0 | 1 => 1,\n        _ => 0,\n    }\n}\n", &[]),
    ("a_test_only_element_the_matcher_cuts_is_refused", FILL, "#[cfg(test)]\nmod probes {\n    #[cfg(all(test, loom))]\n    const ROOM: usize = 1 << 12;\n}\n", &[]),
    ("a_test_only_element_the_matcher_cuts_is_refused", FILL, "#[cfg(test)]\nextern \"C\" fn probe<A, B>() {}\n", &[]),
    ("a_test_only_element_the_matcher_cuts_is_refused", FILL, "#[cfg(test)]\nextern fn probe<A, B>() {}\n", &[]),
    ("SPELLING: a word character outside ASCII before it", FILL, "use std::sync::atomic::\u{b2}Ordering::*;\n", &[]),
    ("SPELLING: a mark outside ASCII after `as`", FILL, "use std::sync::atomic::Ordering as\u{301} O;\n", &["crates/kestrike/src/storage/fill.rs:1: Ordering as hides the sites it names from the matcher"]),
    ("SPELLING: a word character outside ASCII after `as`", FILL, "use std::sync::atomic::Ordering as\u{b2} O;\n", &[]),
    ("VARIANT: a mark outside ASCII after it", FILL, "fn peek() { Acquire\u{301} }\n", &["crates/kestrike/src/storage/fill.rs:1: Acquire outside an Ordering:: path hides its site from the matcher"]),
    ("VARIANT: a word character outside ASCII before it", FILL, "fn peek() { \u{b2}Acquire }\n", &[]),
    ("FORWARDER and an invocation: a mark outside ASCII before the name", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\n\u{301}forward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! is not one arm ($name:ty, $fence:path) => {..} that its production invocations directly follow"]),
    ("FORWARDER and an invocation: a word character outside ASCII before the name", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\n\u{b2}forward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n", &["crates/kestrike/src/storage/fill.rs: \u{b2}forward_fill_word! receives std::sync::atomic::fence and holds no $fence call", "crates/kestrike/src/storage/fill.rs: forward_fill_word! holds a $fence call, and 0 of its 0 production invocations pass std::sync::atomic::fence"]),
    ("a macro_rules! definition: a word character outside ASCII before it", FILL, "\u{b2}macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n", &["crates/kestrike/src/storage/fill.rs: line 5: a $fence call lies in no macro_rules! body", "crates/kestrike/src/storage/fill.rs: forward_fill_word! receives std::sync::atomic::fence and holds no $fence call"]),
    ("a macro_rules! definition: a mark outside ASCII before it", FILL, "\u{301}macro_rules!forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n", &[]),
    ("a macro_rules! definition: a mark outside ASCII after a word before it", FILL, "x\u{301}macro_rules!forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n", &[]),
    ("MACRO: a word character outside ASCII before the bang", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\nspare\u{b2}!(forward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence););\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! is invoked among another macro's tokens, which the matcher cannot expand", "crates/kestrike/src/storage/fill.rs: forward_fill_word! is not one arm ($name:ty, $fence:path) => {..} that its production invocations directly follow"]),
    ("MACRO: a mark outside ASCII before the bang", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\nspare\u{301}!(forward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence););\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! is not one arm ($name:ty, $fence:path) => {..} that its production invocations directly follow"]),
    ("MACRO: a word character outside ASCII before `macro_rules`", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n\u{b2}macro_rules! spare { forward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence); }\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! is not one arm ($name:ty, $fence:path) => {..} that its production invocations directly follow"]),
    ("MACRO: a mark outside ASCII before `macro_rules`", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n\u{301}macro_rules! spare { forward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence); }\n", &["crates/kestrike/src/storage/fill.rs: forward_fill_word! is invoked among another macro's tokens, which the matcher cannot expand", "crates/kestrike/src/storage/fill.rs: forward_fill_word! is not one arm ($name:ty, $fence:path) => {..} that its production invocations directly follow"]),
    ("SPELLING: a comment with a character outside ASCII inside the match", FILL, "use std::sync::atomic::Ordering/*\u{e9}*/::*;\n", &["crates/kestrike/src/storage/fill.rs:1: Ordering     ::* hides the sites it names from the matcher"]),
    ("the callee's last character: `:`", FILL, "fn f() {\n    a:fence();\n}\n", &["crates/kestrike/src/storage/fill.rs:2: a fence callee the matcher cannot delimit hides the sites it names from the matcher"]),
    ("a forwarder invocation without its `;`", FILL, "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence)\n", &["crates/kestrike/src/storage/fill.rs:11: a fence path named outside a call hides the sites it names from the matcher", "crates/kestrike/src/storage/fill.rs: forward_fill_word! holds a $fence call, and 0 of its 1 production invocations pass std::sync::atomic::fence"]),
    ("a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused", SEQUENCE, "macro_rules! forward_seq_word {\n    () => {};\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n        }\n    };\n}\n\nforward_seq_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);\n", &["crates/kestrike/src/index/sequence.rs: forward_seq_word! is not one arm ($name:ty, $fence:path) => {..} that its production invocations directly follow"]),
];

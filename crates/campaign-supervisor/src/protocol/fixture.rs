//! Protocol test fixtures in the worker's output format, and edits that
//! remove or repeat one key's lines.

/// The listing the summary fixtures' profile names resolve against.
pub(super) const LISTING: &str = include_str!("../../testdata/listing.txt");

pub(super) const DIGEST: &str = "f524dec13f9c0f31be2de651057fad6650d068a55d69e55f62e58b6df1875dfa";

/// A counting upload bundle's summary: only the lines every summary prints.
pub(super) const COUNTING: &str = include_str!("../../testdata/counting.summary");

/// A failure identity: 44 bytes in lowercase hex.
pub(super) const IDENTITY: &str =
    "02010100013600d35fb575692400011c76eac6af6124d90dd88d5e2fe40fbc708a84e3c4d019120000000000";

pub(super) const BRANCH: &str = "\
milestone: pending-put boundary=13 semantic=501 decisions=100 prefix=555e9c97b2d92ca9344c62a0cb7c4bff998fab8475240f0a75890472bd30e8c8
witness: pending-put holds=true boundary=13 upload=attempt:1,grant:3,held:2,outcome:0 armed=false
parent: reproduced
child: suffix=0 sibling=0 class=success digest=1f27fb908bebec8fe9cd01041d338f6565bef18f41ee2d4567bb73df1dfa035c terminal=complete pass fired=03 required=03
child: suffix=0 sibling=1 class=success digest=1f27fb908bebec8fe9cd01041d338f6565bef18f41ee2d4567bb73df1dfa035c terminal=complete pass fired=03 required=03
branch: 2 children, 2 credited, 0 problems
";

pub(super) const EXPLORE: &str = "\
label: composed-bounded
milestone: pending-put boundary=13 semantic=501 decisions=100 prefix=555e9c97b2d92ca9344c62a0cb7c4bff998fab8475240f0a75890472bd30e8c8
witness: pending-put holds=true boundary=13 upload=attempt:1,grant:3,held:2,outcome:0 armed=false
limits: depth=2 children=3 faults=12 advances=16
parent: reproduced
node: path=0 class=success wall_us=11373 cpu_us=10148 max_rss_kib=21332
node: path=0.0 class=success wall_us=3650 cpu_us=3672 max_rss_kib=21400
leaf: path=0.0 digest=31f1b1c901ee0a3672fc8538d1358a95f6fceebf11014b6fe861fd97d2b3441f unexplored=4 counts=true verdict=complete pass fired=03 required=03
frontier: nodes=2 credited=2 explored=1 failing=0 unexplored=4
explore: composed-bounded, 0 problems
";

pub(super) const SESSION: &str = "\
session: 3 windows, chain e1bc09f574b9f7060a1ccf70b20f88b4afcec88c2e9f678edfe55893c5ca870b
end: stop=goal terminal=complete pass fired=03 required=03 counts=true turns=1113 virtual_us=5700 skipped_us=5100 rested_us=300 apply_ms=000000000004 failure=None carried=12 registry=5 outstanding=6 kept=7 window_bytes=256512
";

/// `text` with every line of `key` removed.
pub(super) fn without(text: &str, key: &str) -> String {
    let prefix = format!("{key}: ");
    text.lines()
        .filter(|line| !line.starts_with(&prefix))
        .map(|line| format!("{line}\n"))
        .collect()
}

/// `text` with the first line of `key` printed twice.
pub(super) fn twice(text: &str, key: &str) -> String {
    let prefix = format!("{key}: ");
    let line = text
        .lines()
        .find(|line| line.starts_with(&prefix))
        .expect("the fixture prints the key");
    text.replacen(&format!("{line}\n"), &format!("{line}\n{line}\n"), 1)
}

/// `text` with its first `from` replaced by `to`; `text` must hold `from`.
pub(super) fn edited(text: &str, from: &str, to: &str) -> String {
    assert!(text.contains(from), "the fixture holds {from:?}");
    text.replacen(from, to, 1)
}

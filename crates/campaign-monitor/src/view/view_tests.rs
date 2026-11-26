//! Rendering tests: every view draws at the minimum size, a table keeps its
//! selected row on screen and names the rows it shows, detail panes count
//! what they cannot show, copy-paste commands quote snapshot text, and the
//! header's age and staleness follow the poll schedule.

use std::time::Duration;

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use serde_json::{Value, json};

use super::*;
use crate::poll::Fetch;
use crate::state::JobFilter;
use crate::state::tests::{Monitor, parsed};
use crate::tui::theme::{ColorDepth, Glyphs};
use ratatui::style::Modifier;

fn job(n: usize, profile: &str, class: &str) -> Value {
    json!({"id": format!("{n:064x}"), "profile": profile, "campaign": "c", "run": n,
           "variant": "v1", "state": "settled", "attempts_allowed": 3,
           "result": {"attempt": 1, "class": class},
           "attempts": [{"number": 1, "attempt": format!("{n:064x}-0001"), "intent_ms": 1,
                         "finished_ms": 9, "finished": {"class": class, "binding": "matching"},
                         "sim": {"cause": "violation, violating Progress"}}]})
}

fn app(jobs: Vec<Value>, extra: Value) -> Monitor {
    let mut snapshot = json!({
        "format": 1, "observed_ms": 5_000_000, "state": "/state",
        "config": {"verified": {"config": {"wall": 1800, "slots": 1}}},
        "variants": {"v1": {"turns": 20000}},
        "jobs": jobs,
    });
    for (key, value) in extra.as_object().unwrap() {
        snapshot[key] = value.clone();
    }
    let mut app = Monitor::new();
    app.feed(parsed(snapshot), Duration::from_millis(3));
    app
}

fn theme() -> Theme {
    Theme::resolve(ColorDepth::Ansi16, Glyphs::Unicode)
}

fn screen(app: &App, width: u16, height: u16) -> String {
    let theme = theme();
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    let keymap = Keymap::default_map();
    terminal
        .draw(|frame| draw(frame, app, &theme, &keymap))
        .unwrap();
    let buffer = terminal.backend().buffer();
    (0..height)
        .map(|y| {
            (0..width)
                .map(|x| buffer[(x, y)].symbol())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn findings() -> Value {
    json!({
        "findings": [{"id": "a-0001", "blocker": true,
                      "verified": {"admission": {"job": {"experiment": {"profile": "get", "run": 0}}}},
                      "triage": {"latest": {"status": "reproduced"}}}],
        "release_blockers": ["a-0001"],
        "failure_groups": [{"kind": "violation", "identity": "02aa",
                            "cause": "violation, violating Progress",
                            "findings": ["a-0001"], "profiles": ["get"], "runs": [0],
                            "unresolved": 1}],
    })
}

#[test]
fn every_tab_renders_at_every_supported_size_and_names_its_content() {
    let mut app = app(
        vec![
            job(0, "get", "violation"),
            json!({"id": "bad", "held": "job binding differs"}),
        ],
        findings(),
    );
    for (tab, expected) in [
        (Tab::Overview, "1 held"),
        (Tab::Signals, "violating Progress"),
        (Tab::Profiles, "get"),
        (Tab::Jobs, "violation"),
        (Tab::Findings, "<text>"),
    ] {
        app.tab = tab;
        let shown = screen(&app, MIN_WIDTH, MIN_HEIGHT);
        assert!(!shown.contains("enlarge the terminal"), "{tab:?}: {shown}");
        assert!(
            shown.contains(expected),
            "{tab:?} at the minimum lacks {expected:?}: {shown}"
        );
        for (width, height) in [(MIN_WIDTH - 1, MIN_HEIGHT), (MIN_WIDTH, MIN_HEIGHT - 1)] {
            let shown = screen(&app, width, height);
            assert!(
                shown.contains("enlarge the terminal"),
                "{width}x{height}: {shown}"
            );
        }
    }
    for (width, height) in [(80, 24), (120, 40), (200, 55)] {
        for (tab, expected) in [
            (Tab::Overview, "release blockers"),
            (Tab::Signals, "violating Progress"),
            (Tab::Profiles, "get"),
            (Tab::Jobs, "violation"),
            (Tab::Findings, "<id> = a-0001"),
        ] {
            app.tab = tab;
            let shown = screen(&app, width, height);
            assert!(
                shown.contains(expected),
                "{tab:?} at {width}x{height} lacks {expected:?}"
            );
        }
    }
}

#[test]
fn a_terminal_below_the_minimum_size_shows_the_signal_counts_and_the_minimum() {
    let mut app = app(
        vec![
            job(0, "get", "violation"),
            job(1, "put", "unsuccessful"),
            job(2, "del", "engine-failure"),
        ],
        findings(),
    );
    let critical = app
        .signals()
        .iter()
        .filter(|s| s.severity == Severity::Critical)
        .count();
    let warning = app
        .signals()
        .iter()
        .filter(|s| s.severity == Severity::Warning)
        .count();
    assert!(critical > 0 && warning > 0 && critical != warning);
    let shown = screen(&app, 40, 12);
    assert!(
        shown.contains(&format!("!! {critical} critical · ! {warning} warning")),
        "{shown}"
    );
    assert!(shown.contains("enlarge the terminal to 60x16"), "{shown}");
    assert!(shown.contains("q quits"), "{shown}");
    app.help = true;
    assert!(screen(&app, 40, 12).contains("ctrl-c quits"));
}

#[test]
fn the_overview_at_the_minimum_size_lists_signal_rows() {
    let app = app(vec![job(0, "get", "violation")], findings());
    let shown = screen(&app, MIN_WIDTH, MIN_HEIGHT);
    assert!(shown.contains(&app.signals()[0].title[..20]), "{shown}");
}

#[test]
fn outcomes_that_do_not_fit_are_counted_in_a_more_row() {
    let classes = [
        "violation",
        "unsuccessful",
        "engine-failure",
        "signal",
        "incomplete",
        "disagreement",
        "rejected",
        "oom",
        "watchdog",
        "interrupted",
    ];
    let jobs = classes
        .iter()
        .enumerate()
        .flat_map(|(n, class)| [job(2 * n, "p", class), job(2 * n + 1, "p", class)])
        .collect();
    let app = app(jobs, json!({}));
    let shown = screen(&app, 80, 24);
    let more = shown
        .lines()
        .find(|line| line.contains("more outcomes"))
        .unwrap();
    assert!(more.contains("     16  in 8 more outcomes"), "{more}");
    assert!(more.contains("+3 more"), "{more}");
    assert!(shown.contains("settled by outcome (10)"), "{shown}");
}

#[test]
fn the_selected_job_stays_visible_in_a_list_longer_than_the_screen() {
    let jobs = (0..500)
        .map(|n| job(n, &format!("profile-{n:03}"), "violation"))
        .collect();
    let mut app = app(jobs, json!({}));
    app.tab = Tab::Jobs;
    app.selections[Tab::Jobs.index()] = 499;
    let shown = screen(&app, 120, 40);
    let table = above(&shown, " job · paths under");
    assert!(table.contains("profile-499"), "{table}");
    assert!(!table.contains("profile-000"), "{table}");
    assert!(table.contains("rows 484-500 of 500"), "{table}");
    app.selections[Tab::Jobs.index()] = 0;
    let table = above(&screen(&app, 80, 24), " job · paths under").to_owned();
    assert!(table.contains("profile-000"), "{table}");
    assert!(table.contains("rows 1-"), "{table}");
}

/// The screen text above the first line containing `marker`, which must be
/// on screen.
fn above<'a>(shown: &'a str, marker: &str) -> &'a str {
    let end = shown
        .find(marker)
        .unwrap_or_else(|| panic!("no {marker:?} on screen: {shown}"));
    &shown[..end]
}

#[test]
fn the_selected_row_stays_visible_in_long_profile_and_finding_lists() {
    let jobs = (0..300)
        .map(|n| job(n, &format!("profile-{n:03}"), "pass"))
        .collect();
    let mut app = app(jobs, json!({}));
    app.tab = Tab::Profiles;
    app.selections[Tab::Profiles.index()] = 299;
    let table = above(&screen(&app, 120, 40), " workload ").to_owned();
    assert!(table.contains("profile-299"), "{table}");
    assert!(!table.contains("profile-000"), "{table}");
    let groups: Vec<Value> = (0..60)
        .map(|n| {
            json!({"kind": "violation", "identity": format!("id{n:02}"),
                        "cause": format!("cause-{n:02}"), "findings": [], "profiles": ["get"],
                        "runs": [0], "unresolved": 0})
        })
        .collect();
    let mut app = self::app(
        vec![job(0, "get", "pass")],
        json!({"failure_groups": groups}),
    );
    app.tab = Tab::Findings;
    app.selections[Tab::Findings.index()] = 59;
    let table = above(&screen(&app, 120, 40), " group · paths under").to_owned();
    assert!(table.contains("cause-59"), "{table}");
    assert!(!table.contains("cause-00"), "{table}");
    assert!(table.contains("of 60"), "{table}");
}

#[test]
fn a_held_job_shows_only_its_identity_and_reason() {
    let mut app = app(
        vec![json!({"id": "bad", "held": "job binding differs"})],
        json!({}),
    );
    app.tab = Tab::Jobs;
    let shown = screen(&app, 120, 40);
    assert!(shown.contains("held: job binding differs"), "{shown}");
    assert!(!shown.contains("seed 0"), "{shown}");
    let row = shown.lines().find(|line| line.contains("job bad")).unwrap();
    assert!(!row.contains("/0"), "{row}");
    assert!(row.contains(" - "), "{row}");
}

#[test]
fn the_profile_header_labels_each_tenth_run_with_its_tens_digit() {
    let jobs = (8..23).map(|n| job(n, "get", "pass")).collect();
    let mut app = app(jobs, json!({}));
    app.tab = Tab::Profiles;
    let shown = screen(&app, 120, 30);
    let header = shown.lines().find(|line| line.contains("profile")).unwrap();
    let tens = shown
        .lines()
        .nth(shown.lines().position(|line| line == header).unwrap() - 1);
    assert!(header.contains("8 9 0 1 2 3 4 5 6 7 8 9 0 1 2"), "{header}");
    assert!(
        tens.unwrap().contains("0   1                   2"),
        "{tens:?}"
    );
}

#[test]
fn help_lists_every_key_and_the_glyph_legend() {
    let mut app = app(vec![job(0, "get", "pass")], json!({}));
    app.tab = Tab::Profiles;
    app.help = true;
    let shown = screen(&app, 120, 40);
    for expected in [
        "^d/^u",
        "gg",
        "G",
        "H/M/L",
        "zz",
        "zt",
        "zb",
        "n/N",
        "^o",
        "h/l/←/→",
        "? or esc closes",
        "k killed",
    ] {
        assert!(shown.contains(expected), "help lacks {expected:?}");
    }
}

#[test]
fn the_profile_fail_column_counts_failures_outside_the_run_window() {
    let mut jobs: Vec<Value> = (0..200).map(|n| job(n, "get", "pass")).collect();
    jobs[3] = job(3, "get", "violation");
    let mut app = app(jobs, json!({}));
    app.tab = Tab::Profiles;
    let shown = screen(&app, 80, 24);
    let row = shown.lines().find(|line| line.contains("get ")).unwrap();
    assert!(row.contains("   1"), "{row}");
    assert!(!row.contains('✗'), "run 3 lies outside the window: {row}");
    assert!(shown.contains("with service failures"), "{shown}");
}

#[test]
fn runs_past_ninety_nine_add_a_hundreds_header_line() {
    let jobs = (95..105).map(|n| job(n, "get", "pass")).collect();
    let mut app = app(jobs, json!({}));
    app.tab = Tab::Profiles;
    let shown = screen(&app, 120, 30);
    let lines: Vec<&str> = shown.lines().collect();
    let header = lines
        .iter()
        .position(|line| line.contains("profile"))
        .unwrap();
    assert!(
        lines[header].contains("5 6 7 8 9 0 1 2 3 4"),
        "{}",
        lines[header]
    );
    assert!(
        lines[header - 2].contains("0         1"),
        "{}",
        lines[header - 2]
    );
}

#[test]
fn sparse_run_headers_mark_every_tens_change_and_runs_past_999_get_a_thousands_line() {
    let jobs = [8, 19, 21, 35]
        .iter()
        .map(|n| job(*n, "get", "pass"))
        .collect();
    let mut app = app(jobs, json!({}));
    app.tab = Tab::Profiles;
    let shown = screen(&app, 120, 30);
    let lines: Vec<&str> = shown.lines().collect();
    let header = lines
        .iter()
        .position(|line| line.contains("profile"))
        .unwrap();
    assert!(lines[header].contains("8 9 1 5"), "{}", lines[header]);
    assert!(
        lines[header - 1].contains("0 1 2 3"),
        "{}",
        lines[header - 1]
    );
    let jobs = [998, 999, 1000, 1204]
        .iter()
        .map(|n| job(*n, "get", "pass"))
        .collect();
    let mut app = self::app(jobs, json!({}));
    app.tab = Tab::Profiles;
    let shown = screen(&app, 120, 30);
    let lines: Vec<&str> = shown.lines().collect();
    let header = lines
        .iter()
        .position(|line| line.contains("profile"))
        .unwrap();
    assert!(lines[header].contains("8 9 0 4"), "{}", lines[header]);
    assert!(
        lines[header - 1].contains("9   0 0"),
        "{}",
        lines[header - 1]
    );
    assert!(
        lines[header - 2].contains("9   0 2"),
        "{}",
        lines[header - 2]
    );
    assert!(lines[header - 3].contains("0   1"), "{}", lines[header - 3]);
}

#[test]
fn multibyte_variant_id_and_identity_text_is_cut_on_character_boundaries() {
    let mut row = job(0, "get", "violation");
    row["variant"] = json!("ééééééééé");
    row["id"] = json!("ééééééééééééé");
    let mut app = app(
        vec![row],
        json!({"failure_groups": [{"kind": "violation", "identity": "éééééééééééééééé",
                                   "findings": [], "profiles": ["get"], "runs": [0],
                                   "unresolved": 1}]}),
    );
    for tab in [Tab::Profiles, Tab::Jobs, Tab::Findings] {
        app.tab = tab;
        screen(&app, 200, 55);
    }
    let mut row = job(0, "get", "violation");
    row["variant"] = json!(format!("a{}", "é".repeat(8)));
    row["id"] = json!(format!("a{}", "é".repeat(12)));
    let identity = format!("a{}", "é".repeat(24));
    let mut app = self::app(
        vec![row],
        json!({"failure_groups": [{"kind": "violation", "identity": identity,
                                   "findings": [], "profiles": ["get"], "runs": [0],
                                   "unresolved": 1}]}),
    );
    app.filter = JobFilter::All;
    let shown = app.shown();
    app.feed(shown, Duration::ZERO);
    for (tab, expected) in [
        (Tab::Profiles, format!("a{}", "é".repeat(7))),
        (Tab::Jobs, format!("a{}", "é".repeat(11))),
        (Tab::Findings, format!("a{}", "é".repeat(15))),
    ] {
        app.tab = tab;
        let shown = screen(&app, 200, 55);
        assert!(shown.contains(&expected), "{tab:?}: {shown}");
    }
}

#[test]
fn a_finding_id_in_the_commands_is_quoted_as_one_shell_word() {
    let mut extra = findings();
    extra["findings"][0]["id"] = json!("$(touch x)");
    extra["failure_groups"][0]["findings"] = json!(["$(touch x)"]);
    let mut app = app(vec![job(0, "get", "violation")], extra);
    app.tab = Tab::Findings;
    let shown = screen(&app, 200, 55);
    assert!(shown.contains("--from-run '$(touch x)'"), "{shown}");
    assert!(shown.contains("--finding '$(touch x)'"), "{shown}");
    assert!(!shown.contains("run $(touch"), "{shown}");
    assert!(
        shown.contains("--cgroup-root \"${CAMPAIGN_CGROUP_ROOT:?}\""),
        "{shown}"
    );
}

#[test]
fn the_findings_commands_compact_to_fit_a_long_id_at_the_minimum_size() {
    let id = format!("{}-0001", "f".repeat(64));
    let mut extra = findings();
    extra["findings"][0]["id"] = json!(id);
    extra["failure_groups"][0]["findings"] = json!([id]);
    let mut app = app(vec![job(0, "get", "violation")], extra);
    app.tab = Tab::Findings;
    let shown = screen(&app, MIN_WIDTH, MIN_HEIGHT);
    let detail = &shown[shown.find(" group · paths under").unwrap()..];
    assert!(detail.contains("campaign dispose"), "{detail}");
}

#[test]
fn commands_quote_a_state_path_with_a_space_or_an_apostrophe() {
    let mut app = app(vec![job(0, "get", "violation")], findings());
    app.tab = Tab::Findings;
    app.data_mut().snapshot.state = "/st ate/o'k".into();
    let shown = screen(&app, 200, 55);
    assert!(shown.contains(r"--state '/st ate/o'\''k'"), "{shown}");
}

#[test]
fn the_header_keeps_the_age_and_a_fetch_error_ahead_of_a_long_source() {
    let lock = json!({"holders": [{"command": "dispatch", "mode": "exclusive", "pid": 41234}]});
    let mut app = app(vec![job(0, "get", "pass")], json!({"lock": lock}));
    app.source = format!(
        "ssh -o BatchMode=yes {} campaign status --state /s",
        "h".repeat(40)
    );
    app.fail("ssh: connection refused", Duration::from_secs(1));
    let header = screen(&app, 80, 24).lines().next().unwrap().to_owned();
    assert!(header.contains("old"), "{header}");
    assert!(header.contains("ssh: connection refused"), "{header}");
}

#[test]
fn a_snapshot_taken_within_the_poll_schedule_is_not_stale() {
    let mut app = app(vec![job(0, "get", "pass")], json!({}));
    app.fetch_ms = Some(60_000);
    app.fetched_at = std::time::Instant::now().checked_sub(Duration::from_secs(298));
    let stale = |app: &App| {
        let line = header::summary(app, &theme(), 200).0;
        line.spans
            .iter()
            .find(|span| span.content.contains("old"))
            .unwrap()
            .content
            .contains("STALE")
    };
    assert!(!stale(&app), "60 s fetches poll every 240 s");
    app.fetched_at = std::time::Instant::now().checked_sub(Duration::from_secs(400));
    assert!(stale(&app));
}

#[test]
fn the_trend_plots_attempt_counts_once_two_samples_exist() {
    let mut app = app(vec![job(0, "get", "pass")], json!({}));
    let next = parsed(json!({
        "format": 1, "observed_ms": 5_060_000, "state": "/state",
        "jobs": [job(0, "get", "pass"), job(1, "get", "pass")],
    }));
    app.feed(next, Duration::from_millis(3));
    let shown = screen(&app, 120, 40);
    assert!(!shown.contains("collecting samples"), "{shown}");
    assert!(
        shown.contains("last 2 samples · finished attempts 1-2"),
        "{shown}"
    );
}

#[test]
fn jobs_columns_appear_as_the_table_widens() {
    let mut app = app(vec![job(0, "get", "violation")], json!({}));
    app.tab = Tab::Jobs;
    let header = |width| {
        let shown = screen(&app, width, 40);
        shown
            .lines()
            .find(|line| line.contains("outcome"))
            .unwrap()
            .to_owned()
    };
    let narrow = header(80);
    for absent in ["campaign/run", "att", " job"] {
        assert!(!narrow.contains(absent), "{narrow}");
    }
    assert!(narrow.contains("wall"), "{narrow}");
    let wide = header(200);
    for present in ["campaign/run", "wall", "att", "job"] {
        assert!(wide.contains(present), "{wide}");
    }
}

#[test]
fn the_outcome_column_shows_whole_campaign_inconclusive_labels_at_eighty_columns() {
    let mut app = app(vec![job(0, "get", "inconclusive")], json!({}));
    app.data_mut().outcomes[0].label = "inconclusive: limit no_progress".into();
    app.tab = Tab::Jobs;
    app.filter = JobFilter::All;
    app.listed = vec![0];
    let shown = screen(&app, 80, 24);
    assert!(shown.contains("inconclusive: limit no_progress"), "{shown}");
}

/// Three unsuccessful jobs on the Jobs tab whose labels name a rule. The
/// first two rules share their first 17 columns; the third label is the
/// longest a summary can name.
fn ruled() -> (Monitor, [&'static str; 3]) {
    let labels = [
        "unsuccessful: a required witness never fired",
        "unsuccessful: a required witness was never armed",
        "unsuccessful: fewer exact reads than the profile requir",
    ];
    let mut app = app(
        (0..3)
            .map(|n| job(n, "cluster-broad", "unsuccessful"))
            .collect(),
        json!({}),
    );
    for (outcome, label) in app.data_mut().outcomes.iter_mut().zip(labels) {
        outcome.label = label.into();
    }
    app.tab = Tab::Jobs;
    app.filter = JobFilter::All;
    app.listed = vec![0, 1, 2];
    (app, labels)
}

/// The table rows of a Jobs screen: the lines that hold the state column.
fn job_rows(shown: &str) -> Vec<&str> {
    shown
        .lines()
        .filter(|line| line.contains("settled"))
        .collect()
}

#[test]
fn the_outcome_column_widens_to_the_rule_qualified_labels_on_screen() {
    let (app, labels) = ruled();
    let shown = screen(&app, 200, 40);
    let rows = job_rows(&shown);
    assert_eq!(rows.len(), 3, "{shown}");
    for (row, label) in rows.iter().zip(labels) {
        assert!(row.contains(&format!(" {label} ")), "{row}");
    }
}

#[test]
fn a_label_wider_than_the_outcome_column_ends_in_a_mark_and_the_profile_keeps_its_minimum() {
    let (app, _) = ruled();
    let shown = screen(&app, 80, 24);
    let rows = job_rows(&shown);
    let cut = [
        "unsuccessful: a required witness never fi…",
        "unsuccessful: a required witness was neve…",
        "unsuccessful: fewer exact reads than the …",
    ];
    assert_eq!(rows.len(), 3, "{shown}");
    for (row, cut) in rows.iter().zip(cut) {
        assert!(row.contains(&format!(" {cut} cluster-bro… ")), "{row}");
    }
    let header = shown.lines().find(|line| line.contains("outcome")).unwrap();
    assert!(header.contains("wall"), "{header}");
}

/// At every supported width a row shows its whole label or a marked cut of
/// it at least as wide as the widest unqualified label, whichever columns
/// the width adds.
#[test]
fn no_width_cuts_an_outcome_label_without_a_mark() {
    let (app, labels) = ruled();
    for width in layout::MIN_WIDTH..=200 {
        let shown = screen(&app, width, 24);
        let rows = job_rows(&shown);
        assert_eq!(rows.len(), 3, "{width}: {shown}");
        for (row, label) in rows.iter().zip(labels) {
            let marked = (31..=crate::tui::text::width(label))
                .any(|room| row.contains(&format!(" {} ", crate::tui::text::clip(label, room))));
            assert!(marked, "{width}: {row}");
        }
    }
}

#[test]
fn help_at_the_minimum_size_scrolls_to_its_last_row() {
    let mut app = app(vec![job(0, "get", "pass")], json!({}));
    app.help = true;
    let top = screen(&app, MIN_WIDTH, MIN_HEIGHT);
    assert!(top.contains("j/k scroll"), "{top}");
    assert!(!top.contains("queued"), "{top}");
    app.update(crate::tui::keymap::Action::HelpBottom);
    let bottom = screen(&app, MIN_WIDTH, MIN_HEIGHT);
    assert!(bottom.contains("queued"), "{bottom}");
    assert!(bottom.contains("? or esc closes"), "{bottom}");
}

#[test]
fn the_dispose_command_fits_the_findings_detail_at_eighty_columns() {
    let mut app = app(vec![job(0, "get", "violation")], findings());
    app.tab = Tab::Findings;
    let shown = screen(&app, 80, 24);
    assert!(shown.contains("--evidence <text>"), "{shown}");
}

#[test]
fn the_profiles_run_window_follows_the_run_shift() {
    let jobs = (0..200).map(|n| job(n, "get", "pass")).collect();
    let mut app = app(jobs, json!({}));
    app.tab = Tab::Profiles;
    let newest = screen(&app, 80, 24);
    assert!(newest.contains("-199 of 200"), "{newest}");
    app.run_shift.set(1000);
    let oldest = screen(&app, 80, 24);
    assert!(oldest.contains("runs 0-"), "{oldest}");
    crate::state::tests::key(
        &mut app,
        ratatui::crossterm::event::KeyEvent::from(ratatui::crossterm::event::KeyCode::Char('0')),
    );
    screen(&app, 80, 24);
    crate::state::tests::key(
        &mut app,
        ratatui::crossterm::event::KeyEvent::from(ratatui::crossterm::event::KeyCode::Char('l')),
    );
    let moved = screen(&app, 80, 24);
    assert!(
        moved.contains("runs 1-"),
        "l after 0 moves the window: {moved}"
    );
}

#[test]
fn four_digit_runs_leave_a_profile_row_at_the_minimum_size() {
    let jobs = (1000..1040).map(|n| job(n, "get", "pass")).collect();
    let mut app = app(jobs, json!({}));
    app.tab = Tab::Profiles;
    let shown = screen(&app, MIN_WIDTH, MIN_HEIGHT);
    let table = above(&shown, " workload ");
    assert!(
        table
            .lines()
            .any(|line| line.contains("get ") && line.contains('✓')),
        "{table}"
    );
}

#[test]
fn overflow_notes_lead_the_table_titles_at_small_sizes() {
    let jobs: Vec<Value> = (0..300)
        .map(|n| job(n, &format!("a-very-long-profile-name-{n:03}"), "violation"))
        .collect();
    let mut app = app(jobs, json!({}));
    for (width, height) in [(80, 24), (MIN_WIDTH, MIN_HEIGHT)] {
        app.tab = Tab::Profiles;
        assert!(screen(&app, width, height).contains("300 workloads, rows 1-"));
        app.tab = Tab::Jobs;
        assert!(screen(&app, width, height).contains("of 300 jobs, rows 1-"));
    }
    let groups: Vec<Value> = (0..60)
        .map(|n| {
            json!({"kind": "violation", "identity": format!("id{n:02}"),
                   "cause": format!("cause-{n:02}"), "findings": [], "profiles": ["get"],
                   "runs": [0], "unresolved": 0})
        })
        .collect();
    let mut app = self::app(
        vec![job(0, "get", "pass")],
        json!({"failure_groups": groups}),
    );
    app.tab = Tab::Findings;
    let shown = screen(&app, MIN_WIDTH, MIN_HEIGHT);
    assert!(shown.contains("60 failure groups, rows 1-"), "{shown}");
}

#[test]
fn the_selected_signal_stays_visible_past_the_first_screen() {
    let groups: Vec<Value> = (0..60)
        .map(|n| {
            json!({"kind": "violation", "identity": format!("id{n:02}"),
                   "cause": format!("cause-{n:02}"), "findings": [], "profiles": ["get"],
                   "runs": [0], "unresolved": 1})
        })
        .collect();
    let mut app = self::app(
        vec![job(0, "get", "pass")],
        json!({"failure_groups": groups}),
    );
    app.tab = Tab::Signals;
    app.selections[Tab::Signals.index()] = app.signals().len() - 1;
    let table = above(&screen(&app, 120, 40), " detail ").to_owned();
    assert!(
        table.contains(&app.signals().last().unwrap().title),
        "{table}"
    );
    assert!(
        table.contains(&format!("of {}", app.signals().len())),
        "{table}"
    );
}

#[test]
fn detail_panes_count_the_attempts_subjects_and_findings_they_cannot_show() {
    let mut row = job(0, "get", "violation");
    let attempt = row["attempts"][0].clone();
    row["attempts"] = json!(
        (1..=10)
            .map(|n| {
                let mut attempt = attempt.clone();
                attempt["number"] = json!(n);
                attempt
            })
            .collect::<Vec<_>>()
    );
    let mut app = app(vec![row], json!({}));
    app.tab = Tab::Jobs;
    let shown = screen(&app, 80, 24);
    let detail = &shown[shown.find(" job · paths under").unwrap()..];
    assert!(detail.contains("more attempts"), "{detail}");
    let ids: Vec<String> = (0..40).map(|n| format!("{:064x}-{n:04}", 0)).collect();
    let rows: Vec<Value> = ids.iter().map(|id| json!({"id": id})).collect();
    let mut app = self::app(
        vec![job(0, "get", "violation")],
        json!({"findings": rows, "failure_groups": [{"kind": "violation", "identity": "02aa",
               "findings": ids, "profiles": ["get"], "runs": [0], "unresolved": 40}]}),
    );
    app.tab = Tab::Findings;
    let shown = screen(&app, 120, 40);
    assert!(shown.contains("more findings"), "{shown}");
    app.tab = Tab::Signals;
    let row = app
        .signals()
        .iter()
        .position(|signal| signal.subjects.len() == 40)
        .unwrap();
    app.selections[Tab::Signals.index()] = row;
    for (width, height) in [(80, 24), (MIN_WIDTH, MIN_HEIGHT)] {
        let shown = screen(&app, width, height);
        assert!(shown.contains("more"), "{width}x{height}: {shown}");
    }
}

#[test]
fn the_minimum_size_overview_keeps_whole_fact_counts() {
    let mut jobs: Vec<Value> = (0..12).map(|n| job(n, "get", "pass")).collect();
    for n in 12..24 {
        jobs.push(
            json!({"id": format!("{n:064x}"), "profile": "get", "campaign": "c",
                         "run": n, "variant": "v1", "state": "queued"}),
        );
    }
    let app = app(
        jobs,
        json!({"space": {"free_bytes": 549_755_813_888u64, "free_inodes": 12_300_000u64},
               "probes": 123}),
    );
    let shown = screen(&app, MIN_WIDTH, MIN_HEIGHT);
    assert!(shown.contains("12 queue"), "{shown}");
    assert!(shown.contains("123 probe"), "{shown}");
}

#[test]
fn an_oversized_wall_limit_renders_without_overflow() {
    let app = app(
        vec![job(0, "get", "pass")],
        json!({"config": {"verified": {"config": {"wall": u64::MAX, "slots": 1}}}}),
    );
    let shown = screen(&app, 120, 40);
    assert!(shown.contains("wall limit"), "{shown}");
}

#[test]
fn the_minimum_size_view_names_ctrl_c_while_a_prefix_is_pending() {
    let mut app = app(vec![job(0, "get", "pass")], json!({}));
    crate::state::tests::key(
        &mut app,
        ratatui::crossterm::event::KeyEvent::from(ratatui::crossterm::event::KeyCode::Char('g')),
    );
    let shown = screen(&app, 40, 10);
    assert!(shown.contains("ctrl-c quits"), "{shown}");
}

#[test]
fn the_header_names_the_controller_the_lock_reports() {
    let summary = |lock: Value, state: &str, theme: &Theme| {
        let mut row = job(0, "get", "pass");
        row["state"] = json!(state);
        let app = app(vec![row], json!({"lock": lock}));
        header::summary(&app, theme, 200).0
    };
    let shown = |lock: Value, state: &str| {
        summary(lock, state, &theme())
            .spans
            .iter()
            .find(|span| span.content.contains("controller") || span.content.contains(" pid "))
            .map(|span| (span.content.to_string(), span.style))
    };
    let running = json!({"holders": [
        {"command": "report", "mode": "shared", "pid": 7},
        {"command": "dispatch", "mode": "exclusive", "pid": 41234},
    ]});
    assert_eq!(shown(running, "queued").unwrap().0, "dispatch pid 41234");
    let anonymous = json!({"holders": [{"command": null, "mode": "exclusive", "pid": null}]});
    assert_eq!(shown(anonymous, "queued").unwrap().0, "controller running");
    let warned = format!("{} no visible controller", marker(Severity::Warning));
    for lock in [
        json!({"holders": []}),
        json!({"holders": [{"mode": "shared", "pid": 7}]}),
    ] {
        for state in ["queued", "waiting", "settling", "running"] {
            let (text, style) = shown(lock.clone(), state).unwrap();
            assert_eq!(
                (text.as_str(), style),
                (warned.as_str(), theme().warning),
                "{state}"
            );
        }
        let (text, style) = shown(lock, "settled").unwrap();
        assert_eq!(
            (text.as_str(), style),
            ("no visible controller", theme().muted)
        );
    }
    let plain = Theme::resolve(ColorDepth::None, Glyphs::Unicode);
    let texts = |state| -> Vec<String> {
        summary(json!({"holders": []}), state, &plain)
            .spans
            .iter()
            .map(|span| span.content.to_string())
            .collect()
    };
    assert!(
        texts("queued").contains(&warned),
        "the warning survives NO_COLOR"
    );
    assert!(texts("settled").contains(&"no visible controller".to_owned()));
    for lock in [
        json!({"unknown": "/proc/locks is absent"}),
        json!({"holders": [], "unknown": "/proc/locks is absent"}),
        json!({"holders": [{"mode": "new"}]}),
        json!({}),
    ] {
        assert_eq!(shown(lock, "queued").unwrap().0, "controller unknown");
    }
    let app = app(vec![job(0, "get", "pass")], json!({}));
    let line = header::summary(&app, &theme(), 200).0;
    assert!(
        line.spans
            .iter()
            .all(|span| !span.content.contains("controller")),
        "a snapshot without lock names no controller: {line:?}"
    );
}

/// The job counts and a pending refresh come before the controller, so
/// the room that drops one keeps the others.
#[test]
fn the_header_drops_the_controller_before_the_counts_and_a_pending_refresh() {
    let lock = json!({"holders": [{"command": "dispatch", "mode": "exclusive", "pid": 41234}]});
    let mut app = app(vec![job(0, "get", "pass")], json!({"lock": lock}));
    app.refresh_asked
        .get_or_insert_with(std::time::Instant::now);
    let texts = |room: usize| -> Vec<String> {
        header::summary(&app, &theme(), room)
            .0
            .spans
            .iter()
            .map(|span| span.content.to_string())
            .collect()
    };
    let wide = texts(400);
    assert!(
        wide.iter().any(|text| text == "dispatch pid 41234"),
        "{wide:?}"
    );
    assert!(
        wide.iter().any(|text| text == "refresh pending"),
        "{wide:?}"
    );
    let full: usize = wide.iter().map(|text| crate::tui::text::width(text)).sum();
    let narrow = texts(full - 2);
    assert!(
        !narrow.iter().any(|text| text.contains("pid")),
        "{narrow:?}"
    );
    assert!(
        narrow.iter().any(|text| text.contains("running ·")),
        "{narrow:?}"
    );
    assert!(
        narrow.iter().any(|text| text == "refresh pending"),
        "{narrow:?}"
    );
}

#[test]
fn a_failed_fetch_does_not_add_its_duration_to_the_snapshot_age() {
    let mut app = app(vec![job(0, "get", "pass")], json!({}));
    app.fetched_at = std::time::Instant::now().checked_sub(Duration::from_secs(20));
    app.fail("timed out", Duration::from_secs(300));
    let line = header::summary(&app, &theme(), 200).0;
    let age = line
        .spans
        .iter()
        .find(|span| span.content.contains("old"))
        .unwrap();
    assert!(!age.content.contains("5m"), "{}", age.content);
}

#[test]
fn the_footer_names_the_keys_a_pending_prefix_accepts() {
    let mut app = app(vec![job(0, "get", "pass")], json!({}));
    app.tab = Tab::Profiles;
    crate::state::tests::key(
        &mut app,
        ratatui::crossterm::event::KeyEvent::from(ratatui::crossterm::event::KeyCode::Char('g')),
    );
    let shown = screen(&app, 120, 40);
    assert!(shown.contains("g…   gg first row"), "{shown}");
}

#[test]
fn a_newline_in_a_finding_id_leaves_out_the_commands() {
    let mut extra = findings();
    extra["findings"][0]["id"] = json!("a\nb");
    extra["failure_groups"][0]["findings"] = json!(["a\nb"]);
    let mut app = app(vec![job(0, "get", "violation")], extra);
    app.tab = Tab::Findings;
    let shown = screen(&app, 200, 55);
    assert!(shown.contains("control character"), "{shown}");
    assert!(!shown.contains("campaign dispose"), "{shown}");
}

#[test]
fn a_group_targets_its_first_unresolved_finding() {
    let mut extra = findings();
    extra["findings"] = json!([
        {"id": "a-0001", "resolved": true},
        {"id": "a-0002"},
    ]);
    extra["failure_groups"][0]["findings"] = json!(["a-0001", "a-0002"]);
    let mut app = app(vec![job(0, "get", "violation")], extra);
    app.tab = Tab::Findings;
    assert_eq!(app.derived().unwrap().group_summaries[0].target, Some(1));
    let shown = screen(&app, 200, 55);
    assert!(shown.contains("<id> = a-0002"), "{shown}");
}

#[test]
fn the_header_age_counts_from_fetch_completion_on_either_clock() {
    let mut app = app(vec![job(0, "get", "pass")], json!({}));
    let age = |app: &App| {
        header::summary(app, &theme(), 200)
            .0
            .spans
            .iter()
            .find(|span| span.content.contains("old"))
            .unwrap()
            .content
            .to_string()
    };
    let mut next = app.shown();
    next.observed_ms += 1;
    let mut fetch = Fetch::now(Ok(app.derive(next)), Duration::ZERO);
    fetch.completed = std::time::Instant::now()
        .checked_sub(Duration::from_secs(120))
        .unwrap();
    app.apply(fetch);
    assert!(age(&app).contains("2m"), "{}", age(&app));
    let mut next = app.shown();
    next.observed_ms += 1;
    let mut fetch = Fetch::now(Ok(app.derive(next)), Duration::ZERO);
    fetch.completed_wall = std::time::SystemTime::now() - Duration::from_secs(180);
    app.apply(fetch);
    assert!(age(&app).contains("3m"), "{}", age(&app));
}

#[test]
fn r_shows_a_pending_refresh_until_a_later_fetch_returns() {
    let mut app = app(vec![job(0, "get", "pass")], json!({}));
    let earlier = Fetch::now(Ok(app.derive(app.shown())), Duration::ZERO);
    let pressed = crate::state::tests::key(
        &mut app,
        ratatui::crossterm::event::KeyEvent::from(ratatui::crossterm::event::KeyCode::Char('r')),
    );
    assert_eq!(pressed, crate::state::Effect::Refresh);
    let header = |app: &App| screen(app, 120, 40).lines().next().unwrap().to_owned();
    assert!(header(&app).contains("refresh pending"));
    app.apply(earlier);
    assert!(header(&app).contains("refresh pending"));
    let shown = app.shown();
    app.feed(shown, Duration::ZERO);
    assert!(!header(&app).contains("refresh pending"));
}

#[test]
fn the_footer_lists_only_keys_that_act_on_the_current_view() {
    let finding = format!("{:064x}-0001", 0);
    let mut extra = findings();
    extra["findings"][0]["id"] = json!(finding);
    extra["failure_groups"][0]["findings"] = json!([finding]);
    let mut app = app(vec![job(0, "get", "violation")], extra);
    let footer = |app: &App| screen(app, 200, 40).lines().last().unwrap().to_owned();
    assert!(footer(&app).contains("1-5 tab"), "{}", footer(&app));
    assert!(!footer(&app).contains("j/k"), "{}", footer(&app));
    app.tab = Tab::Findings;
    assert!(
        footer(&app).contains("enter open as jobs"),
        "{}",
        footer(&app)
    );
    assert!(!footer(&app).contains("^o back"), "{}", footer(&app));
    assert!(!footer(&app).contains("n/N"), "{}", footer(&app));
    crate::state::tests::key(
        &mut app,
        ratatui::crossterm::event::KeyEvent::from(ratatui::crossterm::event::KeyCode::Enter),
    );
    assert_eq!(app.tab, Tab::Jobs);
    assert!(footer(&app).contains("^o back"), "{}", footer(&app));
    assert!(footer(&app).contains("esc clear"), "{}", footer(&app));
}

fn styled(app: &App, width: u16, height: u16, theme: &Theme) -> Terminal<TestBackend> {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    let keymap = Keymap::default_map();
    terminal
        .draw(|frame| draw(frame, app, theme, &keymap))
        .unwrap();
    terminal
}

/// A tab in a cause would erase cells and an ESC would print as stray
/// text, so snapshot text reaches the screen as visible characters and a
/// finding id that held one leaves out its commands.
#[test]
fn snapshot_text_reaches_the_screen_without_control_characters() {
    let mut extra = findings();
    extra["failure_groups"][0]["cause"] = json!("violation, bad\tcause\u{1b}[31m");
    extra["lock"] =
        json!({"holders": [{"command": "dis\u{1b}patch", "mode": "exclusive", "pid": 9}]});
    let mut app = app(vec![job(0, "get\u{7}x", "violation")], extra);
    app.tab = Tab::Findings;
    let shown = screen(&app, 200, 55);
    assert!(shown.contains("dis\\u{1b}patch pid 9"), "{shown}");
    // The tab stops count from the start of the cause, before the view
    // drops its `violation, ` prefix.
    assert!(shown.contains("bad  cause\\u{1b}[31m"), "{shown}");
    app.tab = Tab::Profiles;
    assert!(screen(&app, 200, 55).contains("get\\u{7}x"));
    let d = app.derived().unwrap();
    assert!(
        d.signals
            .iter()
            .all(|signal| !signal.title.contains(char::is_control))
    );
}

/// A snapshot whose only job is held leaves the matrix with zero runs.
#[test]
fn profiles_with_zero_runs_render_and_title_no_runs() {
    let held = json!({"id": format!("{:064x}", 1), "held": "job binding differs"});
    let mut app = app(vec![held], json!({}));
    app.tab = Tab::Profiles;
    for (width, height) in [(60, 16), (80, 24), (160, 45)] {
        let shown = screen(&app, width, height);
        assert!(shown.contains("no runs"), "{width}x{height}: {shown}");
    }
}

/// A wide profile name is cut by display width, so the variant column
/// keeps its place.
#[test]
fn a_wide_profile_name_keeps_the_columns_after_it_in_place() {
    let jobs = vec![
        job(0, &"日本".repeat(20), "violation"),
        job(1, "get", "violation"),
    ];
    let mut app = app(jobs, json!({}));
    app.tab = Tab::Profiles;
    let terminal = styled(&app, 120, 30, &theme());
    let buffer = terminal.backend().buffer();
    let columns: Vec<u16> = (0..30)
        .filter_map(|y| {
            (0..119).find(|&x| buffer[(x, y)].symbol() == "v" && buffer[(x + 1, y)].symbol() == "1")
        })
        .take(2)
        .collect();
    assert_eq!(columns.len(), 2, "two table rows: {buffer:?}");
    assert_eq!(columns[0], columns[1], "{columns:?}");
}

/// Without color the selected row and the current tab use reverse video,
/// and the selected row also carries the marker.
#[test]
fn no_color_keeps_the_selection_and_current_tab_visible() {
    let mut app = app(vec![job(0, "get", "violation")], findings());
    app.tab = Tab::Jobs;
    let theme = Theme::resolve(ColorDepth::None, Glyphs::Unicode);
    let terminal = styled(&app, 120, 40, &theme);
    let buffer = terminal.backend().buffer();
    let row = (0..40)
        .find(|&y| buffer[(1, y)].symbol() == "▌")
        .expect("a selected row marker");
    assert!(buffer[(5, row)].modifier.contains(Modifier::REVERSED));
    let tab = (0..120)
        .find(|&x| buffer[(x, 1)].symbol() == "J")
        .expect("the Jobs tab title");
    assert!(buffer[(tab, 1)].modifier.contains(Modifier::REVERSED));
    assert!(
        buffer
            .content
            .iter()
            .all(|cell| cell.fg == ratatui::style::Color::Reset)
    );
}

/// ASCII glyphs draw nothing outside ASCII but the plain box borders.
#[test]
fn ascii_glyphs_leave_only_ascii_and_borders_on_screen() {
    let mut app = app(vec![job(0, "get", "violation")], findings());
    let next = parsed(json!({
        "format": 1, "observed_ms": 5_060_000, "state": "/state",
        "jobs": [job(0, "get", "violation"), job(1, "get", "pass")],
    }));
    app.feed(next, Duration::from_millis(3));
    let theme = Theme::resolve(ColorDepth::Ansi16, Glyphs::Ascii);
    for (tab, help) in Tab::ALL
        .into_iter()
        .flat_map(|tab| [(tab, false), (tab, true)])
    {
        app.tab = tab;
        app.help = help;
        let terminal = styled(&app, 120, 40, &theme);
        for cell in &terminal.backend().buffer().content {
            let symbol = cell.symbol();
            assert!(
                symbol.is_ascii() || "─│┌┐└┘├┤┬┴┼".contains(symbol),
                "{tab:?} help={help} drew {symbol:?}"
            );
        }
    }
}

/// The layout is a pure function of the frame size and the state: below
/// the minimum the compact view takes the frame, the header and footer
/// keep their rows at every size, and the Overview drops its outcome band
/// on a short body and adds the trend from 110 columns.
#[test]
fn the_layout_keeps_its_breakpoints_without_a_terminal() {
    let mut app = app(vec![job(0, "get", "violation")], findings());
    let rect = |width, height| ratatui::layout::Rect::new(0, 0, width, height);
    assert!(layout::layout(rect(MIN_WIDTH - 1, MIN_HEIGHT), &app).is_none());
    assert!(layout::layout(rect(MIN_WIDTH, MIN_HEIGHT - 1), &app).is_none());
    for (width, height) in [(60, 16), (80, 24), (120, 40), (200, 55)] {
        let areas = layout::layout(rect(width, height), &app).unwrap();
        assert_eq!((areas.header.height, areas.footer.height), (3, 1));
        assert_eq!(areas.footer.y, height - 1);
        let layout::Body::Overview(panes) = areas.body else {
            panic!("Overview body at {width}x{height}");
        };
        assert_eq!(panes.trend.is_some(), width >= 110, "{width}x{height}");
        assert!(panes.signals.height >= 3, "{width}x{height}");
        let below = panes.signals.y + panes.signals.height;
        assert_eq!(
            below, areas.footer.y,
            "{width}x{height}: panes fill the body"
        );
    }
    let short = layout::overview(rect(60, 12), 3);
    assert_eq!(
        short.domains.height, 0,
        "the band gives its rows to the signals"
    );
    app.tab = Tab::Findings;
    let areas = layout::layout(rect(80, 24), &app).unwrap();
    let layout::Body::Split { list, detail } = areas.body else {
        panic!("Findings splits its body");
    };
    assert!(list.height <= (list.height + detail.height) * 2 / 5 + 1);
    assert_eq!(list.y + list.height, detail.y);
    let (table, pane, depth) = layout::profiles(rect(60, 12), 4);
    assert_eq!(depth, 4);
    assert_eq!(table.height + pane.height, 12);
    assert_eq!(
        layout::profiles(rect(60, 8), 4).2,
        1,
        "a short body keeps one digit"
    );
}

/// The header summary shows the severity counts, the age and PAUSED on
/// every tab, and the fetch error only while it fits.
#[test]
fn the_header_summary_keeps_counts_and_age_and_adds_the_error_when_it_fits() {
    let mut app = app(vec![job(0, "get", "violation")], findings());
    app.fail("ssh: connection refused", Duration::from_millis(5));
    crate::state::tests::key(
        &mut app,
        ratatui::crossterm::event::KeyEvent::from(ratatui::crossterm::event::KeyCode::Char('p')),
    );
    for tab in Tab::ALL {
        app.tab = tab;
        let top = screen(&app, 200, 40).lines().next().unwrap().to_owned();
        for part in [
            "critical",
            "warning",
            "old",
            "PAUSED",
            "running",
            "connection refused",
        ] {
            assert!(top.contains(part), "{tab:?} lacks {part:?}: {top}");
        }
    }
    let (narrow, shown) = header::summary(&app, &theme(), 50);
    assert!(!shown, "{narrow}");
    let header = screen(&app, 60, 16)
        .lines()
        .take(3)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        header.contains("PAUSED") && header.contains("connection"),
        "{header}"
    );
}

const SIZES: [(u16, u16); 4] = [(60, 16), (80, 24), (120, 40), (200, 55)];

/// Every tab draws at the minimum, a default and two wide sizes with both
/// glyph sets, keeps the summary bar and its content, and in ASCII draws
/// nothing outside ASCII but the plain borders.
#[test]
fn every_tab_draws_at_every_size_with_both_glyph_sets() {
    let mut app = app(
        vec![job(0, "get", "violation"), job(1, "put", "unsuccessful")],
        findings(),
    );
    for glyphs in [Glyphs::Unicode, Glyphs::Ascii] {
        let theme = Theme::resolve(ColorDepth::Ansi16, glyphs);
        for (width, height) in SIZES {
            for (tab, expected) in [
                (Tab::Overview, "attempts"),
                (Tab::Signals, "violating Progress"),
                (Tab::Profiles, "get"),
                (Tab::Jobs, "violation"),
                (Tab::Findings, "a-0001"),
            ] {
                app.tab = tab;
                let terminal = styled(&app, width, height, &theme);
                let buffer = terminal.backend().buffer();
                let shown: String = buffer.content.iter().map(|cell| cell.symbol()).collect();
                let at = format!("{tab:?} at {width}x{height} with {glyphs:?}");
                assert!(shown.contains(expected), "{at} lacks {expected:?}");
                assert!(shown.contains("critical"), "{at} lacks the summary");
                if glyphs == Glyphs::Ascii {
                    let stray = buffer
                        .content
                        .iter()
                        .map(|cell| cell.symbol())
                        .find(|symbol| !symbol.is_ascii() && !"─│┌┐└┘".contains(symbol));
                    assert_eq!(stray, None, "{at}");
                }
            }
        }
    }
}

/// The selected row, the current tab and the severity flags stay visible at
/// every color depth: as the theme's selection style with color, as reverse
/// video without it, and with the flag's text marker in every case.
#[test]
fn selection_current_tab_and_severity_flags_hold_at_every_depth() {
    let mut app = app(
        vec![job(0, "get", "violation"), job(1, "put", "unsuccessful")],
        findings(),
    );
    app.tab = Tab::Jobs;
    app.filter = JobFilter::All;
    let shown = app.shown();
    app.feed(shown, Duration::ZERO);
    // The flagged job lists first; selecting the second row leaves the
    // flag drawn in its own style.
    app.selections[Tab::Jobs.index()] = 1;
    for depth in [
        ColorDepth::None,
        ColorDepth::Ansi16,
        ColorDepth::Indexed256,
        ColorDepth::TrueColor,
    ] {
        let theme = Theme::resolve(depth, Glyphs::Unicode);
        let terminal = styled(&app, 120, 40, &theme);
        let buffer = terminal.backend().buffer();
        let selected = (0..40)
            .find(|&y| buffer[(1, y)].symbol() == "▌")
            .unwrap_or_else(|| panic!("{depth:?}: no selection marker"));
        let cell = &buffer[(12, selected)];
        let tab = (0..120)
            .find(|&x| buffer[(x, 1)].symbol() == "J")
            .expect("the Jobs tab title");
        let current = &buffer[(tab, 1)];
        if depth == ColorDepth::None {
            assert!(cell.modifier.contains(Modifier::REVERSED), "{depth:?}");
            assert!(current.modifier.contains(Modifier::REVERSED), "{depth:?}");
        } else {
            assert_eq!(Some(cell.bg), theme.selection.bg, "{depth:?}");
            assert_eq!(Some(current.bg), theme.selection.bg, "{depth:?}");
        }
        let flagged: Vec<(u16, String)> = (0..40)
            .filter(|&y| {
                y > 3
                    && y != selected
                    && buffer[(0, y)].symbol() == "│"
                    && buffer[(1, y)].symbol() == " "
            })
            .filter_map(|y| {
                let flag: String = (3..5).map(|x| buffer[(x, y)].symbol()).collect();
                matches!(flag.trim(), "!!" | "!" | "i").then_some((y, flag))
            })
            .collect();
        assert!(!flagged.is_empty(), "{depth:?}: no flagged row\n{buffer:?}");
        for (y, flag) in flagged {
            let severity = match flag.trim() {
                "!!" => Severity::Critical,
                "!" => Severity::Warning,
                _ => Severity::Info,
            };
            assert_eq!(
                Some(buffer[(3, y)].fg),
                theme.severity(severity).fg,
                "{depth:?} row {y}"
            );
        }
    }
}

/// Every binding's label appears in the help overlay of a tab where it
/// acts, so help lists every key the table dispatches.
#[test]
fn the_help_overlay_lists_every_binding_label() {
    use crate::tui::keymap::{Context, Scope};
    let mut app = app(vec![job(0, "get", "violation")], findings());
    app.help = true;
    let keymap = Keymap::default_map();
    for binding in keymap.bindings() {
        let tab = match binding.scope {
            Scope::Any | Scope::Tabs => Tab::Overview,
            Scope::In(Context::Overview) => Tab::Overview,
            Scope::In(Context::Profiles) => Tab::Profiles,
            Scope::In(Context::Jobs) => Tab::Jobs,
            Scope::In(Context::Findings) => Tab::Findings,
            Scope::Lists | Scope::In(_) => Tab::Signals,
        };
        app.tab = tab;
        let shown = screen(&app, 200, 60);
        assert!(
            shown.contains(binding.label),
            "help on {tab:?} lacks {:?}: {shown}",
            binding.label
        );
    }
}

fn large_snapshot(jobs: usize) -> crate::snapshot::Snapshot {
    use crate::snapshot::{AttemptRow, Job, JobState, Settled, Snapshot};
    let classes = ["pass", "violation", "unsuccessful", "pass"];
    Snapshot {
        format: 1,
        observed_ms: 10_000_000,
        state: "/state".into(),
        config: None,
        space: None,
        probes: 0,
        held_probes: Vec::new(),
        variants: Default::default(),
        lock: Some(crate::snapshot::Lock {
            holders: Some(Vec::new()),
            unknown: None,
        }),
        jobs: (0..jobs)
            .map(|n| Job {
                id: format!("{n:064x}"),
                profile: format!("profile-{:02}", n % 40),
                campaign: "c".into(),
                run: Some((n / 40) as u64),
                variant: "v".into(),
                state: JobState::Settled,
                attempts_allowed: 1,
                result: Some(Settled {
                    attempt: Some(1),
                    class: Some(classes[n % classes.len()].into()),
                    ..Settled::default()
                }),
                attempts: vec![AttemptRow {
                    number: Some(1),
                    intent_ms: Some(1),
                    finished_ms: Some(9),
                    ..AttemptRow::default()
                }],
                ..Job::default()
            })
            .collect(),
        findings: Vec::new(),
        release_blockers: Vec::new(),
        failure_groups: Vec::new(),
    }
}

fn median_frame(app: &App, theme: &Theme) -> Duration {
    let keymap = Keymap::default_map();
    let mut terminal = Terminal::new(TestBackend::new(160, 45)).unwrap();
    let mut frames: Vec<Duration> = (0..9)
        .map(|_| {
            let started = std::time::Instant::now();
            terminal
                .draw(|frame| draw(frame, app, theme, &keymap))
                .unwrap();
            started.elapsed()
        })
        .collect();
    frames.sort();
    frames[frames.len() / 2]
}

/// A frame builds rows only for the visible window, so at 10^5 jobs every
/// tab draws within 10 times the cost of the same tab at 100 jobs; a view
/// that built every row would cost about 1,000 times as much.
#[test]
fn a_frame_at_ten_to_the_fifth_jobs_costs_at_most_ten_times_the_visible_window() {
    let theme = theme();
    let mut small = Monitor::new();
    small.feed(large_snapshot(100), Duration::ZERO);
    let mut large = Monitor::new();
    large.feed(large_snapshot(100_000), Duration::ZERO);
    for monitor in [&mut small, &mut large] {
        monitor.filter = JobFilter::All;
        let shown = monitor.shown();
        monitor.feed(shown, Duration::ZERO);
    }
    for tab in Tab::ALL {
        small.tab = tab;
        large.tab = tab;
        let window = median_frame(&small, &theme).max(Duration::from_micros(200));
        let frame = median_frame(&large, &theme);
        assert!(
            frame <= window * 10,
            "{tab:?}: {frame:?} at 10^5 jobs against {window:?} at 100"
        );
    }
}

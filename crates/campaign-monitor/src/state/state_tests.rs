//! App tests: vim navigation, per-tab search and its restoration, drill-down
//! focus and the back stack, selection identity across snapshots, and
//! agreement between signal naming, job flags and the job list.

use std::ops::{Deref, DerefMut};

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json::json;

use super::fetched::age_text_lasts;
use super::focus::BACK_DEPTH;
use super::naming::{naming, signal_jobs};
use super::*;
use crate::history::History;
use crate::signals::Severity;
use crate::snapshot::Snapshot;
use crate::tui::keymap::{Action, Keymap};

/// An [`App`] with the history its poller would own, so a test feeds
/// snapshots the way the poller derives them.
pub(crate) struct Monitor {
    app: App,
    history: History,
}

impl Monitor {
    pub(crate) fn new() -> Self {
        Self {
            app: App::new("test".into(), Duration::from_secs(15)),
            history: History::in_memory(),
        }
    }

    /// `snapshot` derived against this monitor's history.
    pub(crate) fn derive(&mut self, snapshot: Snapshot) -> Arc<Derived> {
        Arc::new(Derived::observe(snapshot, &mut self.history))
    }

    /// Applies `snapshot` as a fetch that took `elapsed` and returned now.
    pub(crate) fn feed(&mut self, snapshot: Snapshot, elapsed: Duration) {
        let derived = self.derive(snapshot);
        self.app.apply(Fetch::now(Ok(derived), elapsed));
    }

    /// Applies a failed fetch that took `elapsed`.
    pub(crate) fn fail(&mut self, error: &str, elapsed: Duration) {
        self.app.apply(Fetch::now(Err(error.into()), elapsed));
    }

    /// The snapshot shown.
    pub(crate) fn shown(&self) -> Snapshot {
        self.app.derived().unwrap().snapshot.clone()
    }

    /// The derived snapshot shown, for a test that edits it in place.
    pub(crate) fn data_mut(&mut self) -> &mut Derived {
        Arc::get_mut(self.app.derived.as_mut().unwrap()).unwrap()
    }
}

impl Deref for Monitor {
    type Target = App;

    fn deref(&self) -> &App {
        &self.app
    }
}

impl DerefMut for Monitor {
    fn deref_mut(&mut self) -> &mut App {
        &mut self.app
    }
}

/// `fields` over a format-1 snapshot whose required fields are empty, as
/// [`Snapshot`] JSON.
pub(crate) fn complete(fields: serde_json::Value) -> serde_json::Value {
    let mut snapshot = json!({
        "format": 1, "observed_ms": 10_000_000, "state": "/state", "config": null,
        "space": {"free_bytes": 1u64 << 40, "free_inodes": 1_000_000}, "probes": 0,
        "held_probes": [], "jobs": [], "findings": [], "failure_groups": [],
    });
    for (key, value) in fields.as_object().expect("snapshot fields are an object") {
        snapshot[key] = value.clone();
    }
    snapshot
}

/// The [`Snapshot`] of [`complete`] `fields`.
pub(crate) fn parsed(fields: serde_json::Value) -> Snapshot {
    serde_json::from_value(complete(fields)).unwrap()
}

/// Presses `key` the way the run loop does, through the binding table.
pub(crate) fn key(app: &mut App, key: KeyEvent) -> Effect {
    crate::tui::event_loop::press(app, &Keymap::default_map(), key)
}

fn press(app: &mut App, code: KeyCode) -> Effect {
    key(app, KeyEvent::from(code))
}

fn control(app: &mut App, c: char) -> Effect {
    key(app, KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL))
}

fn keys(app: &mut App, text: &str) {
    for c in text.chars() {
        press(app, KeyCode::Char(c));
    }
}

fn id(n: usize) -> String {
    format!("{n:064x}")
}

fn loaded(extra: Vec<serde_json::Value>) -> Monitor {
    let mut app = Monitor::new();
    let mut jobs: Vec<_> = ["pass", "violation", "pass"]
        .iter()
        .enumerate()
        .map(|(n, class)| {
            json!({"id": id(n), "profile": format!("p{n}"), "campaign": "c",
                   "run": 0, "variant": "v", "state": "settled",
                   "result": {"attempt": 1, "class": class},
                   "attempts": [{"number": 1, "attempt": format!("{}-0001", id(n))}]})
        })
        .collect();
    jobs.extend(extra);
    let snapshot = json!({"format": 1, "observed_ms": 10_000_000, "jobs": jobs,
                          "config": {"verified": {"config": {"wall": 60}}}});
    app.feed(parsed(snapshot), Duration::from_millis(5));
    app
}

fn profiles(count: usize) -> Monitor {
    let jobs = (3..count + 3)
        .map(|n| {
            json!({"id": id(n), "profile": format!("profile-{n:03}"), "campaign": "c",
                   "run": 0, "variant": "v", "state": "settled",
                   "result": {"attempt": 1, "class": "pass"},
                   "attempts": [{"number": 1, "attempt": format!("{}-0001", id(n))}]})
        })
        .collect();
    let mut app = loaded(jobs);
    app.tab = Tab::Profiles;
    let rows = app.rows(Tab::Profiles);
    app.view(Tab::Profiles).place(0, rows, 20);
    app
}

fn listed_ids(app: &App) -> Vec<String> {
    (0..app.listed.len())
        .map(|row| app.job(row).unwrap().0.id.clone())
        .collect()
}

#[test]
fn control_d_and_u_move_half_a_screen_and_control_f_and_b_a_whole_screen() {
    let mut app = profiles(300);
    control(&mut app, 'd');
    assert_eq!(app.selected(), 10);
    control(&mut app, 'f');
    assert_eq!(app.selected(), 30);
    control(&mut app, 'u');
    assert_eq!(app.selected(), 20);
    control(&mut app, 'b');
    assert_eq!(app.selected(), 0);
    press(&mut app, KeyCode::PageDown);
    assert_eq!(app.selected(), 20);
}

#[test]
fn gg_and_g_jump_to_the_ends_and_a_lone_g_waits_for_its_second_key() {
    let mut app = profiles(300);
    press(&mut app, KeyCode::Char('G'));
    assert_eq!(app.selected(), app.rows(Tab::Profiles) - 1);
    press(&mut app, KeyCode::Char('g'));
    assert_eq!(app.pending(), Some('g'));
    assert_ne!(app.selected(), 0);
    press(&mut app, KeyCode::Char('g'));
    assert_eq!(app.selected(), 0);
    keys(&mut app, "gt");
    assert_eq!(app.tab, Tab::Jobs);
    keys(&mut app, "gT");
    assert_eq!(app.tab, Tab::Profiles);
}

#[test]
fn h_m_and_l_select_the_top_middle_and_bottom_of_the_screen() {
    let mut app = profiles(300);
    app.select(50);
    let rows = app.rows(Tab::Profiles);
    app.view(Tab::Profiles).place(50, rows, 20);
    press(&mut app, KeyCode::Char('H'));
    assert_eq!(app.selected(), 31);
    press(&mut app, KeyCode::Char('L'));
    assert_eq!(app.selected(), 50);
    press(&mut app, KeyCode::Char('M'));
    assert_eq!(app.selected(), 40);
}

#[test]
fn zt_and_zb_scroll_the_screen_around_the_selection() {
    let mut app = profiles(300);
    app.select(100);
    keys(&mut app, "zt");
    assert_eq!(app.view(Tab::Profiles).offset.get(), 100);
    keys(&mut app, "zb");
    assert_eq!(app.view(Tab::Profiles).offset.get(), 81);
    keys(&mut app, "zz");
    assert_eq!(app.view(Tab::Profiles).offset.get(), 90);
}

#[test]
fn control_e_scrolls_one_line_and_drags_the_selection_into_view() {
    let mut app = profiles(300);
    control(&mut app, 'e');
    assert_eq!(app.view(Tab::Profiles).offset.get(), 1);
    assert_eq!(app.selected(), 1);
    control(&mut app, 'y');
    assert_eq!(app.view(Tab::Profiles).offset.get(), 0);
}

#[test]
fn viewport_scrolls_only_when_the_selection_leaves_it() {
    let view = Viewport::default();
    assert_eq!(view.place(5, 100, 10), (0, 10));
    assert_eq!(view.place(12, 100, 10), (3, 13));
    assert_eq!(view.place(8, 100, 10), (3, 13));
    assert_eq!(view.place(1, 100, 10), (1, 11));
    assert_eq!(view.place(99, 100, 10), (90, 100));
}

#[test]
fn slash_moves_to_the_first_match_and_n_and_shift_n_cycle_matches() {
    let mut app = profiles(300);
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, "profile-1");
    press(&mut app, KeyCode::Enter);
    let first = app.selected();
    assert!(app.row_text(Tab::Profiles, first).contains("profile-1"));
    press(&mut app, KeyCode::Char('n'));
    assert!(app.selected() > first);
    assert!(
        app.row_text(Tab::Profiles, app.selected())
            .contains("profile-1")
    );
    press(&mut app, KeyCode::Char('N'));
    assert_eq!(app.selected(), first);
}

#[test]
fn escape_during_a_search_returns_to_the_row_it_started_from() {
    let mut app = profiles(300);
    app.select(7);
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, "profile-2");
    assert_ne!(app.selected(), 7);
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.selected(), 7);
    assert!(app.search(app.tab).is_empty());
}

#[test]
fn h_and_l_shift_the_profile_run_window_and_zero_and_dollar_reach_its_ends() {
    let mut app = profiles(3);
    press(&mut app, KeyCode::Char('h'));
    assert_eq!(app.run_shift.get(), 1);
    press(&mut app, KeyCode::Char('l'));
    assert_eq!(app.run_shift.get(), 0);
    press(&mut app, KeyCode::Char('0'));
    assert_eq!(
        app.run_shift.get(),
        app.derived().unwrap().matrix.runs.len()
    );
    press(&mut app, KeyCode::Char('$'));
    assert_eq!(app.run_shift.get(), 0);
}

#[test]
fn enter_on_a_profile_focuses_its_jobs_and_control_o_returns() {
    let mut app = profiles(10);
    app.select(4);
    let profile = app.derived().unwrap().matrix.rows[4].profile.clone();
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.tab, Tab::Jobs);
    assert_eq!(app.listed.len(), 1);
    assert_eq!(app.job(0).unwrap().0.profile, profile);
    control(&mut app, 'o');
    assert_eq!(app.tab, Tab::Profiles);
    assert_eq!(app.selected(), 4);
    assert!(app.focus.is_none());
}

#[test]
fn enter_on_a_signal_focuses_the_jobs_it_names() {
    let stuck = json!({"id": id(9), "profile": "long", "campaign": "c", "run": 0,
                       "variant": "v", "state": "running",
                       "attempts": [{"number": 1, "attempt": format!("{}-0001", id(9)),
                                     "intent_ms": 1}]});
    let mut app = loaded(vec![stuck]);
    app.tab = Tab::Signals;
    let row = app
        .signals()
        .iter()
        .position(|signal| signal.detector == "stuck-attempt")
        .unwrap();
    app.select(row);
    press(&mut app, KeyCode::Enter);
    assert_eq!(listed_ids(&app), vec![id(9)]);
    press(&mut app, KeyCode::Esc);
    assert!(app.focus.is_none());
    assert_eq!(app.tab, Tab::Jobs);
}

#[test]
fn the_job_filter_starts_on_problems_and_cycles_through_all_and_unsettled() {
    let queued = json!({"id": id(5), "profile": "p5", "campaign": "c", "run": 0,
                        "variant": "v", "state": "queued"});
    let waiting = json!({"id": id(6), "profile": "p6", "campaign": "c", "run": 0,
                         "variant": "v", "state": "waiting",
                         "attempts": [{"number": 1, "attempt": format!("{}-0001", id(6)), "intent_ms": 1,
                                       "finished_ms": 2, "finished": {"class": "pass"}}]});
    let mut app = loaded(vec![queued, waiting]);
    press(&mut app, KeyCode::Char('4'));
    assert_eq!(listed_ids(&app), vec![id(1)]);
    press(&mut app, KeyCode::Char('f'));
    assert_eq!(app.listed.len(), 5);
    press(&mut app, KeyCode::Char('f'));
    assert_eq!(app.filter, JobFilter::Unsettled);
    let mut listed = listed_ids(&app);
    listed.sort();
    assert_eq!(listed, vec![id(5), id(6)]);
}

#[test]
fn a_job_search_matches_an_outcome_label_or_an_id_prefix() {
    let mut app = loaded(Vec::new());
    app.tab = Tab::Jobs;
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, "violation");
    assert_eq!(listed_ids(&app), vec![id(1)]);
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, &id(2));
    assert_eq!(listed_ids(&app), vec![id(2)]);
    press(&mut app, KeyCode::Esc);
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, "02");
    assert!(
        listed_ids(&app).is_empty(),
        "02 lies inside id(2) but does not start it"
    );
}

/// A list longer than half of the jobs is tested through a mask built in
/// job order, a shorter one job by job; both keep exactly the jobs that
/// match, in list order.
#[test]
fn a_job_query_keeps_the_same_jobs_through_the_mask_and_job_by_job() {
    let extra = (0..40)
        .map(|n| {
            json!({"id": id(10 + n), "profile": format!("P{}", n % 7), "campaign": "c",
                   "run": n, "variant": "v", "state": "settled",
                   "result": {"attempt": 1, "class": if n % 3 == 0 { "violation" } else { "pass" }},
                   "attempts": [{"number": 1, "attempt": format!("{}-0001", id(10 + n))}]})
        })
        .collect();
    let app = loaded(extra);
    let d = app.derived.clone().unwrap();
    let mut all: Vec<usize> = (0..d.snapshot.jobs.len()).collect();
    all.reverse();
    for query in ["p3", "VIOL", &id(12)[..62], "0", "zz"] {
        let mut masked = all.clone();
        super::search::JobQuery::new(query, &d).retain(&mut masked);
        let mut single = super::search::JobQuery::new(query, &d);
        let one_by_one: Vec<usize> = all.iter().copied().filter(|&i| single.matches(i)).collect();
        assert_eq!(masked, one_by_one, "{query}");
        let short = &all[..all.len() / 2];
        let mut kept = short.to_vec();
        super::search::JobQuery::new(query, &d).retain(&mut kept);
        let expected: Vec<usize> = one_by_one
            .iter()
            .copied()
            .filter(|i| short.contains(i))
            .collect();
        assert_eq!(kept, expected, "{query}");
    }
}

/// Lowercasing depends on the characters that follow: "A\u{3a3}" lowercases
/// to "a\u{3c2}" with a final sigma and "A\u{3a3}B" to "a\u{3c3}b". The query
/// after "B" diverges from the query after "\u{3a3}", so typing "B" matches
/// the whole query against every job and lists the jobs whose profile holds
/// "a\u{3c3}b".
#[test]
fn typing_a_job_query_lists_what_a_fresh_match_of_the_whole_query_lists() {
    let profiles = ["a\u{3c3}b", "a\u{3c2}", "ab", "xa\u{3c3}b", "CAB"];
    let extra = profiles
        .iter()
        .enumerate()
        .map(|(n, profile)| {
            json!({"id": id(10 + n), "profile": profile, "campaign": "c",
                   "run": 0, "variant": "v", "state": "settled",
                   "result": {"attempt": 1, "class": "pass"},
                   "attempts": [{"number": 1, "attempt": format!("{}-0001", id(10 + n))}]})
        })
        .collect();
    let mut app = loaded(extra);
    app.tab = Tab::Jobs;
    press(&mut app, KeyCode::Char('/'));
    let mut typed = String::new();
    for c in "A\u{3a3}B".chars() {
        app.type_char(c);
        typed.push(c);
        let narrowed = listed_ids(&app);
        app.relist();
        assert_eq!(narrowed, listed_ids(&app), "after {typed:?}");
    }
    assert!(listed_ids(&app).contains(&id(10)));
    assert!(listed_ids(&app).contains(&id(13)));
    app.paste("0");
    let narrowed = listed_ids(&app);
    app.relist();
    assert_eq!(narrowed, listed_ids(&app));
    assert!(narrowed.is_empty());
}

#[test]
fn escape_after_a_filter_change_keeps_the_filter_the_user_chose() {
    let mut app = loaded(Vec::new());
    app.tab = Tab::Jobs;
    press(&mut app, KeyCode::Char('/'));
    press(&mut app, KeyCode::Char('p'));
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('f'));
    assert_eq!(app.filter, JobFilter::Unsettled);
    press(&mut app, KeyCode::Esc);
    assert!(app.search(app.tab).is_empty());
    assert_eq!(app.filter, JobFilter::Unsettled);
}

#[test]
fn escape_restores_a_filter_other_than_the_default() {
    let mut app = loaded(Vec::new());
    app.tab = Tab::Jobs;
    press(&mut app, KeyCode::Char('f'));
    press(&mut app, KeyCode::Char('f'));
    assert_eq!(app.filter, JobFilter::Unsettled);
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, "p2");
    assert_eq!(app.filter, JobFilter::All);
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.filter, JobFilter::Unsettled);
    assert!(app.listed.is_empty());
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, "p");
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.listed.len(), 3);
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.filter, JobFilter::Unsettled);
    assert!(app.listed.is_empty());
}

fn settled(n: usize, profile: &str, class: &str) -> serde_json::Value {
    json!({"id": id(n), "profile": profile, "campaign": "c", "run": n, "variant": "v",
           "state": "settled", "result": {"attempt": 1, "class": class},
           "attempts": [{"number": 1, "attempt": format!("{}-0001", id(n))}]})
}

fn snapshot(jobs: Vec<serde_json::Value>) -> Snapshot {
    parsed(json!({"jobs": jobs}))
}

#[test]
fn a_smaller_snapshot_clamps_the_selection_to_its_last_row() {
    let mut app = profiles(20);
    app.select(18);
    let jobs = (3..8)
        .map(|n| settled(n, &format!("profile-{n:03}"), "pass"))
        .collect();
    app.feed(snapshot(jobs), Duration::from_millis(5));
    assert_eq!(app.selected(), app.rows(Tab::Profiles) - 1);
}

#[test]
fn the_selected_job_stays_selected_when_a_new_snapshot_reorders_the_list() {
    let mut app = Monitor::new();
    let jobs = vec![settled(1, "a", "violation"), settled(2, "b", "violation")];
    app.feed(snapshot(jobs.clone()), Duration::from_millis(5));
    app.tab = Tab::Jobs;
    app.select(1);
    let chosen = app.job(1).unwrap().0.id.clone();
    let mut more = vec![settled(0, "0", "engine-failure")];
    more.extend(jobs);
    app.feed(snapshot(more), Duration::from_millis(5));
    assert_eq!(app.job(app.selected()).unwrap().0.id, chosen);
}

#[test]
fn a_held_job_named_by_its_record_path_is_flagged_critical() {
    let held = json!({"id": id(7), "held": "job binding differs"});
    let short = json!({"id": "bad", "held": "job binding differs"});
    let app = loaded(vec![held, short]);
    assert_eq!(app.flag(&id(7)), Some(Severity::Critical));
    assert_eq!(app.flag("bad"), Some(Severity::Critical));
    assert!(
        app.naming(&id(7))
            .any(|signal| signal.detector == "held-record")
    );
    assert_eq!(&listed_ids(&app)[..1], [id(7)].as_slice());
}

#[test]
fn naming_lists_each_signal_that_names_a_job_once_in_signal_order() {
    let signal = |severity, subjects: &[String]| Signal {
        severity,
        domain: crate::outcome::Domain::Service,
        detector: "test",
        title: String::new(),
        detail: String::new(),
        subjects: subjects.to_vec(),
    };
    let both = [
        format!("jobs/{}", id(1)),
        format!("{}-0001", id(1)),
        format!("{}-0001", id(2)),
    ];
    let jobs: Vec<crate::snapshot::Job> = [id(1), id(2), id(3), id(1)]
        .into_iter()
        .map(|id| crate::snapshot::Job {
            id,
            ..Default::default()
        })
        .collect();
    let ids = super::ids::IdIndex::new(&jobs);
    let signals = [
        signal(Severity::Warning, &both),
        signal(Severity::Critical, &both[..1]),
        signal(Severity::Info, &both[2..]),
    ];
    let populations = super::populations::Populations::new(&jobs);
    let named: Vec<Vec<usize>> = signals
        .iter()
        .map(|signal| signal_jobs(signal, &populations, &jobs, &ids))
        .collect();
    assert_eq!(named, [vec![0, 1, 3], vec![0, 3], vec![1]]);
    let naming = |job| naming(&named, job).collect::<Vec<_>>();
    assert_eq!(naming(0), [0, 1]);
    assert_eq!(naming(1), [0, 2]);
    assert!(naming(2).is_empty());
    assert_eq!(
        naming(3),
        naming(0),
        "a job that shares an id is named with it"
    );
}

#[test]
fn critical_jobs_list_before_warning_jobs_whatever_their_outcome_rank() {
    let mut app = Monitor::new();
    let jobs = vec![
        settled(1, "service", "unsuccessful"),
        settled(2, "simulator", "engine-failure"),
        settled(3, "passing", "pass"),
    ];
    app.feed(snapshot(jobs), Duration::from_millis(5));
    assert_eq!(app.flag(&id(2)), Some(Severity::Critical));
    assert_eq!(app.flag(&id(1)), Some(Severity::Warning));
    assert_eq!(listed_ids(&app), vec![id(2), id(1)]);
}

#[test]
fn a_variant_cut_for_a_focus_label_keeps_whole_characters() {
    let job = json!({"id": id(3), "profile": "p", "campaign": "c", "run": 0,
                     "variant": format!("a{}", "é".repeat(9)), "state": "settled",
                     "result": {"attempt": 1, "class": "pass"},
                     "attempts": [{"number": 1, "attempt": format!("{}-0001", id(3))}]});
    let mut app = loaded(vec![job]);
    app.tab = Tab::Profiles;
    let row = app
        .derived()
        .unwrap()
        .matrix
        .rows
        .iter()
        .position(|row| row.variant.starts_with('a'))
        .unwrap();
    app.select(row);
    press(&mut app, KeyCode::Enter);
    let label = &app.focus.as_ref().unwrap().label;
    assert!(label.ends_with(&format!("a{}", "é".repeat(7))), "{label}");
}

#[test]
fn a_job_named_by_a_warning_and_a_critical_signal_keeps_the_critical_flag() {
    let mut app = Monitor::new();
    let mut both = settled(1, "service", "unsuccessful");
    both["attempts"] = json!([{"number": 1, "held": "binding differs"}]);
    let jobs = vec![both, settled(2, "other", "unsuccessful")];
    app.feed(snapshot(jobs), Duration::from_millis(5));
    let severities: Vec<Severity> = app.naming(&id(1)).map(|signal| signal.severity).collect();
    assert!(severities.contains(&Severity::Warning), "{severities:?}");
    assert!(severities.contains(&Severity::Critical), "{severities:?}");
    assert_eq!(app.flag(&id(1)), Some(Severity::Critical));
    assert_eq!(app.flag(&id(2)), Some(Severity::Warning));
    assert_eq!(listed_ids(&app), vec![id(1), id(2)]);
}

#[test]
fn a_held_attempt_directory_flags_and_opens_its_job() {
    let held = json!({"id": format!("attempts/{}", id(4)), "held": "not captured"});
    let mut app = Monitor::new();
    let snapshot = parsed(json!({
        "format": 1, "observed_ms": 10_000_001,
        "jobs": [{"id": id(4), "profile": "p4", "campaign": "c", "run": 0,
                  "variant": "v", "state": "running"}],
        "findings": [held],
    }));
    app.feed(snapshot, Duration::from_millis(5));
    assert_eq!(app.flag(&id(4)), Some(Severity::Critical));
    app.tab = Tab::Signals;
    let row = app
        .signals()
        .iter()
        .position(|signal| signal.detector == "held-record")
        .unwrap();
    app.select(row);
    press(&mut app, KeyCode::Enter);
    assert_eq!(listed_ids(&app), vec![id(4)]);
}

#[test]
fn a_running_job_that_a_signal_names_is_a_problem_and_lists_first() {
    let stuck = json!({"id": id(9), "profile": "long", "campaign": "c", "run": 0,
                       "variant": "v", "state": "running",
                       "attempts": [{"number": 1, "attempt": format!("{}-0001", id(9)),
                                     "intent_ms": 1}]});
    let app = loaded(vec![stuck]);
    assert_eq!(listed_ids(&app), vec![id(9), id(1)]);
}

#[test]
fn a_job_search_narrows_the_list_and_escape_restores_the_filter_it_replaced() {
    let mut app = loaded(Vec::new());
    app.tab = Tab::Jobs;
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, "p2");
    assert_eq!(listed_ids(&app), vec![id(2)]);
    assert_eq!(app.filter, JobFilter::All);
    press(&mut app, KeyCode::Esc);
    assert!(!app.searching());
    assert_eq!(app.filter, JobFilter::Problems);
    assert_eq!(listed_ids(&app), vec![id(1)]);
}

#[test]
fn a_committed_job_search_stays_until_escape() {
    let mut app = loaded(Vec::new());
    app.tab = Tab::Jobs;
    press(&mut app, KeyCode::Char('/'));
    press(&mut app, KeyCode::Char('p'));
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.listed.len(), 3);
    press(&mut app, KeyCode::Char('G'));
    assert_eq!(app.selected(), 2);
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.filter, JobFilter::Problems);
    assert_eq!(app.selected(), 0);
}

#[test]
fn help_consumes_keys_until_it_closes() {
    let mut app = loaded(Vec::new());
    press(&mut app, KeyCode::Char('?'));
    assert_eq!(press(&mut app, KeyCode::Char('4')), Effect::None);
    assert_eq!(app.tab, Tab::Overview);
    press(&mut app, KeyCode::Char('q'));
    assert!(!app.help);
    assert_eq!(press(&mut app, KeyCode::Char('q')), Effect::Quit);
}

#[test]
fn a_failed_fetch_keeps_the_last_snapshot_and_reports_the_error() {
    let mut app = loaded(Vec::new());
    app.fail("ssh: connection refused", Duration::from_secs(1));
    assert_eq!(app.error.as_deref(), Some("ssh: connection refused"));
    assert_eq!(app.derived().unwrap().snapshot.jobs.len(), 3);
    assert_eq!(app.fetch_ms, Some(1000));
}

fn group(kind: &str, identity: &str, findings: &[String]) -> serde_json::Value {
    json!({"kind": kind, "identity": identity, "findings": findings, "profiles": ["p"],
           "runs": [0], "unresolved": 1})
}

fn with_groups(jobs: Vec<serde_json::Value>, groups: Vec<serde_json::Value>) -> Snapshot {
    parsed(json!({"jobs": jobs,
                                  "failure_groups": groups}))
}

#[test]
fn the_selected_signal_profile_and_group_stay_selected_when_rows_sort_above_them() {
    let mut app = Monitor::new();
    let jobs = vec![
        settled(1, "m", "unsuccessful"),
        settled(2, "n", "unsuccessful"),
    ];
    let groups = vec![
        group("violation", "02bb", &[format!("{}-0001", id(1))]),
        group("violation", "02cc", &[format!("{}-0001", id(2))]),
    ];
    app.feed(with_groups(jobs.clone(), groups.clone()), Duration::ZERO);
    let mut chosen = Vec::new();
    for tab in [Tab::Signals, Tab::Profiles, Tab::Findings] {
        app.tab = tab;
        let last = app.rows(tab) - 1;
        app.select(last);
        chosen.push((last, app.identity(tab, last).unwrap().to_owned()));
    }
    let mut more = vec![settled(0, "a", "violation")];
    more.extend(jobs);
    let mut groups_more = vec![group("violation", "02aa", &[format!("{}-0001", id(0))])];
    groups_more.extend(groups);
    app.feed(with_groups(more, groups_more), Duration::ZERO);
    for (tab, chosen) in [Tab::Signals, Tab::Profiles, Tab::Findings]
        .into_iter()
        .zip(chosen)
    {
        app.tab = tab;
        let (last, chosen) = chosen;
        assert_eq!(
            app.identity(tab, app.selected()),
            Some(chosen.as_str()),
            "{tab:?}"
        );
        assert!(app.selected() > last, "{tab:?} moved down with its item");
    }
}

#[test]
fn a_drilled_focus_follows_jobs_that_join_the_profile_in_a_later_snapshot() {
    let mut app = profiles(3);
    app.select(0);
    let profile = app.derived().unwrap().matrix.rows[0].profile.clone();
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.listed.len(), 1);
    let mut jobs: Vec<_> = app
        .derived()
        .unwrap()
        .snapshot
        .jobs
        .iter()
        .map(|job| {
            json!({"id": job.id, "profile": job.profile, "campaign": "c", "run": job.run,
               "variant": "v", "state": "settled", "result": {"attempt": 1, "class": "pass"},
               "attempts": [{"number": 1, "attempt": format!("{}-0001", job.id)}]})
        })
        .collect();
    jobs.push(
        json!({"id": id(40), "profile": profile, "campaign": "c", "run": 1,
                     "variant": "v", "state": "settled",
                     "result": {"attempt": 1, "class": "pass"},
                     "attempts": [{"number": 1, "attempt": format!("{}-0001", id(40))}]}),
    );
    app.feed(snapshot(jobs), Duration::ZERO);
    assert_eq!(app.listed.len(), 2);
    assert!(listed_ids(&app).contains(&id(40)));
}

#[test]
fn going_back_after_a_reordering_snapshot_selects_the_item_drilled_from() {
    let mut app = profiles(10);
    app.select(4);
    let profile = app.derived().unwrap().matrix.rows[4].profile.clone();
    press(&mut app, KeyCode::Enter);
    let mut jobs: Vec<_> = (3..13)
        .map(|n| settled(n, &format!("profile-{n:03}"), "pass"))
        .collect();
    jobs.push(settled(50, "aaa-first", "violation"));
    app.feed(snapshot(jobs), Duration::ZERO);
    press(&mut app, KeyCode::Backspace);
    assert_eq!(app.tab, Tab::Profiles);
    assert_eq!(
        app.derived().unwrap().matrix.rows[app.selected()].profile,
        profile
    );
}

#[test]
fn escape_in_a_view_search_after_a_reordering_snapshot_returns_to_its_item() {
    let mut app = profiles(10);
    app.select(4);
    let profile = app.derived().unwrap().matrix.rows[4].profile.clone();
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, "zzz");
    let mut jobs: Vec<_> = (3..13)
        .map(|n| settled(n, &format!("profile-{n:03}"), "pass"))
        .collect();
    jobs.push(settled(50, "aaa-first", "violation"));
    app.feed(snapshot(jobs), Duration::ZERO);
    press(&mut app, KeyCode::Esc);
    assert_eq!(
        app.derived().unwrap().matrix.rows[app.selected()].profile,
        profile
    );
}

#[test]
fn enter_on_a_failure_group_focuses_its_jobs_and_backspace_returns() {
    let mut app = Monitor::new();
    let jobs = vec![settled(1, "p", "violation"), settled(2, "q", "violation")];
    let groups = vec![
        group("violation", "02aa", &[format!("{}-0001", id(1))]),
        group("violation", "02bb", &["unknown-0001".to_owned()]),
    ];
    app.feed(with_groups(jobs, groups), Duration::ZERO);
    app.tab = Tab::Findings;
    let row = app
        .groups()
        .iter()
        .position(|group| group.identity.as_deref() == Some("02bb"))
        .unwrap();
    app.select(row);
    press(&mut app, KeyCode::Enter);
    assert_eq!(
        app.tab,
        Tab::Findings,
        "a group that names no job opens nothing"
    );
    assert!(!app.can_go_back());
    app.select(1 - row);
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.tab, Tab::Jobs);
    assert_eq!(listed_ids(&app), vec![id(1)]);
    press(&mut app, KeyCode::Backspace);
    assert_eq!(app.tab, Tab::Findings);
    assert_eq!(app.selected(), 1 - row);
    assert!(app.focus.is_none());
}

#[test]
fn identity_less_groups_of_one_kind_keep_their_own_selection_and_jobs() {
    let mut app = Monitor::new();
    let jobs = vec![settled(1, "p", "violation"), settled(2, "q", "violation")];
    let groups: Vec<_> = [1, 2]
        .into_iter()
        .map(|n| {
            json!({"kind": "watchdog", "identity": null,
                   "findings": [format!("{}-0001", id(n))], "profiles": ["p"],
                   "runs": [0], "unresolved": 1})
        })
        .collect();
    app.feed(with_groups(jobs.clone(), groups.clone()), Duration::ZERO);
    app.tab = Tab::Findings;
    app.select(1);
    let chosen = app.groups()[1].findings.clone();
    let job = chosen[0].strip_suffix("-0001").unwrap().to_owned();
    app.feed(with_groups(jobs, groups), Duration::ZERO);
    assert_eq!(app.selected(), 1, "the second group stays selected");
    assert_eq!(app.groups()[app.selected()].findings, chosen);
    press(&mut app, KeyCode::Enter);
    assert_eq!(listed_ids(&app), vec![job.clone()]);
    let shown = app.shown();
    app.feed(shown, Duration::ZERO);
    assert_eq!(listed_ids(&app), vec![job], "the focus re-resolves to it");
}

#[test]
fn profile_rows_that_differ_only_by_build_keep_their_own_selection_and_jobs() {
    let mut app = Monitor::new();
    let jobs: Vec<_> = ["b1", "b2"]
        .into_iter()
        .enumerate()
        .map(|(n, build)| {
            json!({"id": id(n), "profile": "p", "campaign": "c", "build": build, "run": 0,
                   "variant": "v", "state": "settled",
                   "result": {"attempt": 1, "class": "violation"},
                   "attempts": [{"number": 1, "attempt": format!("{}-0001", id(n))}]})
        })
        .collect();
    app.feed(snapshot(jobs.clone()), Duration::ZERO);
    app.tab = Tab::Profiles;
    assert_eq!(app.rows(Tab::Profiles), 2);
    app.select(1);
    let build = app.derived().unwrap().matrix.rows[1].build.clone();
    app.feed(snapshot(jobs), Duration::ZERO);
    assert_eq!(app.selected(), 1, "the second build's row stays selected");
    press(&mut app, KeyCode::Enter);
    let listed = listed_ids(&app);
    assert_eq!(listed.len(), 1, "{listed:?}");
    let (job, _) = app.job(0).unwrap();
    assert_eq!(job.build, build);
    let label = &app.focus.as_ref().unwrap().label;
    assert!(label.contains(&build), "{label}");
}

#[test]
fn a_profiles_search_finds_a_row_by_its_build() {
    let mut app = Monitor::new();
    let jobs: Vec<_> = ["b1", "b2"]
        .into_iter()
        .enumerate()
        .map(|(n, build)| {
            json!({"id": id(n), "profile": "p", "campaign": "c", "build": build, "run": 0,
                   "variant": "v", "state": "settled",
                   "result": {"attempt": 1, "class": "violation"},
                   "attempts": [{"number": 1, "attempt": format!("{}-0001", id(n))}]})
        })
        .collect();
    app.feed(snapshot(jobs), Duration::ZERO);
    app.tab = Tab::Profiles;
    app.select(0);
    assert_eq!(app.derived().unwrap().matrix.rows[0].build, "b1");
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, "b2");
    press(&mut app, KeyCode::Enter);
    let selected = app.selected();
    assert_eq!(app.derived().unwrap().matrix.rows[selected].build, "b2");
}

#[test]
fn a_job_search_matches_an_id_prefix_whatever_its_case() {
    let mut app = loaded(vec![
        json!({"id": "ABCDEF", "profile": "q", "campaign": "c", "run": 0, "variant": "v",
               "state": "settled", "result": {"attempt": 1, "class": "pass"},
               "attempts": [{"number": 1, "attempt": "ABCDEF-0001"}]}),
    ]);
    app.tab = Tab::Jobs;
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, "abc");
    press(&mut app, KeyCode::Enter);
    assert_eq!(listed_ids(&app), vec!["ABCDEF".to_owned()]);
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, "ABC");
    press(&mut app, KeyCode::Enter);
    assert_eq!(listed_ids(&app), vec!["ABCDEF".to_owned()]);
}

#[test]
fn a_job_search_matches_an_outcome_label_whatever_its_case() {
    let mut app = loaded(vec![
        json!({"id": id(9), "profile": "q", "campaign": "c", "run": 0, "variant": "v",
               "state": "settled", "result": {"attempt": 1, "class": "unsuccessful"},
               "attempts": [{"number": 1, "attempt": format!("{}-0001", id(9)),
                             "sim": {"unsuccessful": "fresh GET missed"}}]}),
    ]);
    app.tab = Tab::Jobs;
    for query in ["get missed", "GET missed", "unsuccessful: fresh"] {
        press(&mut app, KeyCode::Char('/'));
        keys(&mut app, query);
        press(&mut app, KeyCode::Enter);
        assert_eq!(listed_ids(&app), vec![id(9)], "{query}");
    }
}

#[test]
fn a_findings_search_finds_a_group_by_its_identity() {
    let mut app = Monitor::new();
    let jobs = vec![settled(1, "p", "violation"), settled(2, "p", "violation")];
    let groups = vec![
        group("violation", "02aa", &[format!("{}-0001", id(1))]),
        group("violation", "7f3e", &[format!("{}-0001", id(2))]),
    ];
    app.feed(with_groups(jobs, groups), Duration::ZERO);
    app.tab = Tab::Findings;
    app.select(0);
    let identity = |app: &App, row: usize| {
        app.derived().unwrap().snapshot.failure_groups[row]
            .identity
            .clone()
            .unwrap()
    };
    let other = (0..2).find(|&row| identity(&app, row) == "7f3e").unwrap();
    app.select(1 - other);
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, "7f3e");
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.selected(), other);
}

#[test]
fn a_signals_search_finds_a_signal_by_its_detail() {
    let mut app = loaded(vec![
        settled(5, "alpha", "unsuccessful"),
        settled(6, "beta", "unsuccessful"),
        json!({"id": id(7), "held": "job binding differs"}),
    ]);
    app.tab = Tab::Signals;
    let held = app
        .signals()
        .iter()
        .position(|signal| signal.detector == "held-record")
        .unwrap();
    let outcome = app
        .signals()
        .iter()
        .position(|signal| signal.detector == "outcome")
        .unwrap();
    assert!(app.signals()[outcome].detail.contains("alpha"));
    assert!(!app.signals()[outcome].title.contains("alpha"));
    app.select(held);
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, "alpha");
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.selected(), outcome);
}

#[test]
fn a_job_search_finds_an_id_whose_lowercase_form_has_another_byte_length() {
    let mut app = loaded(vec![
        json!({"id": "\u{130}-1", "profile": "q", "campaign": "c", "run": 0, "variant": "v",
               "state": "settled", "result": {"attempt": 1, "class": "pass"},
               "attempts": [{"number": 1, "attempt": "\u{130}-1-0001"}]}),
    ]);
    app.tab = Tab::Jobs;
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, "\u{130}-1");
    press(&mut app, KeyCode::Enter);
    assert_eq!(listed_ids(&app), vec!["\u{130}-1".to_owned()]);
}

#[test]
fn an_unchanged_observation_keeps_the_age_of_its_first_fetch() {
    let mut app = Monitor::new();
    let first = snapshot(vec![settled(1, "p", "pass")]);
    let derived = app.derive(first.clone());
    let now = Instant::now();
    let mut fetch = Fetch::now(Ok(derived), Duration::ZERO);
    fetch.completed = now - Duration::from_secs(100);
    fetch.completed_wall = SystemTime::now() - Duration::from_secs(100);
    app.apply(fetch);
    assert!(app.age(now).unwrap().1, "100 s without a fetch is stale");
    app.feed(first, Duration::ZERO);
    let (age, stale) = app.age(now).unwrap();
    assert!(age >= 99_000, "{age}");
    assert!(stale, "the same observation read again is as old as before");
    let mut later = snapshot(vec![settled(2, "p", "pass")]);
    later.observed_ms += 1;
    app.feed(later, Duration::ZERO);
    let (age, stale) = app.age(now).unwrap();
    assert!(age < 5_000 && !stale, "{age} {stale}");
}

/// Two monitors on one history: a sample the other monitor recorded while
/// this one was fetching decides whether a group is NEW in watch mode too.
#[test]
fn observe_detects_against_the_sample_another_monitor_recorded_during_the_fetch() {
    let dir = std::env::temp_dir().join(format!(
        "campaign-monitor-observe-shared-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("h.jsonl");
    let finding = format!("{}-0001", id(1));
    let with_group = |observed_ms: u64| {
        let mut snapshot = with_groups(
            vec![settled(1, "p", "violation")],
            vec![group("violation", "02aa", std::slice::from_ref(&finding))],
        );
        snapshot.observed_ms = observed_ms;
        snapshot
    };
    let mut stale = History::open(&path).unwrap();
    let mut empty = snapshot(Vec::new());
    empty.observed_ms = 3;
    stale.record(crate::history::Sample::of(&empty)).unwrap();
    let mut other = History::open(&path).unwrap();
    other
        .record(crate::history::Sample::of(&with_group(5)))
        .unwrap();
    let derived = Derived::observe(with_group(7), &mut stale);
    let titles: Vec<&str> = derived
        .signals
        .iter()
        .filter(|signal| signal.detector == "failure-group")
        .map(|signal| signal.title.as_str())
        .collect();
    assert_eq!(titles.len(), 1, "{titles:?}");
    assert!(!titles[0].starts_with("NEW "), "{titles:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn two_drill_downs_go_back_through_both_focuses() {
    let stuck = json!({"id": id(9), "profile": "long", "campaign": "c", "run": 0,
                       "variant": "v", "state": "running",
                       "attempts": [{"number": 1, "attempt": format!("{}-0001", id(9)),
                                     "intent_ms": 1}]});
    let mut app = loaded(vec![stuck]);
    app.tab = Tab::Profiles;
    let row = app
        .derived()
        .unwrap()
        .matrix
        .rows
        .iter()
        .position(|row| row.profile == "long")
        .unwrap();
    app.select(row);
    press(&mut app, KeyCode::Enter);
    let first = app.focus.as_ref().unwrap().label.clone();
    press(&mut app, KeyCode::Char('2'));
    let signal = app
        .signals()
        .iter()
        .position(|signal| signal.detector == "stuck-attempt")
        .unwrap();
    app.select(signal);
    press(&mut app, KeyCode::Enter);
    assert_ne!(app.focus.as_ref().unwrap().label, first);
    control(&mut app, 'o');
    assert_eq!(app.tab, Tab::Signals);
    assert_eq!(app.focus.as_ref().unwrap().label, first);
    control(&mut app, 'o');
    assert_eq!(app.tab, Tab::Profiles);
    assert_eq!(app.selected(), row);
    assert!(app.focus.is_none());
}

#[test]
fn going_back_restores_a_signal_focus_whose_subjects_grew_while_it_was_on_the_stack() {
    let mut app = Monitor::new();
    let jobs = vec![
        settled(1, "a", "unsuccessful"),
        settled(2, "b", "unsuccessful"),
    ];
    app.feed(snapshot(jobs.clone()), Duration::ZERO);
    app.tab = Tab::Signals;
    let row = app
        .signals()
        .iter()
        .position(|signal| signal.detector == "outcome")
        .unwrap();
    app.select(row);
    press(&mut app, KeyCode::Enter);
    let mut listed = listed_ids(&app);
    listed.sort();
    assert_eq!(listed, vec![id(1), id(2)]);
    press(&mut app, KeyCode::Char('3'));
    app.select(0);
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.listed.len(), 1);
    let mut grown = jobs;
    grown.push(settled(3, "c", "unsuccessful"));
    app.feed(snapshot(grown), Duration::ZERO);
    control(&mut app, 'o');
    assert_eq!(app.tab, Tab::Profiles);
    assert!(app.focus.is_some());
    let mut listed = listed_ids(&app);
    listed.sort();
    assert_eq!(listed, vec![id(1), id(2), id(3)]);
}

#[test]
fn f_clears_a_focus_and_the_back_stack_keeps_at_most_its_depth() {
    let mut app = profiles(3);
    for _ in 0..BACK_DEPTH + 5 {
        app.tab = Tab::Profiles;
        press(&mut app, KeyCode::Enter);
    }
    assert_eq!(app.back.len(), BACK_DEPTH);
    assert!(
        app.back[0].focus.is_some(),
        "the first entry, which held no focus, is the one dropped"
    );
    assert!(app.focus.is_some());
    press(&mut app, KeyCode::Char('f'));
    assert!(app.focus.is_none());
    assert_eq!(app.filter, JobFilter::All);
}

#[test]
fn a_search_on_another_tab_leaves_the_jobs_list_and_filter_alone() {
    let mut app = loaded(Vec::new());
    app.tab = Tab::Jobs;
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, "p");
    press(&mut app, KeyCode::Enter);
    let jobs = listed_ids(&app);
    for tab in ['2', '3', '5'] {
        press(&mut app, KeyCode::Char(tab));
        press(&mut app, KeyCode::Char('/'));
        keys(&mut app, "violation");
        press(&mut app, KeyCode::Enter);
        press(&mut app, KeyCode::Esc);
        assert!(app.search(app.tab).is_empty());
    }
    let shown = app.shown();
    app.feed(shown, Duration::ZERO);
    press(&mut app, KeyCode::Char('4'));
    assert_eq!(app.search(Tab::Jobs), "p");
    assert_eq!(listed_ids(&app), jobs);
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.filter, JobFilter::Problems);
}

#[test]
fn two_job_searches_and_two_escapes_restore_the_filter_the_first_replaced() {
    let mut app = loaded(Vec::new());
    app.tab = Tab::Jobs;
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, "p");
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, "p2");
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.search(Tab::Jobs), "p");
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, "p1");
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.filter, JobFilter::All);
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.filter, JobFilter::Problems);
    assert_eq!(listed_ids(&app), vec![id(1)]);
}

#[test]
fn enter_on_an_empty_search_keeps_the_previous_query() {
    let mut app = loaded(Vec::new());
    app.tab = Tab::Jobs;
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, "p");
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('/'));
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.search(Tab::Jobs), "p");
    assert_eq!(app.filter, JobFilter::All);
}

#[test]
fn a_view_search_without_a_match_stays_on_its_origin_and_backspace_searches_again() {
    let mut app = profiles(30);
    app.select(5);
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, "profile-02x");
    assert_eq!(app.selected(), 5);
    press(&mut app, KeyCode::Backspace);
    assert!(
        app.row_text(Tab::Profiles, app.selected())
            .contains("profile-02")
    );
}

#[test]
fn a_seed_sensitive_signal_flags_and_opens_only_its_workload() {
    let workload = |n: usize, variant: &str, class: &str| {
        json!({"id": id(n), "profile": "p", "campaign": "c", "run": n, "variant": variant,
               "seed": n, "state": "settled", "result": {"attempt": 1, "class": class},
               "attempts": [{"number": 1, "attempt": format!("{}-0001", id(n))}]})
    };
    let mut app = Monitor::new();
    let jobs = vec![
        workload(1, "v", "pass"),
        workload(2, "v", "violation"),
        workload(3, "w", "pass"),
    ];
    app.feed(snapshot(jobs), Duration::ZERO);
    let Some(row) = app
        .signals()
        .iter()
        .position(|signal| signal.detector == "seed-sensitive")
    else {
        panic!("{:?}", app.signals());
    };
    assert!(
        app.naming(&id(1))
            .any(|signal| signal.detector == "seed-sensitive")
    );
    assert!(app.flag(&id(3)).is_none());
    app.tab = Tab::Signals;
    app.select(row);
    assert!(app.can_drill());
    press(&mut app, KeyCode::Enter);
    let mut listed = listed_ids(&app);
    listed.sort();
    assert_eq!(listed, vec![id(1), id(2)]);
}

#[test]
fn a_drilled_failure_group_follows_a_finding_added_in_a_later_snapshot() {
    let mut app = Monitor::new();
    let jobs = vec![settled(1, "p", "violation"), settled(2, "q", "violation")];
    let first = vec![group("violation", "02aa", &[format!("{}-0001", id(1))])];
    app.feed(with_groups(jobs.clone(), first), Duration::ZERO);
    app.tab = Tab::Findings;
    press(&mut app, KeyCode::Enter);
    assert_eq!(listed_ids(&app), vec![id(1)]);
    let both = vec![group(
        "violation",
        "02aa",
        &[format!("{}-0001", id(1)), format!("{}-0001", id(2))],
    )];
    app.feed(with_groups(jobs, both), Duration::ZERO);
    let mut listed = listed_ids(&app);
    listed.sort();
    assert_eq!(listed, vec![id(1), id(2)]);
}

#[test]
fn n_on_the_last_matching_row_wraps_to_the_first_match() {
    let mut app = profiles(5);
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, "profile-");
    press(&mut app, KeyCode::Enter);
    let last = app.rows(Tab::Profiles) - 1;
    app.select(last);
    press(&mut app, KeyCode::Char('n'));
    assert!(app.selected() < last);
}

#[test]
fn control_letters_do_not_enter_the_search_query() {
    let mut app = profiles(5);
    press(&mut app, KeyCode::Char('/'));
    control(&mut app, 'u');
    keys(&mut app, "p");
    assert_eq!(app.search(Tab::Profiles), "p");
}

#[test]
fn a_paste_extends_an_open_search_and_is_dropped_otherwise() {
    let mut app = profiles(30);
    app.paste("q");
    assert_eq!(
        app.tab,
        Tab::Profiles,
        "a paste outside a search does nothing"
    );
    press(&mut app, KeyCode::Char('/'));
    app.paste("profile-02");
    assert_eq!(app.search(Tab::Profiles), "profile-02");
    assert!(
        app.row_text(Tab::Profiles, app.selected())
            .contains("profile-02")
    );
}

#[test]
fn the_age_shows_whole_seconds_then_whole_minutes() {
    assert_eq!(age_text(12_345), "12s");
    assert_eq!(age_text(59_999), "59s");
    assert_eq!(age_text(125_000), "2m");
    assert_eq!(age_text(3_725_000), "1h02m");
    assert_eq!(age_text(90_000_000), "1d01h");
    assert_eq!(age_text_lasts(12_345), 655);
    assert_eq!(age_text_lasts(125_000), 55_000);
    assert_eq!(age_text_lasts(91_800_000), 1_800_000);
}

/// The one timer of the loop fires when the shown age string next changes,
/// or when the snapshot turns stale if that comes first, and never without
/// a snapshot.
#[test]
fn the_age_tick_is_due_when_the_shown_age_or_staleness_next_changes() {
    let mut app = Monitor::new();
    let now = Instant::now();
    assert!(app.next_age_change(now).is_none());
    let shown = loaded(Vec::new()).shown();
    app.feed(shown, Duration::ZERO);
    let fetched = app.fetched_at.unwrap();
    let at = fetched + Duration::from_millis(12_300);
    let (age, stale) = app.age(at).unwrap();
    assert_eq!((age_text(age), stale), ("12s".to_owned(), false));
    let tick = app.next_age_change(at).unwrap();
    assert!(tick <= fetched + Duration::from_millis(13_000), "{tick:?}");
    assert_ne!(age_text(app.age(tick).unwrap().0), "12s");
    // A 15 s poll of a 5 ms fetch is due 30 s after it returned. Once the
    // age reads in minutes, the tick still lands on the stale turn.
    app.fetch_ms = Some(0);
    app.snapshot_fetch_ms = Some(0);
    let at = fetched + Duration::from_millis(29_500);
    assert!(!app.age(at).unwrap().1);
    let tick = app.next_age_change(at).unwrap();
    assert!(tick <= fetched + Duration::from_millis(30_001), "{tick:?}");
    let at = fetched + Duration::from_secs(70);
    assert!(app.age(at).unwrap().1, "70 s after a 15 s poll is stale");
    assert_eq!(
        app.next_age_change(at),
        Some(fetched + Duration::from_secs(120))
    );
}

fn flashed(app: &App) -> String {
    app.flash_at(Instant::now())
        .map(|flash| flash.text.clone())
        .unwrap_or_default()
}

/// A key that cannot act says why instead of doing nothing.
#[test]
fn keys_that_cannot_act_flash_the_reason() {
    let mut app = loaded(Vec::new());
    press(&mut app, KeyCode::Char('j'));
    assert!(
        flashed(&app).contains("acts on every list"),
        "{}",
        flashed(&app)
    );
    press(&mut app, KeyCode::Char('2'));
    press(&mut app, KeyCode::Char('f'));
    assert!(
        flashed(&app).contains("f (filter) acts on Jobs"),
        "{}",
        flashed(&app)
    );
    press(&mut app, KeyCode::Char('n'));
    assert!(flashed(&app).contains("need a search"), "{}", flashed(&app));
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, "zzz");
    press(&mut app, KeyCode::Enter);
    press(&mut app, KeyCode::Char('n'));
    assert!(
        flashed(&app).contains("no match for \"zzz\""),
        "{}",
        flashed(&app)
    );
    press(&mut app, KeyCode::Char('4'));
    press(&mut app, KeyCode::Enter);
    assert!(flashed(&app).starts_with("enter:"), "{}", flashed(&app));
    keys(&mut app, "gx");
    assert!(
        flashed(&app).contains("gx is not a key"),
        "{}",
        flashed(&app)
    );
    assert_eq!(app.pending(), None);
}

#[test]
fn a_flash_expires_after_its_deadline_and_wakes_the_loop() {
    let mut app = loaded(Vec::new());
    app.notify(Level::Info, "hello");
    let now = Instant::now();
    let until = app.flash_at(now).unwrap().until;
    assert!(app.next_change(now).unwrap() <= until);
    assert!(app.flash_at(until).is_none());
}

/// `p` holds new snapshots while the shown one stays; resuming applies the
/// newest held one.
#[test]
fn pause_holds_snapshots_until_resume_applies_the_newest() {
    let mut app = loaded(Vec::new());
    press(&mut app, KeyCode::Char('p'));
    assert!(app.paused);
    let jobs = (0..5).map(|n| settled(n, "p", "violation")).collect();
    app.feed(snapshot(jobs), Duration::ZERO);
    app.feed(snapshot(vec![settled(7, "q", "violation")]), Duration::ZERO);
    assert!(app.holding());
    assert_eq!(app.derived().unwrap().snapshot.jobs.len(), 3);
    press(&mut app, KeyCode::Char('p'));
    assert!(!app.paused && !app.holding());
    assert_eq!(app.derived().unwrap().snapshot.jobs.len(), 1);
    assert!(
        app.take_resumed().is_some(),
        "the replaced snapshot is handed back"
    );
}

#[test]
fn y_on_a_failure_group_copies_a_replay_command_that_names_the_cgroup_root() {
    let mut app = Monitor::new();
    let jobs = vec![settled(1, "p", "violation")];
    let finding = format!("{}-0001", id(1));
    let groups = vec![group("violation", "02aa", std::slice::from_ref(&finding))];
    app.feed(with_groups(jobs, groups), Duration::ZERO);
    press(&mut app, KeyCode::Char('5'));
    assert_eq!(
        press(&mut app, KeyCode::Char('y')),
        Effect::Yank(format!(
            "campaign triage --state /state --cgroup-root \"${{CAMPAIGN_CGROUP_ROOT:?}}\" \
             --from-run {finding} --step replay"
        ))
    );
}

#[test]
fn asking_whether_y_can_copy_a_signal_costs_the_same_for_any_subject_count() {
    let named = |subjects: usize| {
        let mut app = Monitor::new();
        let finding = format!("{}-0001", id(1));
        let groups = vec![group("violation", "02aa", &[finding])];
        app.feed(
            with_groups(vec![settled(1, "p", "violation")], groups),
            Duration::ZERO,
        );
        app.tab = Tab::Signals;
        app.data_mut().signals[0].subjects = (0..subjects).map(id).collect();
        app
    };
    let median = |app: &App| {
        let mut times: Vec<Duration> = (0..51)
            .map(|_| {
                let started = std::time::Instant::now();
                assert!(std::hint::black_box(app).can(Action::Yank));
                started.elapsed()
            })
            .collect();
        times.sort();
        times[times.len() / 2]
    };
    let (small, large) = (named(100), named(100_000));
    let floor = median(&small).max(Duration::from_micros(5));
    let asked = median(&large);
    assert!(
        asked <= floor * 10,
        "{asked:?} at 10^5 subjects against {floor:?} at 100"
    );
}

#[test]
fn a_snapshot_held_while_paused_still_clears_the_shown_fetch_error() {
    let mut app = loaded(Vec::new());
    press(&mut app, KeyCode::Char('p'));
    app.fail("ssh: connection refused", Duration::ZERO);
    assert_eq!(app.error.as_deref(), Some("ssh: connection refused"));
    app.feed(snapshot(vec![settled(7, "q", "violation")]), Duration::ZERO);
    assert!(
        app.paused && app.holding(),
        "the snapshot is held, not shown"
    );
    assert_eq!(app.derived().unwrap().snapshot.jobs.len(), 3);
    assert_eq!(app.error, None, "the latest fetch succeeded");
    let mut derived = app.derive(snapshot(vec![settled(8, "q", "violation")]));
    Arc::get_mut(&mut derived).unwrap().history_error = Some("history not recorded: x".into());
    app.apply(Fetch::now(Ok(derived), Duration::ZERO));
    assert!(app.paused && app.holding());
    assert_eq!(app.derived().unwrap().snapshot.jobs.len(), 3);
    assert_eq!(app.error.as_deref(), Some("history not recorded: x"));
    press(&mut app, KeyCode::Char('p'));
    assert_eq!(app.derived().unwrap().snapshot.jobs.len(), 1);
    assert_eq!(app.error.as_deref(), Some("history not recorded: x"));
}

#[test]
fn resuming_keeps_the_error_of_a_fetch_that_failed_after_the_held_snapshot() {
    let mut app = loaded(Vec::new());
    press(&mut app, KeyCode::Char('p'));
    app.feed(snapshot(vec![settled(7, "q", "violation")]), Duration::ZERO);
    app.fail("ssh: connection refused", Duration::ZERO);
    press(&mut app, KeyCode::Char('p'));
    assert_eq!(app.derived().unwrap().snapshot.jobs.len(), 1);
    assert_eq!(app.error.as_deref(), Some("ssh: connection refused"));
    app.feed(snapshot(vec![settled(8, "q", "violation")]), Duration::ZERO);
    assert_eq!(app.error, None, "a later snapshot clears the error");
}

#[test]
fn y_refuses_a_job_id_profile_or_subject_whose_display_form_differs_from_its_value() {
    let mut app = loaded(vec![
        json!({"id": "a\tb", "profile": "p\u{1b}q", "campaign": "c", "run": 0,
               "variant": "v", "state": "settled",
               "result": {"attempt": 1, "class": "violation"},
               "attempts": [{"number": 1, "attempt": "a\tb-0001"}]}),
        json!({"id": "h\tk", "held": "job binding differs"}),
    ]);
    press(&mut app, KeyCode::Char('4'));
    let row = listed_ids(&app)
        .iter()
        .position(|id| id.starts_with('a'))
        .unwrap();
    app.select(row);
    assert_eq!(press(&mut app, KeyCode::Char('y')), Effect::None);
    assert!(
        flashed(&app).contains("control character"),
        "{}",
        flashed(&app)
    );
    press(&mut app, KeyCode::Char('3'));
    let row = app
        .derived()
        .unwrap()
        .matrix
        .rows
        .iter()
        .position(|row| row.profile.contains("\\u{1b}"))
        .unwrap();
    app.select(row);
    assert_eq!(press(&mut app, KeyCode::Char('y')), Effect::None);
    assert!(
        flashed(&app).contains("control character"),
        "{}",
        flashed(&app)
    );
    press(&mut app, KeyCode::Char('2'));
    let row = app
        .signals()
        .iter()
        .position(|signal| signal.detector == "held-record")
        .unwrap();
    app.select(row);
    assert_eq!(press(&mut app, KeyCode::Char('y')), Effect::None);
    assert!(
        flashed(&app).contains("a subject holds a control character"),
        "{}",
        flashed(&app)
    );
}

#[test]
fn y_refuses_subjects_past_the_copy_bound() {
    let mut app = Monitor::new();
    let finding = format!("{}-0001", id(1));
    let groups = vec![group("violation", "02aa", std::slice::from_ref(&finding))];
    app.feed(
        with_groups(vec![settled(1, "p", "violation")], groups),
        Duration::ZERO,
    );
    app.tab = Tab::Signals;
    app.data_mut().signals[0].subjects = (0..17).map(|_| "x".repeat(1 << 20)).collect();
    assert_eq!(press(&mut app, KeyCode::Char('y')), Effect::None);
    assert!(
        flashed(&app).contains("the subjects exceed"),
        "{}",
        flashed(&app)
    );
}

#[test]
fn y_copies_the_selected_job_id_and_flashes_when_nothing_is_selected() {
    let mut app = loaded(Vec::new());
    assert_eq!(press(&mut app, KeyCode::Char('y')), Effect::None);
    assert!(
        flashed(&app).contains("acts on every list"),
        "{}",
        flashed(&app)
    );
    press(&mut app, KeyCode::Char('4'));
    assert_eq!(press(&mut app, KeyCode::Char('y')), Effect::Yank(id(1)));
    assert_eq!(flashed(&app), "copied the job id");
    press(&mut app, KeyCode::Char('/'));
    keys(&mut app, "nothing");
    press(&mut app, KeyCode::Enter);
    assert_eq!(press(&mut app, KeyCode::Char('y')), Effect::None);
    assert!(
        flashed(&app).contains("no job is selected"),
        "{}",
        flashed(&app)
    );
}

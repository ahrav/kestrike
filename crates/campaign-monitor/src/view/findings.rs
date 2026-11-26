//! The Findings tab: failure groups over the selected group's target
//! finding, its copy-paste commands and its member findings.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::text::Line;
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table, TableState, Wrap};

use super::panes::{
    SELECTED, bound, fill, paths_title, rows, rows_of, selection, table_rows, title, window_note,
};
use crate::snapshot::FailureGroup;
use crate::source::shell_quote;
use crate::state::derived::RUNS_WIDTH;
use crate::state::{App, Derived, Tab, replay_command};
use crate::tui::text::{clip, prefix};
use crate::tui::theme::Theme;

pub(super) fn findings(
    frame: &mut Frame,
    table: Rect,
    detail: Rect,
    app: &App,
    d: &Derived,
    t: &Theme,
) {
    let snapshot = &d.snapshot;
    let groups = app.groups();
    let wide = table.width >= 120;
    let height = table_rows(table, 1);
    let (start, end) = app
        .view(Tab::Findings)
        .place(app.selected(), groups.len(), height);
    let rows = groups[start..end]
        .iter()
        .zip(&d.group_summaries[start..end])
        .map(|(group, summary)| {
            let mut cells = vec![
                Cell::from(group.kind.clone()).style(t.error),
                Cell::from(
                    group
                        .cause
                        .as_deref()
                        .map(|cause| {
                            cause
                                .strip_prefix(&format!("{}, ", group.kind))
                                .unwrap_or(cause)
                                .to_owned()
                        })
                        .unwrap_or_default(),
                ),
                Cell::from(summary.profiles.clone()),
                Cell::from(summary.runs.clone()),
                Cell::from(format!("{}/{}", group.unresolved, group.findings.len())),
            ];
            if wide {
                cells.push(
                    Cell::from(
                        group
                            .identity
                            .as_deref()
                            .map_or("-".to_owned(), |id| prefix(id, 16).to_owned()),
                    )
                    .style(t.muted),
                );
            }
            Row::new(cells)
        });
    let mut widths = vec![
        Constraint::Length(10),
        Constraint::Min(20),
        Constraint::Length(20),
        Constraint::Length(RUNS_WIDTH as u16),
        Constraint::Length(5),
    ];
    let mut header = vec!["kind", "cause", "profiles", "runs", "open"];
    if wide {
        widths.push(Constraint::Length(16));
        header.push("identity");
    }
    let mut state = TableState::default().with_selected(Some(app.selected() - start));
    frame.render_stateful_widget(
        Table::new(rows, widths)
            .style(t.text)
            .header(Row::new(header).style(t.heading))
            .row_highlight_style(selection(app, t))
            .highlight_symbol(SELECTED)
            .block(
                Block::bordered()
                    .border_style(t.border_focused)
                    .title(title(
                        [
                            match window_note(start, end, groups.len()) {
                                Some(note) => format!("{} failure groups, {note}", groups.len()),
                                None => format!("{} failure groups", groups.len()),
                            },
                            format!("{} findings", snapshot.findings.len()),
                            format!("{} release blockers", snapshot.release_blockers.len()),
                        ],
                        table.width,
                    )),
            ),
        table,
        &mut state,
    );
    let lines = match groups.get(app.selected()) {
        Some(group) => group_detail(
            group,
            d.group_summaries[app.selected()].target,
            app,
            &snapshot.state,
            usize::from(detail.height.saturating_sub(2)),
            usize::from(detail.width.saturating_sub(2)).max(1),
            t,
        ),
        None => vec![Line::from("no findings")],
    };
    frame.render_widget(
        Paragraph::new(lines).wrap(Wrap { trim: false }).block(
            Block::bordered().border_style(t.border).title(paths_title(
                "group",
                &snapshot.state,
                detail.width,
            )),
        ),
        detail,
    );
}

/// The detail of `group` in `height` rows of `width` columns, around the
/// finding at `target` in `group.findings`. The target finding and its
/// replay and dispose commands are kept first, in the longest form that
/// fits; then the evidence line, then the identity line, then the finding
/// list take the remaining rows in that order, so the list shrinks first
/// when space is short. A state path or finding id whose display text
/// differs from its value, because it held a control character, cannot be
/// pasted as shown, so its commands are left out.
pub(super) fn group_detail(
    group: &FailureGroup,
    target: Option<usize>,
    app: &App,
    state: &str,
    height: usize,
    width: usize,
    t: &Theme,
) -> Vec<Line<'static>> {
    let altered = app.derived().map(|d| &d.altered);
    let altered = |text: &str| altered.is_some_and(|set| set.contains(text));
    let target = target.and_then(|index| group.findings.get(index)).cloned();
    let mut commands: Option<[Line<'static>; 3]> = None;
    let mut evidence = None;
    let mut notice = None;
    match &target {
        Some(id) if altered(id) || altered(state) => {
            notice = Some(
                Line::from(format!(
                    "▸ {id}: the id or state path holds a control character; take the commands from `check --json`"
                ))
                .style(t.muted),
            );
        }
        Some(id) => {
            let quoted = shell_quote(id);
            let state = shell_quote(state);
            let shown_id = if width >= 160 {
                quoted.clone()
            } else {
                "<id>".to_owned()
            };
            let line = |text: String| Line::from(text).style(t.muted);
            let dispose = "--disposition resolved|harness|release-blocker --evidence <text>";
            let forms = [
                [
                    line(format!("▸ <id> = {quoted}")),
                    line(format!("  replay    {}", replay_command(&state, &shown_id))),
                    line(format!(
                        "  dispose   campaign dispose --state {state} --finding {shown_id} {dispose}"
                    )),
                ],
                [
                    line(format!("▸ <id> = {quoted}")),
                    line(format!("  {}", replay_command(&state, "<id>"))),
                    line(format!(
                        "  campaign dispose --state {state} --finding <id> --disposition <d> --evidence <text>"
                    )),
                ],
                [
                    line(format!("▸ <id> = {}", clip(&quoted, width.saturating_sub(9)))),
                    line(format!("  {}", replay_command("<state>", "<id>"))),
                    line(
                        "  campaign dispose --state <state> --finding <id> --disposition <d> --evidence <text>"
                            .to_owned(),
                    ),
                ],
            ];
            let [.., last] = &forms;
            let last = last.clone();
            commands = Some(
                forms
                    .into_iter()
                    .find(|form| rows_of(form, width) <= height)
                    .unwrap_or(last),
            );
            evidence = Some(line(format!(
                "  evidence  findings/{shown_id}/  triage/{shown_id}/steps/"
            )));
        }
        None => {}
    }
    let fixed = commands.as_ref().map_or(0, |lines| rows_of(lines, width))
        + notice.as_ref().map_or(0, |line| rows(line, width));
    let mut room = height.saturating_sub(fixed);
    let evidence = evidence.filter(|line| rows(line, width) <= room);
    if let Some(line) = &evidence {
        room -= rows(line, width);
    }
    let mut lines = Vec::new();
    let identity = Line::from(format!(
        "identity {}{}",
        group
            .identity
            .as_deref()
            .map_or("-".to_owned(), |id| clip(id, 25)),
        group
            .failure_virtual_us
            .map(|us| format!(" · first failure at virtual_us {us}"))
            .unwrap_or_default()
    ))
    .style(t.muted);
    if rows(&identity, width) <= room {
        lines.push(identity);
    }
    let members = group.findings.iter().map(|id| {
        let row = app.finding(id);
        let profile = row.and_then(|row| row.profile()).unwrap_or("?");
        let run = row
            .and_then(|row| row.run())
            .map_or("?".to_owned(), |run| run.to_string());
        let triage = row.map_or("?", |row| row.triage_state());
        let decision = row.and_then(|row| row.decision()).unwrap_or("undisposed");
        let marker = if target.as_ref() == Some(id) {
            "▸"
        } else {
            " "
        };
        vec![Line::from(format!(
            "{marker} {} · {} run {run} · triage {triage} · {}",
            clip(id, 17),
            profile,
            decision
        ))]
    });
    let total = group.findings.len();
    let shown = fill(&mut lines, members, total, room, width);
    if shown < total && rows_of(&lines, width) < room {
        lines.push(Line::from(format!("  {} more findings", total - shown)).style(t.muted));
    }
    lines.extend(notice);
    if let Some([finding, replay, dispose]) = commands {
        lines.push(finding);
        lines.extend(evidence);
        lines.extend([replay, dispose]);
    }
    bound(lines, height, width, "enlarge the pane for the commands", t)
}

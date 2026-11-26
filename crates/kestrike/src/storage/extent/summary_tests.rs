//! The tests use summaries computed directly from 11-unit bitmaps as the oracle for summary updates.
//!
//! The bitmap oracle detects incorrect summaries at ties, node edges, boundary-crossing runs, and nodes extending past the volume.

use super::summary::{Summary, joined, split};

const UNITS: u64 = 11;

/// The summary of units `n0..n1` of `free`, where units past `free`'s length are taken.
fn read(free: &[bool], n0: u64, n1: u64) -> Summary {
    let at = |u: u64| free.get(u as usize).copied().unwrap_or(false);
    let start = (n0..n1).take_while(|&u| at(u)).count() as u64;
    let end = (n0..n1).rev().take_while(|&u| at(u)).count() as u64;
    let (mut max, mut run) = (0, 0);
    for u in n0..n1 {
        run = if at(u) { run + 1 } else { 0 };
        max = max.max(run);
    }
    Summary { start, max, end }
}

fn bitmaps() -> impl Iterator<Item = Vec<bool>> {
    (0..1u32 << UNITS).map(|bits| (0..UNITS).map(|u| bits >> u & 1 == 1).collect())
}

fn runs(free: &[bool]) -> Vec<(u64, u64)> {
    let mut found = Vec::new();
    let mut u = 0;
    while u < free.len() {
        if free[u] {
            let low = u;
            while u < free.len() && free[u] {
                u += 1;
            }
            found.push((low as u64, u as u64));
        }
        u += 1;
    }
    found
}

fn nodes() -> impl Iterator<Item = (u64, u64)> {
    (0..UNITS).flat_map(|n0| (n0 + 1..=UNITS + 2).map(move |n1| (n0, n1)))
}

#[test]
fn a_join_gives_the_summary_of_the_bitmap_after_it_in_every_node_it_overlaps() {
    let (mut crossing, mut edge, mut past_volume) = (0, 0, 0);
    for now in bitmaps() {
        for (low, high) in runs(&now) {
            let width = high - low;
            for taken in 1..1u32 << width {
                let mut was = now.clone();
                for i in 0..width {
                    if taken >> i & 1 == 1 {
                        was[(low + i) as usize] = false;
                    }
                }
                for (n0, n1) in nodes().filter(|&(n0, n1)| low < n1 && n0 < high) {
                    let got = joined(low, high, read(&was, n0, n1), n0, n1);
                    assert_eq!(
                        got,
                        read(&now, n0, n1),
                        "join {low}..{high} over {n0}..{n1} from {was:?}"
                    );
                    crossing += usize::from(low < n0 || high > n1);
                    edge += usize::from(low == n0 || high == n1);
                    past_volume += usize::from(n1 > UNITS);
                }
            }
        }
    }
    assert!(
        crossing > 0 && edge > 0 && past_volume > 0,
        "{crossing} {edge} {past_volume}"
    );
}

#[test]
fn a_split_is_exact_when_it_answers_and_answers_every_node_the_run_covers() {
    let (mut exact, mut covered, mut edge, mut recomputed, mut ties) = (0, 0, 0, 0, 0);
    let (mut crossing, mut past_volume) = (0, 0);
    for was in bitmaps() {
        let all = runs(&was);
        for &(low, high) in &all {
            for start in low..high {
                for end in start + 1..=high {
                    let mut now = was.clone();
                    now[start as usize..end as usize].fill(false);
                    for (n0, n1) in nodes().filter(|&(n0, n1)| start < n1 && n0 < end) {
                        let old = read(&was, n0, n1);
                        let part = high.min(n1) - low.max(n0);
                        edge += usize::from(low == n0 || high == n1);
                        crossing += usize::from(low < n0 || high > n1);
                        past_volume += usize::from(n1 > UNITS);
                        match split([low, start, end, high], old, n0, n1) {
                            Some(sum) => {
                                assert_eq!(
                                    sum,
                                    read(&now, n0, n1),
                                    "split {start}..{end} of {low}..{high} over {n0}..{n1} in {was:?}"
                                );
                                exact += 1;
                                covered += usize::from(low <= n0 && n1 <= high);
                            }
                            None => {
                                assert!(
                                    part >= old.max,
                                    "a recomputation follows only a longest run's split"
                                );
                                assert!(
                                    !(low <= n0 && n1 <= high),
                                    "a covered node gets its summary"
                                );
                                recomputed += 1;
                                ties += usize::from(read(&now, n0, n1).max == old.max);
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(
        exact > 0
            && covered > 0
            && edge > 0
            && crossing > 0
            && past_volume > 0
            && recomputed > 0
            && ties > 0,
        "{exact} {covered} {edge} {crossing} {past_volume} {recomputed} {ties}"
    );
}

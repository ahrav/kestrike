//! The mapping from a variant's construction sites to its measured state.
//!
//! A site's [`Evidence`] comes from the coverage region at `site.at`, which
//! can be `Region::Uncounted`. A [`Form::Eager`] or [`Form::Value`] site
//! whose own region counts zero takes that zero; otherwise it uses the region
//! at its chain-ending `?` (`site.chain`, set under `ok_or` and `map_err`
//! alone) when the export counts that position, and a
//! positive `?` count for a site with `branch` set is
//! [`Evidence::Evaluated`]. A site of another form whose own region is
//! uncounted, inside a closure whose `site.outer` has count zero, takes
//! `Evidence::Constructed(0)`: the error-path closure never ran. `place`
//! reads [`Form::Compare`] and [`Form::Table`] sites as references to a
//! variant and measures the variant's other sites.

use crate::coverage::{Coverage, Region};
use crate::source::{Form, Site};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Reached,
    Unreached,
    Unplaced,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            Self::Reached => "reached",
            Self::Unreached => "unreached",
            Self::Unplaced => "unplaced",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Measured {
    /// Every file holding a read site has zero covered lines.
    FileNotRun,
    /// At least one file holding a read site has a covered line, and every
    /// function span holding a read site has entry count zero.
    FunctionNotEntered,
    /// At least one function span holding a read site has a nonzero entry
    /// count, every counted read site has count zero, and each read site in
    /// an entered function has a count.
    NotConstructed,
}

impl Measured {
    pub fn name(self) -> &'static str {
        match self {
            Self::FileNotRun => "file-not-run",
            Self::FunctionNotEntered => "function-not-entered",
            Self::NotConstructed => "not-constructed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// Every site is a comparison or a table, or the variant has no site.
    NoSite,
    /// Every counted read site has count zero, and a read site in an
    /// entered function resolves to `Region::Uncounted`.
    NoRegion,
    /// At least one function span holding a read site has a nonzero entry
    /// count, at least one read site has a positive count, and every such
    /// site is an eager argument or a function value whose count is its own
    /// region or a `?` count that it shares with other branches.
    Unplaceable,
}

impl Cause {
    pub fn name(self) -> &'static str {
        match self {
            Self::NoSite => "no-site",
            Self::NoRegion => "no-region",
            Self::Unplaceable => "unplaceable",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement {
    pub state: State,
    /// The summed count of the sites whose count stands for a construction.
    pub count: u64,
    pub measured: Option<Measured>,
    pub cause: Option<Cause>,
}

/// `Evidence` classifies a site's coverage count as a construction count,
/// an evaluation count, or unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Evidence {
    /// The count stands for the site's constructions and adds to the
    /// variant's reached count.
    Constructed(u64),
    /// The count is an eager argument's own region or a `?` count shared
    /// with other branches, so it can exceed the site's constructions. A
    /// positive one earns no reach and makes an entered variant
    /// [`Cause::Unplaceable`].
    Evaluated(u64),
    /// The site's count is unknown. A site in an entered function with this
    /// evidence makes the variant [`Cause::NoRegion`].
    Uncounted,
}

fn evidence(site: &Site, coverage: &Coverage) -> Evidence {
    let own = coverage.region(&site.file, site.at);
    if matches!(site.form, Form::Eager | Form::Value) {
        if own == Region::Count(0) {
            return Evidence::Constructed(0);
        }
        if let Some(chain) = site.chain
            && let Region::Count(count) = coverage.region(&site.file, chain)
        {
            return if site.branch && count > 0 {
                Evidence::Evaluated(count)
            } else {
                Evidence::Constructed(count)
            };
        }
        return match own {
            Region::Count(count) => Evidence::Evaluated(count),
            Region::Uncounted => Evidence::Uncounted,
        };
    }
    if own == Region::Uncounted
        && let Some(outer) = site.outer
        && coverage.region(&site.file, outer) == Region::Count(0)
    {
        return Evidence::Constructed(0);
    }
    match own {
        Region::Count(count) => Evidence::Constructed(count),
        Region::Uncounted => Evidence::Uncounted,
    }
}

/// # Errors
///
/// `place` returns `Err` when the construction counts of `sites` sum past
/// `u64::MAX`.
pub fn place(sites: &[&Site], coverage: &Coverage) -> Result<Placement, String> {
    let read: Vec<&Site> = sites
        .iter()
        .copied()
        .filter(|site| site.form.constructs())
        .collect();
    let unplaced = |cause| {
        Ok(Placement {
            state: State::Unplaced,
            count: 0,
            measured: None,
            cause: Some(cause),
        })
    };
    if read.is_empty() {
        return unplaced(Cause::NoSite);
    }
    let evidence: Vec<Evidence> = read.iter().map(|site| evidence(site, coverage)).collect();
    let count = evidence
        .iter()
        .filter_map(|evidence| match evidence {
            Evidence::Constructed(count) => Some(*count),
            _ => None,
        })
        .try_fold(0_u64, u64::checked_add)
        .ok_or_else(|| {
            let site = read[0];
            format!(
                "{}::{}: the construction counts sum past {}",
                site.file,
                site.variant,
                u64::MAX
            )
        })?;
    if count > 0 {
        return Ok(Placement {
            state: State::Reached,
            count,
            measured: None,
            cause: None,
        });
    }
    let entered = read
        .iter()
        .any(|site| coverage.entered(&site.file, site.at));
    let executed_weak = evidence
        .iter()
        .any(|evidence| matches!(evidence, Evidence::Evaluated(1..)));
    let unknown = read.iter().zip(&evidence).any(|(site, evidence)| {
        *evidence == Evidence::Uncounted && coverage.entered(&site.file, site.at)
    });
    if entered && executed_weak {
        return unplaced(Cause::Unplaceable);
    }
    if unknown {
        return unplaced(Cause::NoRegion);
    }
    let measured = if !read.iter().any(|site| coverage.file_ran(&site.file)) {
        Measured::FileNotRun
    } else if !entered {
        Measured::FunctionNotEntered
    } else {
        Measured::NotConstructed
    };
    Ok(Placement {
        state: State::Unreached,
        count: 0,
        measured: Some(measured),
        cause: None,
    })
}

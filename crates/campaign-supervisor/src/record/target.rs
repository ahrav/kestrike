//! Corpus inputs and fork bounds frozen into targeted job records.

use super::{Digest, Text};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "FormFields", into = "FormFields")]
/// A branch fixes its suffix and sibling counts; exploration fixes its manifest-derived tree limits.
pub enum ForkForm {
    Branch {
        siblings: u64,
        suffixes: u64,
    },
    Explore {
        advances: u64,
        children: u64,
        depth: u64,
        faults: u64,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FormFields {
    advances: Option<u64>,
    children: Option<u64>,
    depth: Option<u64>,
    faults: Option<u64>,
    form: Text,
    siblings: Option<u64>,
    suffixes: Option<u64>,
}

impl From<ForkForm> for FormFields {
    fn from(form: ForkForm) -> Self {
        let mut fields = Self {
            advances: None,
            children: None,
            depth: None,
            faults: None,
            form: Text::new(form.command()).expect("fork form is ASCII"),
            siblings: None,
            suffixes: None,
        };
        match form {
            ForkForm::Branch { siblings, suffixes } => {
                fields.siblings = Some(siblings);
                fields.suffixes = Some(suffixes);
            }
            ForkForm::Explore {
                advances,
                children,
                depth,
                faults,
            } => {
                fields.advances = Some(advances);
                fields.children = Some(children);
                fields.depth = Some(depth);
                fields.faults = Some(faults);
            }
        }
        fields
    }
}

impl TryFrom<FormFields> for ForkForm {
    type Error = &'static str;
    fn try_from(fields: FormFields) -> Result<Self, Self::Error> {
        let form = match (
            fields.form.as_str(),
            fields.siblings,
            fields.suffixes,
            fields.advances,
            fields.children,
            fields.depth,
            fields.faults,
        ) {
            ("branch", Some(siblings), Some(suffixes), None, None, None, None) => {
                Self::Branch { siblings, suffixes }
            }
            ("explore", None, None, Some(advances), Some(children), Some(depth), Some(faults)) => {
                Self::Explore {
                    advances,
                    children,
                    depth,
                    faults,
                }
            }
            _ => return Err("fork form fields differ"),
        };
        if form.children().is_none() {
            return Err("fork bounds exceed worker limits");
        }
        Ok(form)
    }
}

impl ForkForm {
    pub(crate) fn leaf_name(path: &str) -> String {
        format!("leaf-{path}.bundle")
    }

    pub fn command(&self) -> &'static str {
        match self {
            Self::Branch { .. } => "branch",
            Self::Explore { .. } => "explore",
        }
    }
    pub fn children(&self) -> Option<u64> {
        match *self {
            Self::Branch { siblings, suffixes }
                if (1..=4).contains(&siblings) && (1..=16).contains(&suffixes) =>
            {
                Some(siblings * suffixes)
            }
            Self::Explore {
                children,
                depth,
                advances,
                faults,
            } if children > 0 && (1..=128).contains(&depth) && advances > 0 && faults > 0 => {
                let (mut level, mut total) = (1u64, 0u64);
                for _ in 0..depth {
                    level = level.checked_mul(children)?;
                    if level > 128 {
                        return None;
                    }
                    total += level;
                }
                let largest = (children - 1).to_string();
                let path = vec![largest.as_str(); depth as usize].join(".");
                crate::store::Name::new(&Self::leaf_name(&path)).map(|_| total)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Frozen corpus prefix, original seed, fork bounds and archived build.
/// These experiment facts determine targeted identity independently of catalog version.
pub struct Target {
    pub asset: Digest,
    pub boundary: u64,
    pub build: Digest,
    pub bundle: Digest,
    pub bytes: u64,
    pub decisions: u64,
    pub form: ForkForm,
    pub manifest: Digest,
    pub milestone: Text,
    pub prefix: Digest,
    pub root: u64,
    pub semantic: u64,
}

impl Target {
    pub(crate) fn valid(&self) -> bool {
        self.root > 0
            && self.bytes > 0
            && self.bytes.is_multiple_of(48)
            && !self.milestone.as_str().is_empty()
            && !self.milestone.as_str().starts_with("recovery-")
            && self.form.children().is_some()
    }
    pub fn shares(&self) -> u64 {
        self.form.children().unwrap_or(0) + 1
    }
}

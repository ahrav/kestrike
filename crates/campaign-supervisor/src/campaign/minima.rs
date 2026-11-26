//! Frozen minima parse into one decimal count per distinct `COVERAGE` dimension, so admission, calibration and the report read one grammar.

use super::{Error, text};
use crate::record::Text;
use std::collections::BTreeMap;

pub(super) fn parse(frozen: &Text) -> Result<BTreeMap<Text, u64>, Error> {
    let mut minima = BTreeMap::new();
    for field in frozen.as_str().split(',') {
        let (key, count) = field
            .split_once(':')
            .ok_or_else(|| Error::Held("frozen minima malformed".into()))?;
        let count = count
            .parse::<u64>()
            .map_err(|_| Error::Held("frozen minimum is not a count".into()))?;
        if !crate::protocol::COVERAGE.contains(&key) || minima.insert(text(key)?, count).is_some() {
            return Err(Error::Held("frozen minimum dimension invalid".into()));
        }
    }
    Ok(minima)
}

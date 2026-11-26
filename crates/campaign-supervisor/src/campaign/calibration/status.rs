use super::{Error, contract, name};
use crate::record::{Calibration, CalibrationPlan, Digest};
use crate::store::View;

pub(in crate::campaign) fn status(view: &View) -> Result<Vec<serde_json::Value>, Error> {
    let Some(roots) = view.open_dir(view.root(), &name("calibrations"))? else {
        return Ok(Vec::new());
    };
    let mut rows = Vec::new();
    for entry in view.list(&roots, crate::scan_bound())? {
        let checked = (|| -> Result<serde_json::Value, Error> {
            let root = view
                .open_dir(&roots, &entry)?
                .ok_or_else(|| Error::Held("calibration root vanished".into()))?;
            let id = Digest::parse(entry.as_str())
                .ok_or_else(|| Error::Held("calibration identity filename invalid".into()))?;
            let Some(plan) = view.read_record::<CalibrationPlan>(&root, &name("plan"))? else {
                if !view.list(&root, crate::scan_bound())?.is_empty() {
                    return Err(Error::Held("calibration plan missing".into()));
                }
                return Ok(
                    serde_json::json!({"id": id,"missing": ["calibration plan is missing"],"verdict": "uncalibrated"}),
                );
            };
            if plan.record().healthy.job().id().digest() != id {
                return Err(Error::Held("calibration plan root differs".into()));
            }
            let scoped = contract(plan.record())?;
            let Some(result) = view.read_record::<Calibration>(&root, &name("result"))? else {
                return Ok(
                    serde_json::json!({"contract": scoped,"id": id,"missing": ["calibration result is missing"],"verdict": "unsealed"}),
                );
            };
            if result.record().root != id || result.record().contract != scoped {
                return Err(Error::Held("calibration result binding differs".into()));
            }
            Ok(
                serde_json::json!({"contract": scoped,"id": id,"verdict": result.record().verdict,"verified": result.record()}),
            )
        })();
        rows.push(match checked {
            Ok(row) => row,
            Err(error) if error.at_scan_bound() => return Err(error),
            Err(error) => serde_json::json!({"held": error.to_string(),"id": entry.as_str(),"verdict": "held"}),
        });
    }
    Ok(rows)
}

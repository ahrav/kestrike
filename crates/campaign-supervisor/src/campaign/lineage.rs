//! A child finding stays verified only while its bound parent attempt still
//! reports the child. One listing or triage selection reuses a parent's
//! successful verification for sibling child findings frozen under the same
//! admission.

use super::Error;
use crate::record::{Admission, Artifact, Attempt, ChildEvidence, Digest, Finding, Finished};
use crate::store::ReadStore;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

#[derive(Clone)]
pub(super) struct Parent {
    pub(super) admission: Admission,
    pub(super) attempt: Attempt,
    pub(super) finished: Finished,
    pub(super) artifact: Artifact,
    pub(super) children: Option<Vec<ChildEvidence>>,
}

type Verification = Arc<OnceLock<Option<Arc<Parent>>>>;

/// Concurrent readers of one parent attempt wait for its first verification
/// and reuse its success when admissions match. After the first verification
/// fails, subsequent readers verify independently.
#[derive(Default)]
pub(super) struct Parents(Mutex<BTreeMap<(Digest, u64), Verification>>);

impl Parents {
    pub(super) fn get(
        &self,
        finding: &Finding,
        verify: impl Fn() -> Result<Parent, Error>,
    ) -> Result<Arc<Parent>, Error> {
        let key = (finding.attempt.job, finding.attempt.number);
        let cell = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(key)
            .or_default()
            .clone();
        let mut failure = None;
        let cached = cell.get_or_init(|| match verify() {
            Ok(parent) => Some(Arc::new(parent)),
            Err(error) => {
                failure = Some(error);
                None
            }
        });
        if let Some(error) = failure {
            return Err(error);
        }
        match cached {
            Some(parent) if parent.admission == finding.admission => Ok(Arc::clone(parent)),
            _ => verify().map(Arc::new),
        }
    }
}

fn parent(view: &impl ReadStore, finding: &Finding) -> Result<Parent, Error> {
    let root = crate::layout::attempts(view, &finding.attempt.job.to_string())?
        .ok_or_else(|| Error::Held("child parent job missing".into()))?;
    let (_, attempt, completed) =
        crate::attempt::completed_at(view, &finding.admission, &root, finding.attempt.number)
            .map_err(Error::from)?;
    let bound = completed
        .bound()
        .ok_or_else(|| Error::Held("child parent evidence missing".into()))?;
    Ok(Parent {
        admission: finding.admission.clone(),
        attempt: attempt.record().clone(),
        finished: completed.finished().record().clone(),
        artifact: bound.artifact().clone(),
        children: bound.targeted().map(|judged| judged.children.clone()),
    })
}

pub(super) fn verify(
    view: &impl ReadStore,
    finding: &Finding,
    parents: &Parents,
) -> Result<(), Error> {
    let Some(child) = &finding.child else {
        return Ok(());
    };
    let parent = parents.get(finding, || parent(view, finding))?;
    let fact = ChildEvidence {
        bundle: None,
        ..child.clone()
    };
    if parent.attempt != finding.attempt
        || parent.finished != finding.finished
        || finding.artifact.as_ref() != Some(&parent.artifact)
        || !parent
            .children
            .as_ref()
            .is_some_and(|children| children.contains(&fact))
    {
        return Err(Error::Held(
            "child differs from its bound parent evidence".into(),
        ));
    }
    Ok(())
}

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;

use crate::failover::attachments::{ControlPlane, InstanceId, Unlisted};
use crate::failover::loss::{CreateError, Provider};
use crate::failover::records::{
    EventKind, Host, Layout, Namespace, Record, VolumeId, VolumeRecord,
};
use crate::failover::report::MAX_LEN;
use crate::failover::standbys::Zone;
use crate::failover::zone_loop::evidence::{Instance, VolumeCondition};
use crate::failover::zone_loop::sources::{
    AttachRefusal, AttachReply, Attacher, DetachReply, InstanceSource, ListedVolume, ReportSource,
    Unreachable, VolumeSource, Witness,
};
use crate::storage::store::sim::Shared;
use crate::storage::store::{Item, Key, Outcome, Store, Unavailable, Write};

/// Each `Event` represents one request to `World` or a store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Event {
    Report(Host),
    Instances,
    Volumes,
    Attachments(VolumeId),
    Attach(VolumeId, InstanceId),
    Detach(VolumeId, InstanceId),
    Read(Key),
    Write(Key),
}

/// `Log` records `World` and store requests in arrival order.
pub(crate) type Log = Rc<RefCell<Vec<Event>>>;

#[derive(Debug, Default)]
pub(crate) struct Faults {
    pub(crate) reports: BTreeSet<Host>,
    pub(crate) instances: bool,
    pub(crate) volumes: bool,
    pub(crate) attachments: bool,
    /// The replies of the next attach requests, in order; a request past the list attaches and is accepted.
    pub(crate) attach: VecDeque<AttachFault>,
    /// The replies of the next detach requests, in order; a request past the list detaches and is accepted.
    pub(crate) detach: VecDeque<DetachFault>,
}

/// A scripted detach reply: an unknown reply after a detach that `detached` says landed or did not, or an accepted
/// detach whose instance the listing keeps showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DetachFault {
    Unknown { detached: bool },
    Lingers,
}

/// A scripted attach reply. `Refuse` preserves attachment state and returns `Refused(AttachRefusal::Other)`. For
/// `Unknown`, `attached` specifies whether the attach takes effect. `Unlanded` preserves attachment state and returns
/// `Accepted`. `Listed` attaches and returns `AlreadyListed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttachFault {
    Refuse,
    Unknown { attached: bool },
    Unlanded,
    Listed,
}

/// `World` shares zone state across host reports, instance listings, volume listings, and per-volume attachment
/// listings.
pub(crate) struct World {
    pub(crate) zone: Zone,
    pub(crate) instances: Vec<Instance>,
    pub(crate) volumes: Vec<ListedVolume>,
    pub(crate) reports: BTreeMap<Host, Vec<u8>>,
    pub(crate) faults: Faults,
    pub(crate) log: Log,
    /// The store an attach request's STANDBY-WRITE-ORDER check reads, when the test sets one.
    pub(crate) store: Option<Shared>,
    /// Each attach request whose volume record held no live, unenrolled entry bound to its instance, and each detach
    /// request that [`World::detached`] refuses.
    pub(crate) breaks: Vec<String>,
    /// The volume provider. A volume it creates lists available with no attachment.
    pub(crate) provider: Provisioner,
}

impl World {
    pub(crate) fn new(zone: Zone) -> Self {
        Self {
            zone,
            instances: Vec::new(),
            volumes: Vec::new(),
            reports: BTreeMap::new(),
            faults: Faults::default(),
            log: Log::default(),
            store: None,
            breaks: Vec::new(),
            provider: Provisioner::default(),
        }
    }

    pub(crate) fn events(&self) -> Vec<Event> {
        self.log.borrow().clone()
    }

    fn record(&self, event: Event) {
        self.log.borrow_mut().push(event);
    }

    /// New listings start with an empty attachment list; condition updates preserve existing attachments.
    pub(crate) fn volume(&mut self, volume: VolumeId, condition: VolumeCondition) {
        match self
            .volumes
            .iter_mut()
            .find(|listed| listed.volume == volume)
        {
            Some(listed) => listed.condition = condition,
            None => self.volumes.push(ListedVolume {
                volume,
                condition,
                attachments: Vec::new(),
            }),
        }
    }

    fn listed(&mut self, volume: VolumeId) -> &mut ListedVolume {
        let found = self
            .volumes
            .iter_mut()
            .find(|listed| listed.volume == volume);
        found.unwrap_or_else(|| panic!("{volume:?} is not listed"))
    }

    pub(crate) fn attach(&mut self, volume: VolumeId, instance: InstanceId) {
        let listed = self.listed(volume);
        listed.attachments.push(instance.as_str().to_owned());
    }

    pub(crate) fn detach(&mut self, volume: VolumeId, instance: InstanceId) {
        let listed = self.listed(volume);
        listed
            .attachments
            .retain(|attached| attached != instance.as_str());
    }
}

impl ReportSource for World {
    fn latest(&mut self, host: Host) -> Result<Option<Vec<u8>>, Unreachable> {
        self.record(Event::Report(host));
        if self.faults.reports.contains(&host) {
            return Err(Unreachable);
        }
        let bytes = self.reports.get(&host);
        Ok(bytes.map(|bytes| bytes[..bytes.len().min(MAX_LEN + 1)].to_vec()))
    }
}

impl InstanceSource for World {
    fn instances(&mut self, zone: Zone) -> Result<Vec<Instance>, Unlisted> {
        self.record(Event::Instances);
        assert_eq!(zone, self.zone);
        match self.faults.instances {
            true => Err(Unlisted),
            false => Ok(self.instances.clone()),
        }
    }
}

impl VolumeSource for World {
    fn volumes(&mut self, zone: Zone) -> Result<Vec<ListedVolume>, Unlisted> {
        self.record(Event::Volumes);
        assert_eq!(zone, self.zone);
        match self.faults.volumes {
            true => Err(Unlisted),
            false => Ok(self.volumes.clone()),
        }
    }
}

impl ControlPlane for World {
    fn attachments(&mut self, volume: &VolumeId) -> Result<Vec<String>, Unlisted> {
        self.record(Event::Attachments(*volume));
        if self.faults.attachments {
            return Err(Unlisted);
        }
        let listed = self.volumes.iter().find(|listed| listed.volume == *volume);
        listed
            .map(|listed| listed.attachments.clone())
            .ok_or(Unlisted)
    }
}

impl World {
    /// A detach request of `instance` from `volume`, checked against DETACH-AFTER-DROP: the store's volume record must
    /// hold the instance's entry as its host's latest, either ended with no recorded pair, or gone with no attach or
    /// ended entry bound to the instance (DETACH-RELISTED).
    pub(crate) fn detached(&mut self, volume: VolumeId, instance: InstanceId) -> DetachReply {
        self.record(Event::Detach(volume, instance));
        if let Some(store) = &self.store {
            let item = store.0.borrow().current(&Key::Volume(volume)).cloned();
            let held = item.and_then(|item| VolumeRecord::decode(&item.value).ok());
            let dropped = held.is_some_and(|held| {
                let bound = held.events.iter().any(|event| {
                    event.instance == Some(instance)
                        && matches!(event.kind, EventKind::Attach | EventKind::Ended)
                });
                held.events.iter().any(|event| {
                    let latest = held
                        .latest(event.host)
                        .is_some_and(|(seq, _)| seq == event.seq);
                    let ended = event.kind == EventKind::Ended
                        && held.pinned(event.host, event.seq).is_none();
                    let relisted = event.kind == EventKind::Gone && !bound;
                    event.instance == Some(instance) && latest && (ended || relisted)
                })
            });
            if !dropped {
                self.breaks.push(format!(
                    "detach of {} from {volume:?} before its pair's drop",
                    instance.as_str()
                ));
            }
        }
        match self.faults.detach.pop_front() {
            None => {
                self.detach(volume, instance);
                DetachReply::Accepted
            }
            Some(DetachFault::Lingers) => DetachReply::Accepted,
            Some(DetachFault::Unknown { detached }) => {
                if detached {
                    self.detach(volume, instance);
                }
                DetachReply::Unknown
            }
        }
    }
}

impl Provider for World {
    /// Creates through `provider`, after recording a break for a token that no committed version of a replacement
    /// receipt in `store` shows issued (CREATE-AFTER-ISSUE).
    fn create(&mut self, token: &str, layout: Layout) -> Result<VolumeId, CreateError> {
        if let Some(store) = &self.store {
            let store = store.0.borrow();
            let replacements = store
                .keys()
                .filter(|key| matches!(key, Key::Replacement(_)));
            let issued = replacements
                .flat_map(|key| store.versions(key))
                .any(|item| {
                    let receipt = crate::failover::loss::Receipt::decode(&item.value);
                    receipt.is_ok_and(|receipt| {
                        receipt.phase == crate::failover::loss::Phase::Issued
                            && receipt.token() == token
                    })
                });
            if !issued {
                drop(store);
                self.breaks
                    .push(format!("create of {token} before its issue write"));
            }
        }
        let created = self.provider.create(token, layout);
        let made = (self.provider.created.iter())
            .find(|(made, _)| made == token)
            .map(|&(_, volume)| volume);
        if let Some(volume) = made
            && self.volumes.iter().all(|listed| listed.volume != volume)
        {
            let available = VolumeCondition {
                state: crate::failover::zone_loop::evidence::ListedVolumeState::Available,
                status: crate::failover::zone_loop::evidence::VolumeStatus::Ok,
            };
            self.volume(volume, available);
        }
        created
    }
}

impl Attacher for World {
    fn detach(&mut self, witness: Witness<'_>) -> DetachReply {
        self.detached(witness.volume(), witness.instance())
    }

    fn attach(&mut self, volume: VolumeId, instance: InstanceId) -> AttachReply {
        self.record(Event::Attach(volume, instance));
        if let Some(store) = &self.store {
            let item = store.0.borrow().current(&Key::Volume(volume)).cloned();
            let held = item.and_then(|item| VolumeRecord::decode(&item.value).ok());
            let recorded = held.is_some_and(|held| {
                let replacement = held.state == crate::failover::records::VolumeState::Fresh
                    && held.pairs.is_empty()
                    && matches!(held.events.as_slice(), [event] if event.kind == EventKind::Attach);
                replacement
                    || held.live_hosts().any(|host| {
                        let entry = held.live(host).and_then(|seq| held.event(seq));
                        entry.is_some_and(|entry| {
                            entry.kind == EventKind::Attach
                                && entry.instance == Some(instance)
                                && held.enrolled(host).is_none()
                        })
                    })
            });
            if !recorded {
                self.breaks.push(format!(
                    "attach of {} to {volume:?} before its entry",
                    instance.as_str()
                ));
            }
        }
        let attach = |world: &mut Self| {
            let listed = world.listed(volume);
            if !listed.attachments.iter().any(|id| id == instance.as_str()) {
                listed.attachments.push(instance.as_str().to_owned());
            }
        };
        match self.faults.attach.pop_front() {
            None => {
                attach(self);
                AttachReply::Accepted
            }
            Some(AttachFault::Refuse) => AttachReply::Refused(AttachRefusal::Other),
            Some(AttachFault::Unlanded) => AttachReply::Accepted,
            Some(AttachFault::Listed) => {
                attach(self);
                AttachReply::AlreadyListed
            }
            Some(AttachFault::Unknown { attached }) => {
                if attached {
                    attach(self);
                }
                AttachReply::Unknown
            }
        }
    }
}

/// `Provisioner` assigns volume IDs in creation order and reuses each token's ID on retries. Tokens in `failed` have
/// outcome `Failed`. For the next `unsent` creates with undecided tokens, `Provisioner` returns `Unknown` before
/// deciding the outcome. Of the creates that reach an outcome, the next `lose` return `Unknown`. `calls` counts the
/// creates, and `layouts` records the token and layout of every create, including those that return `Unknown`.
#[derive(Default)]
pub(crate) struct Provisioner {
    pub(crate) created: Vec<(String, VolumeId)>,
    pub(crate) layouts: Vec<(String, Layout)>,
    pub(crate) failed: Vec<String>,
    pub(crate) unsent: usize,
    pub(crate) lose: usize,
    pub(crate) calls: usize,
}

impl Provider for Provisioner {
    fn create(&mut self, token: &str, layout: Layout) -> Result<VolumeId, CreateError> {
        self.calls += 1;
        assert!(
            self.layouts.iter().all(|(t, l)| t != token || *l == layout),
            "token {token} met another layout"
        );
        self.layouts.push((token.to_owned(), layout));
        let kept = self.created.iter().find(|(t, _)| t == token);
        if self.unsent > 0 && kept.is_none() && !self.failed.iter().any(|t| t == token) {
            self.unsent -= 1;
            return Err(CreateError::Unknown);
        }
        let outcome = if self.failed.iter().any(|t| t == token) {
            Err(CreateError::Failed)
        } else {
            Ok(match kept {
                Some(&(_, volume)) => volume,
                None => {
                    let volume = VolumeId::new(&format!("vol-0c{}", self.created.len())).unwrap();
                    self.created.push((token.to_owned(), volume));
                    volume
                }
            })
        };
        if self.lose > 0 {
            self.lose -= 1;
            return Err(CreateError::Unknown);
        }
        outcome
    }
}

/// A store that logs every request's key before it forwards the request.
pub(crate) struct Recording<S> {
    pub(crate) inner: S,
    pub(crate) log: Log,
}

impl<S: Store> Store for Recording<S> {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        self.log.borrow_mut().push(Event::Read(*key));
        self.inner.read(key)
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        self.log.borrow_mut().push(Event::Write(*key));
        self.inner.write(key, write)
    }

    fn namespace(&self) -> Namespace {
        self.inner.namespace()
    }
}

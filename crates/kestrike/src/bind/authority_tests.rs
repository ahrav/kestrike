use super::authority::AttachAuthority;
use super::fixture::Fixture;
use super::mappings_tests;
use super::record_step::{RecordStep, SCRIPT, Script, Scripted};
use super::{Mappings, Metadata, OwnerLock};
use crate::failover::admission::{AdmissionError, FreshError};
use crate::failover::assignment::{Assignment, AuthenticatedAssignment};
use crate::failover::assignment_tests::{HOST_KEY, other_record, record, sample, verified};
use crate::failover::record::{LocalRecord, RecordError};
use crate::failover::restart::Local;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub(crate) struct Setup {
    pub(crate) lock: OwnerLock,
    host: Fixture,
    pub(crate) state: PathBuf,
}
impl Setup {
    pub(crate) fn new() -> Self {
        Self::seeded(&record())
    }
    /// A setup whose local record is a differently bound record the fresh path draws over: the record of attachment `attach-0` of the sample instance and volume. An earlier attachment of one volume is a retirement trigger the fresh-acquisition preconditions check; here it serves only as a valid record of another binding.
    fn earlier() -> Self {
        Self::seeded(&earlier_record())
    }
    fn seeded(seed: &LocalRecord) -> Self {
        let host = Fixture::new(512);
        let state = std::env::var_os("HOME")
            .map_or_else(|| std::env::current_dir().unwrap(), PathBuf::from)
            .join(".tmp/kestrike-authority-tests")
            .join(host.root.file_name().unwrap());
        super::prepare_state_dir(&state, fs::metadata("/proc/self").unwrap().uid()).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let mut lock = OwnerLock::acquire(&state).unwrap();
        mappings_tests::sample(None)
            .write(&state.join("mappings"))
            .unwrap();
        lock.persist_local(seed).unwrap();
        private(&state.join("host.key"), &HOST_KEY);
        private(
            &state.join("assignment"),
            &sample().sign(&HOST_KEY).unwrap(),
        );
        Self { host, state, lock }
    }
    pub(crate) fn host(&self) -> &super::Host {
        &self.host.host
    }
    fn prepare(&mut self) -> Result<AttachAuthority, AdmissionError> {
        self.lock
            .prepare_verified(&self.host.host, &Placement, assignment())
    }
}
impl Drop for Setup {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.state).unwrap();
    }
}
fn private(path: &Path, bytes: &[u8]) {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    f.write_all(bytes).unwrap();
}
fn assignment() -> AuthenticatedAssignment {
    verified(&sample())
}
/// Instance metadata that a refusal ahead of the metadata checks never reaches.
struct Unreached;
impl Metadata for Unreached {
    fn get(&self, path: &str) -> io::Result<String> {
        panic!("a refused admission reached the instance metadata at {path}")
    }
}
/// Instance metadata naming the sample assignment's instance and availability zone.
pub(crate) struct Placement;
impl Metadata for Placement {
    fn get(&self, path: &str) -> io::Result<String> {
        Ok(match path {
            "instance-id" => sample().instance,
            "placement/availability-zone" => sample().az,
            _ => panic!("unexpected metadata path"),
        })
    }
}
#[test]
fn fresh_records_activate_without_assignment_admission() {
    use crate::failover::fresh::Refusals;
    use crate::failover::fresh::tests::{self, Card, Log};
    use crate::failover::restart::LocalSource;
    use crate::storage::store_tests::{client, shard};
    for stale in [false, true] {
        let setup = owner_setup();
        fs::remove_file(setup.state.join("host.key")).unwrap();
        fs::remove_file(setup.state.join("assignment")).unwrap();
        if stale {
            private(&setup.state.join("assignment"), &[0; 658]);
        }
        let store = tests::store(tests::shard_record(0), tests::volume_record());
        let log = Log::default();
        let mut card = Card::new(&log);
        let mut local = owner_records(&setup);
        let activated = tests::fresh_of(shard(), tests::holder())
            .run(
                &mut client(&store),
                &mut tests::plane(),
                &mut local,
                &mut card,
                &mut Refusals::default(),
            )
            .unwrap();
        assert!(activated.fencing().coverage().is_some());
        assert_eq!(local.local().unwrap(), tests::local_record());
        assert_eq!(
            log.borrow().as_slice(),
            ["host", "register", "acquire", "report", "write", "read"]
        );
    }
}

#[test]
fn fresh_records_retain_refusal_across_adapter_recreation() {
    use crate::failover::fresh::LocalRecords;
    use crate::failover::fresh::tests::holder;
    use crate::failover::restart::LocalSource;
    let mut setup = Setup::new();
    let prepared = {
        let mut local = fresh_records(&setup);
        let prepared = local.persist(&holder(), 0, record().pair().key).unwrap();
        local.retain_refusal(&prepared).unwrap();
        prepared
    };
    assert_eq!(
        LocalRecord::decode(&fs::read(marker_path(&setup, &record())).unwrap()),
        Ok(prepared)
    );
    assert_eq!(setup.lock.local(), Err(Local::Retained));
    assert_eq!(setup.prepare().unwrap_err(), AdmissionError::Retained);
    assert_eq!(
        setup.lock.prepare_fresh_verified(
            &setup.host.host,
            &Placement,
            &assignment(),
            0,
            crate::failover::identity::Key::attachment(assignment().fields().incarnation),
            || -> Result<(), ()> { panic!("a retained refusal runs no compare-and-swap") },
        ),
        Err(FreshError::Admission(AdmissionError::Retained))
    );
    let mut local = fresh_records(&setup);
    assert_eq!(local.local(), Err(Local::Retained));
    assert_eq!(
        local.persist(&holder(), 0, record().pair().key),
        Err(AdmissionError::Retained)
    );
    let unmarked = Setup::new();
    let mut local = fresh_records(&unmarked);
    assert_eq!(local.local(), Ok(record()));
    local.key = crate::failover::identity::Key::attachment(
        crate::failover::identity::Incarnation::new(900).unwrap(),
    );
    assert_eq!(local.local(), Err(Local::Binding));
    local.key = record().pair().key;
    local.binding.attachment = "attach-replacement".into();
    assert_eq!(local.local(), Err(Local::Binding));
}

#[test]
fn fresh_records_release_refusal_removes_only_the_own_marker() {
    use crate::failover::fresh::LocalRecords;
    use crate::failover::restart::LocalSource;
    let setup = Setup::new();
    let path = marker_path(&setup, &record());
    let mut local = fresh_records(&setup);
    assert_eq!(local.release_refusal(&record()), Ok(()));
    local.retain_refusal(&record()).unwrap();
    assert_eq!(
        local.release_refusal(&other_record()),
        Err(AdmissionError::Binding)
    );
    assert!(path.exists());
    for step in [RecordStep::Unlink, RecordStep::DirectorySync] {
        SCRIPT.set(Some(Script {
            outcomes: vec![(step, Scripted::Errno(libc::EIO))],
            reached: vec![],
            observe: Box::new(|_| {}),
        }));
        let released = local.release_refusal(&record());
        SCRIPT.take().unwrap();
        assert_eq!(released, Err(AdmissionError::DurableWrite), "{step:?}");
        assert!(path.exists(), "{step:?}");
    }
    assert_eq!(local.local(), Err(Local::Retained));
    assert_eq!(local.release_refusal(&record()), Ok(()));
    assert!(!path.exists());
    assert_eq!(local.local(), Ok(record()));
}

/// Each mismatch of the holder, the binding, the instance metadata or the mappings file refuses `persist` with its
/// own error, and the authority file remains unchanged.
#[test]
fn fresh_records_persist_refuses_each_mismatch_before_writing() {
    use crate::failover::attachments::InstanceId;
    use crate::failover::fresh::LocalRecords;
    use crate::failover::fresh::tests::holder;
    use crate::failover::poll::Holder;
    use crate::failover::record::Binding;
    struct Instance(String);
    impl Metadata for Instance {
        fn get(&self, path: &str) -> io::Result<String> {
            assert_eq!(path, "instance-id");
            Ok(self.0.clone())
        }
    }
    let own = record().binding().instance.clone();
    let unchanged = |_: &mut Mappings| {};
    let eni_only = |m: &mut Mappings| {
        m.nvme = None;
        m.eni = Some(mappings_tests::eni(1));
    };
    let other_instance = |m: &mut Mappings| m.instance = "i-0fffffffffffffff0".into();
    let other_boot = |m: &mut Mappings| m.boot = "new-boot".into();
    let other_nvme =
        |m: &mut Mappings| m.nvme.as_mut().unwrap().volume = "vol-0fffffffffffffff0".into();
    let mut other_volume = holder();
    other_volume.volume = crate::failover::records::VolumeId::new("vol-ff").unwrap();
    let mut other_host_instance = holder();
    other_host_instance.instance = InstanceId::new("i-0fffffffffffffff0").unwrap();
    let mut other_binding = record().binding().clone();
    other_binding.instance = "i-0fffffffffffffff0".into();
    let same = record().binding().clone();
    type Case<'a> = (
        &'a str,
        &'a str,
        &'a dyn Fn(&mut Mappings),
        Holder,
        Binding,
        AdmissionError,
    );
    let cases: Vec<Case<'_>> = vec![
        (
            "instance metadata",
            "i-0fffffffffffffff0",
            &unchanged,
            holder(),
            same.clone(),
            AdmissionError::Instance,
        ),
        (
            "holder volume",
            &own,
            &unchanged,
            other_volume,
            same.clone(),
            AdmissionError::Binding,
        ),
        (
            "holder instance",
            &own,
            &unchanged,
            other_host_instance,
            same.clone(),
            AdmissionError::Binding,
        ),
        (
            "binding instance",
            &own,
            &unchanged,
            holder(),
            other_binding,
            AdmissionError::Binding,
        ),
        (
            "eni only",
            &own,
            &eni_only,
            holder(),
            same.clone(),
            AdmissionError::Volume,
        ),
        (
            "mappings instance",
            &own,
            &other_instance,
            holder(),
            same.clone(),
            AdmissionError::Binding,
        ),
        (
            "mappings boot",
            &own,
            &other_boot,
            holder(),
            same.clone(),
            AdmissionError::Binding,
        ),
        (
            "nvme volume",
            &own,
            &other_nvme,
            holder(),
            same,
            AdmissionError::Volume,
        ),
    ];
    for (name, instance, mappings, holder, binding, expected) in cases {
        let mut setup = Setup::new();
        let mut written = mappings_tests::sample(None);
        mappings(&mut written);
        if written != mappings_tests::sample(None) {
            written.write(&setup.state.join("mappings")).unwrap();
        }
        let before = snapshot(&setup);
        let metadata = Instance(instance.to_owned());
        let mut local = super::authority::FreshRecords {
            lock: &mut setup.lock,
            host: &setup.host.host,
            metadata: &metadata,
            binding,
            key: record().pair().key,
        };
        assert_eq!(
            local.persist(&holder, 0, record().pair().key),
            Err(expected),
            "{name}"
        );
        assert_eq!(snapshot(&setup), before, "{name}");
    }
}

pub(crate) fn marker_path(setup: &Setup, record: &LocalRecord) -> PathBuf {
    setup.state.join(super::authority::refusal_name(
        record.binding(),
        record.pair().key.incarnation(),
    ))
}

/// A marker's file name stays stable across releases, so a marker an earlier build wrote still refuses.
#[test]
fn the_refusal_marker_name_is_stable() {
    assert_eq!(
        super::authority::refusal_name(record().binding(), record().pair().key.incarnation()),
        "authority-refused-72e3efb853a82d9dae7c93ba4a9e299f5b401c038022d432b7ac05e53fb0b280"
    );
}

pub(crate) fn fresh_records(setup: &Setup) -> super::authority::FreshRecords<'_> {
    super::authority::FreshRecords {
        lock: &setup.lock,
        host: &setup.host.host,
        metadata: &Placement,
        binding: record().binding().clone(),
        key: record().pair().key,
    }
}

/// A setup seeded with the fresh owner's record under the key of entry 0, the one key the volume record admits for a
/// fresh owner's first pair, beside the assignment its issuer signs for entry 0, which carries incarnation 1, so a
/// connect admits the record.
pub(crate) fn owner_setup() -> Setup {
    let setup = Setup::seeded(&crate::failover::fresh::tests::local_record());
    let path = setup.state.join("assignment");
    fs::remove_file(&path).unwrap();
    let assignment = Assignment {
        incarnation: crate::failover::fresh::tests::local_record()
            .pair()
            .key
            .incarnation(),
        ..sample()
    };
    private(&path, &assignment.sign(&HOST_KEY).unwrap());
    setup
}

/// The adapter of [`owner_setup`]'s record, which draws a new record under entry 0's key.
pub(crate) fn owner_records(setup: &Setup) -> super::authority::FreshRecords<'_> {
    super::authority::FreshRecords {
        key: crate::failover::fresh::tests::local_record().pair().key,
        ..fresh_records(setup)
    }
}

#[test]
fn refusal_marker_blocks_delayed_unknown_bump_rerun_and_post_fb_restart() {
    use crate::failover::fresh::tests::{self, Card, Log};
    use crate::failover::fresh::{Check, Refusals};
    use crate::failover::restart;
    use crate::storage::store::Key;
    use crate::storage::store::sim::Arm;
    use crate::storage::store_tests::{client, shard};
    for post_fb in [false, true] {
        let setup = owner_setup();
        let original = fs::read(setup.state.join("authority")).unwrap();
        let store = tests::store(tests::shard_record(0), tests::volume_record());
        if !post_fb {
            for arm in [Arm::Pass, Arm::Pass, Arm::Pass, Arm::Hold] {
                store.schedule(arm);
            }
        }
        let log = Log::default();
        let mut card = Card::new(&log);
        if post_fb {
            card.fail = Some("write");
        }
        let refused = {
            let mut local = owner_records(&setup);
            tests::fresh_of(shard(), tests::holder())
                .run(
                    &mut client(&store),
                    &mut tests::plane(),
                    &mut local,
                    &mut card,
                    &mut Refusals::default(),
                )
                .unwrap_err()
        };
        assert!(matches!(
            refused.check,
            Check::Bump(crate::storage::store::StoreError::Unknown) | Check::Write(_)
        ));
        assert_eq!(fs::read(setup.state.join("authority")).unwrap(), original);
        assert_eq!(
            LocalRecord::decode(&fs::read(marker_path(&setup, &tests::local_record())).unwrap()),
            Ok(tests::local_record())
        );
        let before = log.borrow().clone();
        let mut local = owner_records(&setup);
        let again = tests::fresh_of(shard(), tests::holder())
            .run(
                &mut client(&store),
                &mut tests::plane(),
                &mut local,
                &mut card,
                &mut Refusals::default(),
            )
            .unwrap_err();
        assert_eq!(
            again.check,
            if post_fb {
                Check::Restart
            } else {
                Check::Persist(AdmissionError::Retained)
            }
        );
        let rerun_request = again.retirement(tests::holder().volume);
        assert_eq!(rerun_request.is_some(), !post_fb);
        if !post_fb {
            assert_eq!(store.0.borrow().commit_count(&Key::Shard(shard())), 1);
            store.release();
        }
        let restarted = restart::tests::restart_of(shard(), tests::holder())
            .run(&mut client(&store), &local, &mut card)
            .unwrap_err();
        assert_eq!(
            restarted.check,
            restart::Check::Local(restart::Local::Retained)
        );
        assert_eq!(*log.borrow(), before);
        let current = client(&store)
            .read::<crate::failover::records::ShardRecord>(Key::Shard(shard()))
            .unwrap();
        assert_eq!(current.value().attempts, 1);
        assert_eq!(store.0.borrow().commit_count(&Key::Shard(shard())), 2);
        let request = refused.retirement(tests::holder().volume).unwrap();
        assert!(request.admit(current.value()).is_ok());
        if let Some(rerun_request) = rerun_request {
            assert!(
                rerun_request.admit(current.value()).is_ok(),
                "the rerun's request admits the late commit of the held bump"
            );
        }
    }
}

#[test]
fn refusal_marker_write_failures_at_fb_stop_activation_before_the_medium_write() {
    use crate::failover::fresh::LocalRecords;
    use crate::failover::fresh::tests::{self, Card, Log};
    use crate::failover::fresh::{Check, Refusals};
    use crate::storage::store_tests::{client, shard};
    for step in WRITE
        .into_iter()
        .filter(|step| *step != RecordStep::TemporaryUnlink)
    {
        let setup = owner_setup();
        let store = tests::store(tests::shard_record(0), tests::volume_record());
        let log = Log::default();
        let mut card = Card::new(&log);
        SCRIPT.set(Some(Script {
            outcomes: vec![(step, Scripted::Pass), (step, Scripted::Errno(libc::EIO))],
            reached: vec![],
            observe: Box::new(|_| {}),
        }));
        let mut monitor = Refusals::default();
        let authority = setup.state.join("authority");
        let mut local = owner_records(&setup);
        let refused = tests::fresh_of(shard(), tests::holder())
            .run(
                &mut client(&store),
                &mut tests::plane(),
                &mut local,
                &mut card,
                &mut monitor,
            )
            .unwrap_err();
        SCRIPT.take().unwrap();
        assert_eq!(
            refused.check,
            Check::Hold(AdmissionError::DurableWrite),
            "{step:?}"
        );
        assert_eq!(
            (monitor.before_commands, monitor.before_fb, monitor.after_fb),
            (0, 0, 1)
        );
        assert_eq!(
            log.borrow().as_slice(),
            ["host", "register", "acquire", "report"]
        );
        assert!(!authority.exists());
        let before = log.borrow().clone();
        let restarted = crate::failover::restart::tests::restart_of(shard(), tests::holder())
            .run(&mut client(&store), &local, &mut card)
            .unwrap_err();
        assert!(matches!(
            restarted.check,
            crate::failover::restart::Check::Local(crate::failover::restart::Local::Absent)
        ));
        assert_eq!(*log.borrow(), before);
        let current = client(&store)
            .read::<crate::failover::records::ShardRecord>(crate::storage::store::Key::Shard(
                shard(),
            ))
            .unwrap();
        assert_eq!(current.value().attempts, 1);
        drop(local);
        let landed = matches!(step, RecordStep::DirectoryOpen | RecordStep::DirectorySync);
        assert_eq!(
            marker_path(&setup, &tests::local_record()).exists(),
            landed,
            "{step:?}"
        );
        let rerun =
            owner_records(&setup).persist(&tests::holder(), 0, tests::local_record().pair().key);
        if landed {
            assert_eq!(rerun, Err(AdmissionError::Retained), "{step:?}");
        } else {
            assert!(rerun.is_ok(), "{step:?}: {rerun:?}");
        }
    }
}

/// After a post-FB refusal, restart stays blocked even when state-file creation and `authority` removal fail with
/// `EROFS` from the medium write on. Restart leaves `E` unchanged, so the refusal's retirement request stays
/// admissible.
#[test]
fn a_post_fb_refusal_blocks_restart_when_the_filesystem_fails_from_the_medium_write_on() {
    use crate::failover::fresh::tests::{self, Card, Log};
    use crate::failover::fresh::{Check, Refusals};
    use crate::failover::records::ShardRecord;
    use crate::failover::restart;
    use crate::storage::store::Key;
    use crate::storage::store_tests::{client, shard};
    let setup = owner_setup();
    let store = tests::store(tests::shard_record(0), tests::volume_record());
    let log = Log::default();
    let mut card = Card::new(&log);
    card.fail = Some("write");
    card.on = Some((
        "write",
        Box::new(|| {
            SCRIPT.set(Some(Script {
                outcomes: vec![
                    (RecordStep::Create, Scripted::Errno(libc::EROFS)),
                    (RecordStep::Unlink, Scripted::Errno(libc::EROFS)),
                ],
                reached: vec![],
                observe: Box::new(|_| {}),
            }));
        }),
    ));
    let refused = {
        let mut local = owner_records(&setup);
        tests::fresh_of(shard(), tests::holder())
            .run(
                &mut client(&store),
                &mut tests::plane(),
                &mut local,
                &mut card,
                &mut Refusals::default(),
            )
            .unwrap_err()
    };
    let script = SCRIPT.take().unwrap();
    assert_eq!(
        refused.check,
        Check::Write(crate::failover::restart::Failed(None))
    );
    assert!(
        script.reached.is_empty(),
        "the refusal reaches no state-directory step"
    );
    let request = refused.retirement(tests::holder().volume).unwrap();
    let before = log.borrow().clone();
    let local = owner_records(&setup);
    let restarted = restart::tests::restart_of(shard(), tests::holder())
        .run(&mut client(&store), &local, &mut card)
        .map(drop)
        .unwrap_err();
    assert_eq!(
        restarted.check,
        restart::Check::Local(restart::Local::Retained)
    );
    assert_eq!(*log.borrow(), before, "restart issues no device command");
    let current = client(&store)
        .read::<ShardRecord>(Key::Shard(shard()))
        .unwrap();
    assert_eq!(current.value().attempts, 1);
    assert!(request.admit(current.value()).is_ok());
}

/// KEY-PER-ATTACH through the adapter: a fresh run whose local record would carry another key than the volume record
/// admits refuses `Persist(Key)` before any record step or store write request. The assignment's incarnation-2 record
/// and a kept record under epoch 6 stay byte for byte, an absent record stays absent, and the volume record, `E` and
/// the device stay unchanged. After the refusal over an absent record, a run of the same binding under entry 0's key
/// activates on the same store, and a kept epoch-6 record whose pair the volume record holds replays and activates
/// with no enrollment write.
#[test]
fn a_fresh_record_under_another_key_than_entry_0s_refuses_before_any_write() {
    use crate::failover::fresh::tests::{self, Card, Log};
    use crate::failover::fresh::{Check, Refusals};
    use crate::failover::records::{RecordedPair, ShardRecord, VolumeRecord};
    use crate::storage::store::sim::{Counting, MemLog, Requests};
    use crate::storage::store::{Client, Key};
    use crate::storage::store_tests::{client, shard};
    let epoch_6 = LocalRecord::fresh(
        record().binding().clone(),
        crate::failover::identity::Key::decode((6 << 32) | 1).unwrap(),
        || Some([9; 16]),
    )
    .unwrap();
    let volume = tests::volume_record().volume;
    let counting = |store: &crate::storage::store::sim::Shared, requests: &Requests| {
        Client::open(
            Counting {
                store: store.clone(),
                requests: requests.clone(),
            },
            MemLog::default(),
        )
        .unwrap()
    };
    fn run<S: crate::storage::store::Store, L: crate::storage::store::WatermarkLog>(
        setup: &mut Setup,
        store: &mut Client<S, L>,
        adapter_key: crate::failover::identity::Key,
        card: &mut Card,
    ) -> (
        Result<crate::failover::fresh::Activated, crate::failover::fresh::Refused>,
        Vec<RecordStep>,
    ) {
        let mut refused = None;
        let steps = reached(|| {
            refused = Some(tests::fresh_of(shard(), tests::holder()).run(
                store,
                &mut tests::plane(),
                &mut super::authority::FreshRecords {
                    key: adapter_key,
                    ..fresh_records(setup)
                },
                card,
                &mut Refusals::default(),
            ));
        });
        (refused.unwrap(), steps)
    }
    for (name, seed, adapter_key) in [
        (
            "assignment incarnation 2",
            Some(record()),
            record().pair().key,
        ),
        ("absent record", None, record().pair().key),
        (
            "kept epoch 6",
            Some(epoch_6.clone()),
            tests::local_record().pair().key,
        ),
    ] {
        let mut setup = Setup::seeded(seed.as_ref().unwrap_or(&record()));
        let authority = setup.state.join("authority");
        if seed.is_none() {
            fs::remove_file(&authority).unwrap();
        }
        let before = fs::read(&authority).ok();
        let store = tests::store(tests::shard_record(0), tests::volume_record());
        let requests = Requests::default();
        let mut counted = counting(&store, &requests);
        let log = Log::default();
        let (refused, steps) = run(&mut setup, &mut counted, adapter_key, &mut Card::new(&log));
        let refused = refused.unwrap_err();
        assert_eq!(refused.check, Check::Persist(AdmissionError::Key), "{name}");
        assert!(steps.is_empty(), "{name}: {steps:?}");
        assert_eq!(requests.seen().1, 0, "{name}: no store write request");
        assert_eq!(fs::read(&authority).ok(), before, "{name}");
        assert!(log.borrow().is_empty(), "{name}: no device command");
        let mut held = client(&store);
        assert_eq!(
            held.read::<VolumeRecord>(Key::Volume(volume))
                .unwrap()
                .value(),
            &tests::volume_record(),
            "{name}"
        );
        assert_eq!(
            held.read::<ShardRecord>(Key::Shard(shard()))
                .unwrap()
                .value()
                .attempts,
            0,
            "{name}"
        );
        if seed.is_some() {
            continue;
        }
        let mut card = Card::new(&log);
        card.own = None;
        let (activated, _) = run(
            &mut setup,
            &mut counting(&store, &Requests::default()),
            tests::local_record().pair().key,
            &mut card,
        );
        activated.unwrap_or_else(|refused| panic!("{name}: {refused:?}"));
        let written = LocalRecord::decode(&fs::read(&authority).unwrap()).unwrap();
        assert_eq!(written.pair().key, tests::local_record().pair().key);
        let mut held = client(&store);
        assert_eq!(
            held.read::<VolumeRecord>(Key::Volume(volume))
                .unwrap()
                .value()
                .enrolled(tests::holder().host),
            Some(written.pair())
        );
        assert_eq!(
            held.read::<ShardRecord>(Key::Shard(shard()))
                .unwrap()
                .value()
                .attempts,
            1
        );
    }
    let mut setup = Setup::seeded(&epoch_6);
    let authority = setup.state.join("authority");
    let before = fs::read(&authority).unwrap();
    let store = tests::store(
        tests::shard_record(0),
        VolumeRecord {
            pairs: vec![RecordedPair {
                host: tests::holder().host,
                pair: epoch_6.pair(),
                attach: 0,
            }],
            ..tests::volume_record()
        },
    );
    let log = Log::default();
    let mut card = Card::new(&log);
    card.own = Some(epoch_6.pair());
    let (activated, _) = run(
        &mut setup,
        &mut counting(&store, &Requests::default()),
        tests::local_record().pair().key,
        &mut card,
    );
    activated.unwrap();
    assert_eq!(
        fs::read(&authority).unwrap(),
        before,
        "the kept record replays"
    );
    assert_eq!(store.0.borrow().commit_count(&Key::Volume(volume)), 1);
}

#[test]
fn refusal_marker_read_failure_and_wrong_identity_fail_closed_without_overwrite() {
    use crate::failover::fresh::LocalRecords;
    use crate::failover::fresh::tests::holder;
    use crate::failover::restart::LocalSource;
    for fault in ["mode", "torn", "identity"] {
        let setup = Setup::new();
        let path = marker_path(&setup, &record());
        let bytes = if fault == "identity" {
            other_record().encode().unwrap()
        } else {
            record().encode().unwrap()
        };
        private(&path, &bytes);
        if fault == "mode" {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }
        if fault == "torn" {
            fs::write(&path, [0; 512]).unwrap();
        }
        let before = fs::read(&path).unwrap();
        let mut local = fresh_records(&setup);
        let refusal = local.persist(&holder(), 0, record().pair().key);
        if fault == "identity" {
            assert_eq!(refusal, Err(AdmissionError::Binding));
        } else {
            assert!(
                matches!(refusal, Err(AdmissionError::RecordCodec(_))),
                "{fault}: {refusal:?}"
            );
        }
        assert_eq!(local.local(), Err(Local::Unreadable), "{fault}");
        assert_eq!(
            local.retain_refusal(&record()),
            refusal.map(drop),
            "{fault}"
        );
        assert_eq!(local.local(), Err(Local::Absent), "{fault}");
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(!setup.state.join("authority").exists());
    }
}

#[test]
fn refusal_marker_keeps_same_identity_blocked_and_allows_replacement_identity() {
    use crate::failover::fresh::LocalRecords;
    use crate::failover::fresh::tests::holder;
    use crate::failover::identity::{Incarnation, Key};
    use crate::failover::restart::LocalSource;
    let original = record();
    let own = original.pair().key.incarnation();
    for (attachment, incarnation) in [
        ("attach-replacement", Incarnation::new(900).unwrap()),
        ("attach-replacement", own),
        ("attach-1", Incarnation::new(900).unwrap()),
    ] {
        let mut setup = Setup::new();
        {
            let mut local = fresh_records(&setup);
            local.retain_refusal(&original).unwrap();
        }
        let mut binding = original.binding().clone();
        binding.attachment = attachment.to_owned();
        let key = Key::attachment(incarnation);
        if binding == *original.binding() {
            let mut local = super::authority::FreshRecords {
                lock: &mut setup.lock,
                host: &setup.host.host,
                metadata: &Placement,
                binding,
                key,
            };
            assert_eq!(
                local.persist(&holder(), 0, key),
                Err(AdmissionError::Key),
                "the marker of another incarnation is not consulted"
            );
            continue;
        }
        let replacement = {
            let mut local = super::authority::FreshRecords {
                lock: &mut setup.lock,
                host: &setup.host.host,
                metadata: &Placement,
                binding: binding.clone(),
                key,
            };
            assert_eq!(
                local.retain_refusal(&original),
                Err(AdmissionError::Binding)
            );
            let next = local.persist(&holder(), 0, key).unwrap();
            assert_eq!(next.binding(), &binding);
            assert_eq!(next.pair().key, key);
            assert_eq!(local.local().unwrap(), next);
            next
        };
        let successor = fs::read(setup.state.join("authority")).unwrap();
        let mut old = fresh_records(&setup);
        assert_eq!(
            old.persist(&holder(), 0, record().pair().key),
            Err(AdmissionError::Retained)
        );
        assert_eq!(
            old.retain_refusal(&replacement),
            Err(AdmissionError::Binding)
        );
        assert_eq!(fs::read(setup.state.join("authority")).unwrap(), successor);
        assert!(!marker_path(&setup, &replacement).exists());
        assert_eq!(
            LocalRecord::decode(&fs::read(marker_path(&setup, &original)).unwrap()),
            Ok(original.clone())
        );
    }
}

pub(crate) fn prepared() -> AttachAuthority {
    Setup::new().prepare().unwrap()
}

/// The steps a scripted run reached, in order.
fn reached(run: impl FnOnce()) -> Vec<RecordStep> {
    SCRIPT.set(Some(Script {
        outcomes: vec![],
        reached: vec![],
        observe: Box::new(|_| {}),
    }));
    run();
    SCRIPT
        .take()
        .unwrap()
        .reached
        .into_iter()
        .map(|x| x.0)
        .collect()
}

/// The durable replacement's steps, which a write of the local record takes.
const WRITE: [RecordStep; 7] = [
    RecordStep::TemporaryUnlink,
    RecordStep::Create,
    RecordStep::Write,
    RecordStep::FileSync,
    RecordStep::Rename,
    RecordStep::DirectoryOpen,
    RecordStep::DirectorySync,
];

fn local(setup: &Setup) -> Result<LocalRecord, RecordError> {
    LocalRecord::decode(&fs::read(setup.state.join("authority")).unwrap())
}

/// The authority file's bytes and its (device, inode) identity.
fn snapshot(setup: &Setup) -> (Vec<u8>, (u64, u64)) {
    let path = setup.state.join("authority");
    let meta = fs::metadata(&path).unwrap();
    (fs::read(&path).unwrap(), (meta.dev(), meta.ino()))
}

/// The record of an earlier attachment `attach-0` of the sample instance and volume, with host ID `[4; 16]`.
fn earlier_record() -> LocalRecord {
    let mut binding = record().binding().clone();
    binding.attachment = "attach-0".into();
    LocalRecord::fresh(binding, record().pair().key, || Some([4; 16])).unwrap()
}

/// A record the fresh path drew for the sample assignment: its binding and key, and a host ID other than the seeded `[9; 16]` and `[4; 16]`.
fn drawn(seen: &LocalRecord) -> bool {
    seen.binding() == record().binding()
        && seen.pair().key == record().pair().key
        && seen.pair().exhid != record().pair().exhid
        && seen.pair().exhid != earlier_record().pair().exhid
}

/// A fresh-path run's result, its record-and-CAS order and its filesystem steps.
type Fresh = (
    Result<(), FreshError<()>>,
    Vec<&'static str>,
    Vec<RecordStep>,
);

impl Setup {
    /// Runs the fresh path at attempt counter `attempt` with a compare-and-swap that succeeds, and returns its result, the order of its record write, logged as `record` at the directory sync, and its compare-and-swap, logged as `cas`, and the filesystem steps it reached.
    fn fresh(&mut self, attempt: u32) -> Fresh {
        let order = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let (log, observed) = (std::rc::Rc::clone(&order), std::rc::Rc::clone(&order));
        SCRIPT.set(Some(Script {
            outcomes: vec![],
            reached: vec![],
            observe: Box::new(move |step| {
                if step == RecordStep::DirectorySync {
                    observed.borrow_mut().push("record");
                }
            }),
        }));
        let result = self.lock.prepare_fresh_verified(
            &self.host.host,
            &Placement,
            &assignment(),
            attempt,
            crate::failover::identity::Key::attachment(assignment().fields().incarnation),
            move || {
                log.borrow_mut().push("cas");
                Ok(())
            },
        );
        let steps = SCRIPT
            .take()
            .unwrap()
            .reached
            .into_iter()
            .map(|x| x.0)
            .collect();
        let order = order.borrow().clone();
        (result, order, steps)
    }
}

#[test]
fn owner_lock_mappings_refuse_a_non_regular_or_oversized_entry() {
    type Plant = fn(&Path);
    let rows: [(&str, Plant); 4] = [
        ("fifo", |path| {
            let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
            // SAFETY: `name` is a NUL-terminated path that outlives the call.
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        }),
        ("symlink", |path| {
            let target = path.with_extension("target");
            fs::write(&target, "format=3\n").unwrap();
            std::os::unix::fs::symlink(&target, path).unwrap();
        }),
        ("directory", |path| fs::create_dir(path).unwrap()),
        ("oversized", |path| {
            let oversized = usize::try_from(super::mappings::MAPPINGS_BYTES).unwrap() + 1;
            fs::write(path, vec![b'#'; oversized]).unwrap();
        }),
    ];
    for (name, plant) in rows {
        let setup = Setup::new();
        let path = setup.state.join("mappings");
        fs::remove_file(&path).unwrap();
        plant(&path);
        assert!(
            matches!(
                setup.lock.mappings(),
                Err(super::mappings::MappingsError::Io(_))
            ),
            "{name}: the reader refuses the entry before any parse"
        );
    }
}

/// A connect's preparation reads the bound local record and reaches no filesystem write step; its pair is the record's.
#[test]
fn connect_preparation_reads_the_record_and_writes_nothing() {
    let mut setup = Setup::new();
    let mut authority = None;
    assert!(reached(|| authority = Some(setup.prepare().unwrap())).is_empty());
    let authority = authority.unwrap();
    assert_eq!(authority.pair(), record().pair());
    assert_eq!(local(&setup), Ok(record()));
}

/// With the shard record's `E` at zero and no usable record of this attachment, absent, torn or bound elsewhere, the fresh path persists a record with a newly drawn host ID, distinct across the three runs, through every durable-replacement step, before its compare-and-swap runs, and a connect then reads that record.
#[test]
fn local_record_written_before_attempt_cas() {
    let mut drawn_ids = Vec::new();
    for start in ["absent", "torn", "earlier"] {
        let mut setup = Setup::earlier();
        let path = setup.state.join("authority");
        match start {
            "absent" => fs::remove_file(&path).unwrap(),
            "torn" => {
                let mut sector = fs::read(&path).unwrap();
                sector[300] = 1;
                fs::write(&path, sector).unwrap();
            }
            _ => {}
        }
        let (result, order, steps) = setup.fresh(0);
        result.unwrap();
        assert_eq!(order, ["record", "cas"], "{start}");
        assert_eq!(steps, WRITE, "{start}");
        let written = local(&setup).unwrap();
        assert!(drawn(&written), "{start}: {written:?}");
        assert!(!drawn_ids.contains(&written.pair().exhid), "{start}");
        drawn_ids.push(written.pair().exhid);
        assert_eq!(setup.prepare().unwrap().record, written, "{start}");
    }
}

#[test]
fn fresh_record_carries_the_assignment_key() {
    let mut setup = Setup::new();
    fs::remove_file(setup.state.join("authority")).unwrap();
    let mut a = sample();
    a.incarnation = crate::failover::identity::Incarnation::new(3).unwrap();
    setup
        .lock
        .prepare_fresh_verified(
            &setup.host.host,
            &Placement,
            &verified(&a),
            0,
            crate::failover::identity::Key::attachment(verified(&a).fields().incarnation),
            || Ok::<(), ()>(()),
        )
        .unwrap();
    let written = local(&setup).unwrap();
    assert_eq!(written.pair().key.encode(), (1u64 << 32) | 3);
    assert_eq!(written.binding(), record().binding());
    assert_ne!(written.pair().exhid, record().pair().exhid);
}

/// A rerun of the fresh path while `E` still reads zero rewrites the record through every durable-replacement step and keeps its host ID, so a rerun handed a stale `E = 0` after an earlier run registered that host ID leaves it in place; once `E > 0` the fresh path refuses `AttemptConsumed` before any filesystem step, the temporary file included, and before its compare-and-swap, leaving the record's bytes and inode as written.
#[test]
fn local_record_rewrite_after_attempt_refused() {
    let mut setup = Setup::earlier();
    setup.fresh(0).0.unwrap();
    let first = local(&setup).unwrap();
    assert!(drawn(&first));
    let before = snapshot(&setup);
    let (result, order, steps) = setup.fresh(0);
    result.unwrap();
    assert_eq!(order, ["record", "cas"]);
    assert_eq!(steps, WRITE);
    assert_eq!(local(&setup), Ok(first));
    assert_ne!(snapshot(&setup).1, before.1, "the rerun replaced the file");
    let rewritten = snapshot(&setup);
    for attempt in [1, 7] {
        let steps = reached(|| {
            assert_eq!(
                setup.lock.prepare_fresh_verified(
                    &setup.host.host,
                    &Placement,
                    &assignment(),
                    attempt,
                    crate::failover::identity::Key::attachment(assignment().fields().incarnation),
                    || -> Result<(), ()> { panic!("compare-and-swap at E > 0") },
                ),
                Err(FreshError::Admission(AdmissionError::AttemptConsumed))
            );
        });
        assert!(steps.is_empty(), "{steps:?}");
    }
    assert_eq!(snapshot(&setup), rewritten);
    assert!(!setup.state.join("authority.tmp").exists());
}

/// A compare-and-swap that fails after the record write returns its own error as `Cas` and leaves the new record written; a later rerun at `E = 0` keeps that host ID, and at `E > 0` the fresh path reaches no filesystem step and no compare-and-swap.
#[test]
fn failed_attempt_cas_returns_its_error_and_leaves_the_record() {
    #[derive(Debug, PartialEq, Eq)]
    struct Unacknowledged;
    let mut setup = Setup::earlier();
    let path = setup.state.join("authority");
    let mut at_cas = None;
    let steps = reached(|| {
        assert_eq!(
            setup.lock.prepare_fresh_verified(
                &setup.host.host,
                &Placement,
                &assignment(),
                0,
                crate::failover::identity::Key::attachment(assignment().fields().incarnation),
                || {
                    at_cas = Some(LocalRecord::decode(&fs::read(&path).unwrap()).unwrap());
                    Err(Unacknowledged)
                }
            ),
            Err(FreshError::Cas(Unacknowledged))
        );
    });
    assert_eq!(steps, WRITE);
    let written = at_cas.unwrap();
    assert!(drawn(&written));
    assert_eq!(local(&setup), Ok(written.clone()));
    setup.fresh(0).0.unwrap();
    assert_eq!(local(&setup), Ok(written));
    let before = snapshot(&setup);
    let steps = reached(|| {
        assert_eq!(
            setup.lock.prepare_fresh_verified(
                &setup.host.host,
                &Placement,
                &assignment(),
                1,
                crate::failover::identity::Key::attachment(assignment().fields().incarnation),
                || -> Result<(), ()> { panic!("compare-and-swap at E > 0") },
            ),
            Err(FreshError::Admission(AdmissionError::AttemptConsumed))
        );
    });
    assert!(steps.is_empty(), "{steps:?}");
    assert_eq!(snapshot(&setup), before);
    assert!(!setup.state.join("authority.tmp").exists());
}

/// A binding the trusted records do not agree on refuses before connect, with the record unchanged: a record bound to another instance, volume or attachment than the assignment, and a mappings file from another instance or boot.
#[test]
fn ambiguous_binding_refuses() {
    for field in 0..3 {
        let mut setup = Setup::new();
        let mut binding = record().binding().clone();
        match field {
            0 => binding.instance = "i-0fffffffffffffff0".into(),
            1 => binding.volume = "vol-0fffffffffffffff0".into(),
            _ => binding.attachment = "attach-2".into(),
        }
        let other = LocalRecord::fresh(binding, record().pair().key, || Some([9; 16])).unwrap();
        setup.lock.persist_local(&other).unwrap();
        assert_eq!(setup.prepare().unwrap_err(), AdmissionError::Binding);
        assert_eq!(local(&setup), Ok(other));
    }
    for field in 0..2 {
        let mut setup = Setup::new();
        let mut mappings = mappings_tests::sample(None);
        match field {
            0 => mappings.instance = "i-0fffffffffffffff0".into(),
            _ => mappings.boot = "new-boot".into(),
        }
        mappings.write(&setup.state.join("mappings")).unwrap();
        assert_eq!(setup.prepare().unwrap_err(), AdmissionError::Binding);
        assert_eq!(local(&setup), Ok(record()));
    }
    let mut setup = Setup::new();
    fs::remove_file(setup.state.join("authority")).unwrap();
    assert_eq!(setup.prepare().unwrap_err(), AdmissionError::Record);
}

/// Over a recording filesystem, of the fresh path, the connect preparation and a withdrawal, only the fresh path reaches a write step: a connect preparation, a withdrawal of a scripted disk holding the prepared authority (an accepted Register, then quiesce, stop and detach) and a connect preparation after it reach none and leave the record's bytes and inode unchanged; the fresh path at `E = 0` reaches the durable replacement's steps, and at `E > 0` reaches none.
#[test]
fn a_connect_and_a_withdrawal_write_no_local_record_and_the_fresh_path_writes_at_attempt_zero() {
    let mut setup = Setup::new();
    let before = snapshot(&setup);
    let steps = reached(|| {
        let authority = setup.prepare().unwrap();
        crate::storage::device::withdraw_with(authority);
        setup.prepare().unwrap();
    });
    assert!(steps.is_empty(), "{steps:?}");
    assert_eq!(snapshot(&setup), before);
    let steps = reached(|| {
        setup
            .lock
            .prepare_fresh_verified(
                &setup.host.host,
                &Placement,
                &assignment(),
                0,
                crate::failover::identity::Key::attachment(assignment().fields().incarnation),
                || Ok::<(), ()>(()),
            )
            .unwrap();
    });
    assert_eq!(steps, WRITE);
    let written = snapshot(&setup);
    let steps = reached(|| {
        assert_eq!(
            setup.lock.prepare_fresh_verified(
                &setup.host.host,
                &Placement,
                &assignment(),
                3,
                crate::failover::identity::Key::attachment(assignment().fields().incarnation),
                || Ok::<(), ()>(())
            ),
            Err(FreshError::Admission(AdmissionError::AttemptConsumed))
        );
    });
    assert!(steps.is_empty(), "the fresh path at E > 0 writes nothing");
    assert_eq!(snapshot(&setup), written);
}

/// A failed write step of the fresh path withholds the compare-and-swap and leaves one complete record at every step: the earlier attachment's record until the rename lands, the new record of the sample binding and key after it. A rerun at `E = 0` then leaves a complete record of that binding and key, keeping the host ID of a new record that landed.
#[test]
fn failed_fresh_write_withholds_the_attempt_and_leaves_one_complete_record() {
    for step in [
        RecordStep::Write,
        RecordStep::FileSync,
        RecordStep::Rename,
        RecordStep::DirectoryOpen,
        RecordStep::DirectorySync,
    ] {
        let mut setup = Setup::earlier();
        let path = setup.state.join("authority");
        let observed = path.clone();
        SCRIPT.set(Some(Script {
            outcomes: vec![(step, Scripted::Errno(libc::EIO))],
            reached: vec![],
            observe: Box::new(move |_| {
                let seen = LocalRecord::decode(&fs::read(&observed).unwrap()).unwrap();
                assert!(seen == earlier_record() || drawn(&seen), "{seen:?}");
            }),
        }));
        let mut cas = false;
        assert_eq!(
            setup.lock.prepare_fresh_verified(
                &setup.host.host,
                &Placement,
                &assignment(),
                0,
                crate::failover::identity::Key::attachment(assignment().fields().incarnation),
                || {
                    cas = true;
                    Ok::<(), ()>(())
                }
            ),
            Err(FreshError::Admission(AdmissionError::DurableWrite))
        );
        assert!(SCRIPT.take().unwrap().outcomes.is_empty());
        assert!(!cas, "{step:?} withheld the compare-and-swap");
        let visible = LocalRecord::decode(&fs::read(&path).unwrap()).unwrap();
        let landed = matches!(step, RecordStep::DirectoryOpen | RecordStep::DirectorySync);
        if landed {
            assert!(drawn(&visible), "{step:?}: {visible:?}");
        } else {
            assert_eq!(visible, earlier_record(), "{step:?}");
        }
        setup.fresh(0).0.unwrap();
        let retried = local(&setup).unwrap();
        assert!(drawn(&retried), "{step:?}: {retried:?}");
        if landed {
            assert_eq!(retried, visible, "{step:?}");
        }
        assert!(!setup.state.join("authority.tmp").exists());
    }
}

/// A stored sector whose crc no longer matches its bytes, here a prefix of another record over the stored record's tail, makes the connect refuse `Torn` before connect and leaves the sector unchanged, for a tear inside each identifier, the host ID and the key, and one at the crc. The fresh path's rename-based replacement leaves a complete old or new record at the path after a failed step, so this case is the damage the crc detects; retiring the volume on the refusal belongs to the restart sequence's caller.
#[test]
fn local_record_torn() {
    let next = other_record().encode().unwrap();
    let mut states = Vec::new();
    for torn in [20, 76, 140, 204, 216, 508] {
        let mut setup = Setup::new();
        let path = setup.state.join("authority");
        let mut sector = fs::read(&path).unwrap();
        sector[..torn].copy_from_slice(&next[..torn]);
        assert!(!states.contains(&sector), "torn at {torn} repeats a state");
        states.push(sector.clone());
        fs::write(&path, &sector).unwrap();
        assert_eq!(
            setup.prepare().unwrap_err(),
            AdmissionError::RecordCodec(RecordError::Torn),
            "torn at {torn}"
        );
        assert_eq!(fs::read(&path).unwrap(), sector);
    }
}

/// A public state directory, a missing host key, an assignment of a legacy length, of the 763-byte format-1 length or missing, and a wrong host key refuse in directory, key, length and tag order before the instance metadata service is contacted, on the connect path and on the fresh path at `E = 0` and `E > 0`, with no filesystem write step, no compare-and-swap and the record and assignment unchanged.
#[test]
fn assignmentless_legacy_keyless_and_public_directories_refuse_before_metadata() {
    use crate::failover::assignment::AssignmentError;
    type Fault<'a> = &'a dyn Fn(&Path);
    let cases: [(Fault<'_>, AdmissionError); 6] = [
        (
            &|state| fs::set_permissions(state, fs::Permissions::from_mode(0o755)).unwrap(),
            AdmissionError::StateDirectory,
        ),
        (
            &|state| fs::remove_file(state.join("host.key")).unwrap(),
            AdmissionError::HostKey,
        ),
        (
            &|state| fs::write(state.join("assignment"), b"legacy").unwrap(),
            AdmissionError::Assignment(AssignmentError::Length),
        ),
        (
            &|state| fs::write(state.join("assignment"), [1; 763]).unwrap(),
            AdmissionError::Assignment(AssignmentError::Length),
        ),
        (
            &|state| fs::remove_file(state.join("assignment")).unwrap(),
            AdmissionError::Assignment(AssignmentError::Length),
        ),
        (
            &|state| fs::write(state.join("host.key"), [0; 32]).unwrap(),
            AdmissionError::Assignment(AssignmentError::Tag),
        ),
    ];
    for (at, (fault, expected)) in cases.iter().enumerate() {
        for fresh in [None, Some(0), Some(1)] {
            let mut setup = Setup::new();
            fault(&setup.state);
            let before = snapshot(&setup);
            let assignment = fs::read(setup.state.join("assignment")).ok();
            let steps = reached(|| {
                let result = match fresh {
                    Some(attempt) => setup.lock.prepare_fresh(
                        &setup.host.host,
                        attempt,
                        record().pair().key,
                        || -> Result<(), ()> { panic!("a refused admission reached the CAS") },
                    ),
                    None => setup
                        .lock
                        .prepare_authority(&setup.host.host, &Unreached)
                        .map(drop)
                        .map_err(FreshError::Admission),
                };
                assert_eq!(
                    result,
                    Err(FreshError::Admission(*expected)),
                    "{at} fresh {fresh:?}"
                );
            });
            assert!(steps.is_empty(), "{at} fresh {fresh:?}: {steps:?}");
            assert_eq!(snapshot(&setup), before, "{at} fresh {fresh:?}");
            assert_eq!(
                fs::read(setup.state.join("assignment")).ok(),
                assignment,
                "{at} fresh {fresh:?}"
            );
        }
    }
}

#[test]
fn authority_files_require_private_regular_bounded_bytes() {
    for name in ["host.key", "assignment", "authority"] {
        for fault in ["mode", "symlink", "length", "directory"] {
            let mut setup = Setup::new();
            let path = setup.state.join(name);
            let bound = fs::read(&path).unwrap().len();
            match fault {
                "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
                "symlink" => {
                    let target = setup.state.join("private-target");
                    fs::rename(&path, &target).unwrap();
                    std::os::unix::fs::symlink(target, &path).unwrap();
                }
                "length" => fs::write(&path, vec![0; bound + 1]).unwrap(),
                "directory" => {
                    fs::remove_file(&path).unwrap();
                    fs::create_dir(&path).unwrap();
                }
                _ => unreachable!(),
            }
            let result = if name == "authority" {
                setup.prepare()
            } else {
                setup.lock.prepare_authority(&setup.host.host, &Placement)
            };
            let expected = match name {
                "host.key" => AdmissionError::HostKey,
                "assignment" => {
                    AdmissionError::Assignment(crate::failover::assignment::AssignmentError::Length)
                }
                "authority" => AdmissionError::RecordCodec(RecordError::Length),
                _ => unreachable!(),
            };
            assert_eq!(result.unwrap_err(), expected, "{name} {fault}");
        }
    }
}

/// An `authority` file of the 283-byte format-1 record length refuses `Length` at a connect and stays unchanged.
#[test]
fn a_format_one_length_record_refuses_without_rewrite() {
    let mut setup = Setup::new();
    let path = setup.state.join("authority");
    fs::write(&path, [1; 283]).unwrap();
    let before = snapshot(&setup);
    assert_eq!(
        setup.prepare().unwrap_err(),
        AdmissionError::RecordCodec(RecordError::Length)
    );
    assert_eq!(snapshot(&setup), before);
}

/// Every admission refusal, from the instance metadata, the mappings file or the assignment, refuses on both the connect and the fresh path, at `E = 0` and at `E > 0`, with its own error, no filesystem write step, no compare-and-swap and the record unchanged; an instance mismatch refuses `Instance` before the record read even when the record is absent.
#[test]
fn imds_and_mapping_mismatches_refuse_before_publication() {
    struct Observation {
        instance: &'static str,
        az: &'static str,
    }
    impl Metadata for Observation {
        fn get(&self, path: &str) -> io::Result<String> {
            match path {
                "instance-id" => Ok(self.instance.into()),
                "placement/availability-zone" => Ok(self.az.into()),
                _ => panic!("unexpected metadata path"),
            }
        }
    }
    const OBSERVED: Observation = Observation {
        instance: "i-0123456789abcdef0",
        az: "us-east-1a",
    };
    let unchanged = |_: &mut Mappings| {};
    let eni_only = |m: &mut Mappings| {
        m.nvme = None;
        m.eni = Some(mappings_tests::eni(1));
    };
    let other_instance = |m: &mut Mappings| m.instance = "i-0fffffffffffffff0".into();
    let other_boot = |m: &mut Mappings| m.boot = "new-boot".into();
    type Case<'a> = (
        Observation,
        &'a dyn Fn(&mut Mappings),
        Assignment,
        AdmissionError,
    );
    let mut cases: Vec<Case<'_>> = vec![];
    for (instance, az, expected) in [
        ("i-other", "us-east-1a", AdmissionError::Instance),
        ("i-0123456789abcdef0", "us-east-1b", AdmissionError::Az),
        ("i-0123456789abcdef0", "", AdmissionError::Az),
        ("i-0123456789abcdef0", "US-EAST-1A", AdmissionError::Az),
    ] {
        cases.push((Observation { instance, az }, &unchanged, sample(), expected));
    }
    cases.push((OBSERVED, &eni_only, sample(), AdmissionError::Volume));
    cases.push((OBSERVED, &other_instance, sample(), AdmissionError::Binding));
    cases.push((OBSERVED, &other_boot, sample(), AdmissionError::Binding));
    let mut other_volume = sample();
    other_volume.volume = "vol-0fffffffffffffff0".into();
    cases.push((OBSERVED, &unchanged, other_volume, AdmissionError::Volume));
    for deletion in [None, Some(true)] {
        let mut a = sample();
        a.delete_on_termination = deletion;
        cases.push((OBSERVED, &unchanged, a, AdmissionError::DeleteOnTermination));
    }
    for (observation, mappings, a, expected) in &cases {
        for path in [None, Some(0), Some(1)] {
            let mut setup = Setup::new();
            let mut written = mappings_tests::sample(None);
            mappings(&mut written);
            if written != mappings_tests::sample(None) {
                written.write(&setup.state.join("mappings")).unwrap();
            }
            let before = snapshot(&setup);
            let steps = reached(|| {
                let result = match path {
                    Some(attempt) => setup.lock.prepare_fresh_verified(
                        &setup.host.host,
                        observation,
                        &verified(a),
                        attempt,
                        crate::failover::identity::Key::attachment(
                            verified(a).fields().incarnation,
                        ),
                        || -> Result<(), ()> { panic!("a refused admission reached the CAS") },
                    ),
                    None => setup
                        .lock
                        .prepare_verified(&setup.host.host, observation, verified(a))
                        .map(drop)
                        .map_err(FreshError::Admission),
                };
                assert_eq!(result, Err(FreshError::Admission(*expected)), "{path:?}");
            });
            assert!(steps.is_empty(), "{expected:?} {path:?}: {steps:?}");
            assert_eq!(snapshot(&setup), before, "{expected:?} {path:?}");
        }
    }
    let setup = Setup::new();
    fs::remove_file(setup.state.join("authority")).unwrap();
    assert_eq!(
        setup
            .lock
            .prepare_verified(
                &setup.host.host,
                &Observation {
                    instance: "i-other",
                    az: "us-east-1a"
                },
                assignment()
            )
            .unwrap_err(),
        AdmissionError::Instance
    );
}

#[test]
fn owner_lock_pins_the_canonical_directory_after_a_link_is_retargeted() {
    let setup = Setup::new();
    let target = setup.state.join("target");
    super::prepare_state_dir(&target, fs::metadata("/proc/self").unwrap().uid()).unwrap();
    mappings_tests::sample(None)
        .write(&target.join("mappings"))
        .unwrap();
    let link = setup.state.join("state-link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let locked = OwnerLock::acquire(&link).unwrap();
    fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(&setup.state, &link).unwrap();
    assert_eq!(locked.state_dir(), fs::canonicalize(target).unwrap());
    assert_ne!(locked.state_dir(), setup.lock.state_dir());
    assert_eq!(locked.mappings().unwrap(), setup.lock.mappings().unwrap());
}

#[test]
fn a_link_placed_above_the_locked_directory_is_checked_through_its_target() {
    let setup = Setup::new();
    let owner = fs::metadata("/proc/self").unwrap().uid();
    let state = fs::canonicalize(&setup.state).unwrap();
    let middle = state.join("middle");
    let locked = middle.join("locked");
    super::prepare_state_dir(&locked, owner).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
    let lock = OwnerLock::acquire(&locked).unwrap();
    let private = state.join("private");
    fs::create_dir(&private).unwrap();
    fs::rename(&middle, private.join("middle")).unwrap();
    std::os::unix::fs::symlink(private.join("middle"), &middle).unwrap();
    assert_eq!(
        super::binder::private_canonical(&locked, owner),
        Ok(fs::canonicalize(&locked).unwrap())
    );
    assert_ne!(fs::canonicalize(&locked).unwrap(), locked);
    assert_eq!(
        lock.prepare_authority(setup.host(), &Placement)
            .unwrap_err(),
        AdmissionError::HostKey
    );
    let shared = state.join("shared");
    fs::create_dir(&shared).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
    fs::rename(private.join("middle"), shared.join("middle")).unwrap();
    fs::remove_file(&middle).unwrap();
    std::os::unix::fs::symlink(shared.join("middle"), &middle).unwrap();
    assert_eq!(
        super::private_state_dir(&locked, owner),
        Err(fs::canonicalize(&shared).unwrap())
    );
    for suffix in ["/", "//", "/."] {
        let mut spelled = middle.clone().into_os_string();
        spelled.push(suffix);
        assert_eq!(
            super::private_state_dir(std::path::Path::new(&spelled), owner),
            Err(fs::canonicalize(&shared).unwrap()),
            "{suffix}"
        );
    }
    assert_eq!(
        lock.prepare_authority(setup.host(), &Placement)
            .unwrap_err(),
        AdmissionError::StateDirectory
    );
}

#[test]
fn production_attach_refuses_keyless_and_invalid_config_without_publication() {
    use crate::native::{Environment, registration_tests};
    use crate::storage::{ReservationLimits, SpdkAttachError, SpdkConfig, SpdkDisk};
    let setup = Setup::new();
    fs::remove_file(setup.state.join("host.key")).unwrap();
    let before = fs::read(setup.state.join("authority")).unwrap();
    let (env, arena) = (Environment::detached(), registration_tests::new_arena());
    let mut registration = registration_tests::ready(&env, &arena);
    let limits = ReservationLimits::new(3, 2, 10, 20).unwrap();
    let config = SpdkConfig {
        queue_depth: 8,
        timeout_io_us: 1,
        timeout_admin_us: 1,
    };
    assert!(matches!(
        SpdkDisk::<crate::storage::device::Spdk>::attach(
            &setup.host.host,
            &setup.lock,
            &Unreached,
            &mut registration,
            config,
            limits
        ),
        Err(SpdkAttachError::Authority(AdmissionError::HostKey))
    ));
    let invalid = SpdkConfig {
        queue_depth: 0,
        ..config
    };
    assert!(matches!(
        SpdkDisk::<crate::storage::device::Spdk>::attach(
            &setup.host.host,
            &setup.lock,
            &Unreached,
            &mut registration,
            invalid,
            limits
        ),
        Err(SpdkAttachError::Config)
    ));
    assert_eq!(fs::read(setup.state.join("authority")).unwrap(), before);
}

/// The host-ID draw passes a successful fill through unchanged, an all-zero fill included, so the record's zero redraw runs, and yields nothing for a failed fill.
#[test]
fn host_id_draw_passes_zero_fills_through() {
    use super::authority::host_id_draw;
    assert_eq!(host_id_draw(|_| Ok(())), Some([0; 16]));
    assert_eq!(
        host_id_draw(|bytes| {
            bytes.fill(3);
            Ok(())
        }),
        Some([3; 16])
    );
    assert_eq!(
        host_id_draw(|_| Err(crate::entropy::EntropyError::Unavailable { code: 38 })),
        None
    );
}

/// An `authority` file that exists and cannot be read as a private regular file of at most one sector, by mode, symlink, size or file type, makes the fresh path refuse `RecordCodec(Length)` with no filesystem write step and no compare-and-swap, leaving the path as it was, so a record the fresh path cannot read keeps whatever host ID it holds.
#[test]
fn fresh_path_refuses_an_unreadable_record_without_writing() {
    for fault in ["mode", "symlink", "length", "directory"] {
        let mut setup = Setup::new();
        let path = setup.state.join("authority");
        let target = setup.state.join("private-target");
        match fault {
            "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            "symlink" => {
                fs::rename(&path, &target).unwrap();
                std::os::unix::fs::symlink(&target, &path).unwrap();
            }
            "length" => fs::write(&path, vec![0; 513]).unwrap(),
            "directory" => {
                fs::remove_file(&path).unwrap();
                fs::create_dir(&path).unwrap();
            }
            _ => unreachable!(),
        }
        let before = fs::symlink_metadata(&path).unwrap();
        let steps = reached(|| {
            assert_eq!(
                setup.lock.prepare_fresh_verified(
                    &setup.host.host,
                    &Placement,
                    &assignment(),
                    0,
                    crate::failover::identity::Key::attachment(assignment().fields().incarnation),
                    || -> Result<(), ()> { panic!("an unreadable record reached the CAS") },
                ),
                Err(FreshError::Admission(AdmissionError::RecordCodec(
                    RecordError::Length
                ))),
                "{fault}"
            );
        });
        assert!(steps.is_empty(), "{fault}: {steps:?}");
        let after = fs::symlink_metadata(&path).unwrap();
        assert_eq!(
            (after.ino(), after.mode(), after.len()),
            (before.ino(), before.mode(), before.len()),
            "{fault}"
        );
        if fault == "symlink" {
            assert_eq!(
                LocalRecord::decode(&fs::read(&target).unwrap()),
                Ok(record())
            );
        }
    }
}

/// A local record of this attachment's binding that holds another key incarnation than the assignment refuses `Key` on the fresh path, with no write step and no compare-and-swap, and at a connect, leaving the record unchanged.
#[test]
fn a_record_with_another_key_refuses_on_both_paths() {
    for key in [
        other_record().pair().key,
        crate::failover::identity::Key::attachment(other_record().pair().key.incarnation()),
    ] {
        let other = LocalRecord::fresh(record().binding().clone(), key, || Some([9; 16])).unwrap();
        let mut setup = Setup::seeded(&other);
        let before = snapshot(&setup);
        let steps = reached(|| {
            assert_eq!(
                setup.lock.prepare_fresh_verified(
                    &setup.host.host,
                    &Placement,
                    &assignment(),
                    0,
                    crate::failover::identity::Key::attachment(assignment().fields().incarnation),
                    || -> Result<(), ()> { panic!("a key conflict reached the CAS") },
                ),
                Err(FreshError::Admission(AdmissionError::Key))
            );
        });
        assert!(steps.is_empty(), "{steps:?}");
        assert_eq!(setup.prepare().unwrap_err(), AdmissionError::Key);
        assert_eq!(snapshot(&setup), before);
    }
}

#[test]
fn a_record_keyed_before_the_fixed_epoch_keeps_its_key() {
    let a = sample();
    let earlier = LocalRecord::fresh(
        record().binding().clone(),
        crate::failover::identity::Key::new(
            crate::failover::identity::Epoch::new(6).unwrap(),
            a.incarnation,
        ),
        || Some([9; 16]),
    )
    .unwrap();
    let bytes = earlier.encode().unwrap();
    assert_eq!(&bytes[212..220], &[2, 0, 0, 0, 6, 0, 0, 0]);
    let mut setup = Setup::seeded(&earlier);
    let before = snapshot(&setup);
    assert_eq!(before.0, bytes);
    let authority = setup.prepare().unwrap();
    assert_eq!(authority.pair().key.encode(), (6u64 << 32) | 2);
    assert_eq!(authority.pair(), earlier.pair());
    assert_eq!(snapshot(&setup), before, "the connect rewrites nothing");
    assert_eq!(
        setup.lock.prepare_fresh_verified(
            &setup.host.host,
            &Placement,
            &assignment(),
            0,
            crate::failover::identity::Key::attachment(a.incarnation),
            || -> Result<(), ()> { panic!("a key refusal runs no compare-and-swap") },
        ),
        Err(FreshError::Admission(AdmissionError::Key)),
        "the kept record's epoch-6 key is not the key the caller admits"
    );
    assert_eq!(snapshot(&setup), before, "the key refusal rewrites nothing");
    setup
        .lock
        .prepare_fresh_verified(
            &setup.host.host,
            &Placement,
            &assignment(),
            0,
            earlier.pair().key,
            || Ok::<(), ()>(()),
        )
        .unwrap();
    assert_eq!(
        local(&setup),
        Ok(earlier),
        "the fresh rerun keeps the stored key and host ID"
    );
}

/// KEY-PER-ATTACH at the assignment-backed preparation: over an absent record, a key other than the one the record
/// would carry refuses `Key` with no record step, no authority file and no compare-and-swap; the same binding then
/// prepares under its own key.
#[test]
fn a_fresh_preparation_under_another_key_refuses_before_any_write() {
    let mut setup = Setup::new();
    let authority = setup.state.join("authority");
    fs::remove_file(&authority).unwrap();
    let mut refused = None;
    let steps = reached(|| {
        refused = Some(setup.lock.prepare_fresh_verified(
            &setup.host.host,
            &Placement,
            &assignment(),
            0,
            crate::failover::records::attachment_key(0).unwrap(),
            || -> Result<(), ()> { panic!("a key refusal runs no compare-and-swap") },
        ));
    });
    assert_eq!(
        refused,
        Some(Err(FreshError::Admission(AdmissionError::Key)))
    );
    assert!(steps.is_empty(), "{steps:?}");
    assert!(!authority.exists());
    setup
        .lock
        .prepare_fresh_verified(
            &setup.host.host,
            &Placement,
            &assignment(),
            0,
            record().pair().key,
            || Ok::<(), ()>(()),
        )
        .unwrap();
    assert_eq!(
        LocalRecord::decode(&fs::read(&authority).unwrap())
            .unwrap()
            .pair()
            .key,
        record().pair().key
    );
}

/// A release whose marker unlink succeeds and whose directory sync fails returns `DurableWrite`, which
/// `Fresh::run` reports as `Check::Release` with a flip request. The RetainedRefusal rule keeps the retention
/// behind a refusal that requests a flip, so the release records the marker again and the restart local-record
/// read still refuses with `Retained`; when the marker cannot be recorded again, the local record is removed and
/// that read refuses with `Absent`.
#[test]
fn a_release_that_fails_at_the_directory_sync_keeps_the_retention() {
    use crate::failover::fresh::LocalRecords;
    use crate::failover::restart::LocalSource;
    for (rerecord, restart) in [(None, Local::Retained), (Some(libc::EIO), Local::Absent)] {
        let setup = Setup::new();
        let mut local = fresh_records(&setup);
        local.retain_refusal(&record()).unwrap();
        assert_eq!(local.local(), Err(Local::Retained));
        let mut outcomes = vec![(RecordStep::DirectorySync, Scripted::Errno(libc::EIO))];
        outcomes.extend(rerecord.map(|errno| (RecordStep::Create, Scripted::Errno(errno))));
        SCRIPT.set(Some(Script {
            outcomes,
            reached: vec![],
            observe: Box::new(|_| {}),
        }));
        let released = local.release_refusal(&record());
        let script = SCRIPT.take().unwrap();
        assert!(script.outcomes.is_empty(), "{rerecord:?}");
        assert_eq!(released, Err(AdmissionError::DurableWrite), "{rerecord:?}");
        assert_eq!(
            local.local(),
            Err(restart),
            "a failed release left the attachment unretained"
        );
    }
}

/// The standby's persist writes the record it returns on every call. It keeps the key and host ID of a valid
/// record of the assignment's binding and key, and draws a record over an absent file, a sector that fails
/// decoding and a record bound to another attachment; a retry keeps the record the first call wrote. A key other
/// than the assignment's, over an absent file, a record of another attachment and an unreadable file included, a
/// record of this binding under another key incarnation or under the requested incarnation and another epoch, a file
/// that cannot be read and a retained refusal refuse before any write, the last over a record the persist would
/// otherwise replace. The retained key of a record of this binding persists when the caller requests it, as for the
/// replay of a pair enrolled under it.
#[test]
fn the_standby_persist_keeps_a_bound_record_and_writes_one_over_any_other() {
    let persist = |setup: &Setup| {
        (setup.lock).persist_standby(&setup.host.host, &Placement, record().pair().key)
    };
    let setup = Setup::new();
    let steps = reached(|| assert_eq!(persist(&setup), Ok(record())));
    assert_eq!(steps, WRITE, "a bound record is written again");
    assert_eq!(local(&setup), Ok(record()));

    let absent = Setup::new();
    fs::remove_file(absent.state.join("authority")).unwrap();
    let torn = Setup::new();
    let path = torn.state.join("authority");
    let mut sector = fs::read(&path).unwrap();
    sector[..76].copy_from_slice(&other_record().encode().unwrap()[..76]);
    fs::write(&path, &sector).unwrap();
    assert_eq!(local(&torn), Err(RecordError::Torn));
    for (case, setup) in [
        ("another attachment", Setup::earlier()),
        ("absent", absent),
        ("torn", torn),
    ] {
        let mut written = None;
        let steps = reached(|| written = Some(persist(&setup).unwrap()));
        assert_eq!(steps, WRITE, "{case}");
        let written = written.unwrap();
        assert!(drawn(&written), "{case}: {written:?}");
        assert_eq!(local(&setup), Ok(written.clone()), "{case}");
        let steps = reached(|| assert_eq!(persist(&setup), Ok(written.clone())));
        assert_eq!(steps, WRITE, "{case}: a retry keeps the record it wrote");
    }

    // KEY-PER-ATTACH: a key other than the assignment's, as for a live attach entry whose number the issuer did not
    // read, refuses before any read of the record or write.
    let setup = Setup::new();
    let before = snapshot(&setup);
    let steps = reached(|| {
        let key = other_record().pair().key;
        assert_eq!(
            (setup.lock).persist_standby(&setup.host.host, &Placement, key),
            Err(AdmissionError::Key)
        );
    });
    assert!(steps.is_empty(), "{steps:?}");
    assert_eq!(snapshot(&setup), before);

    // Only the assignment check refuses here: over an absent file or a record of another attachment the persist
    // would otherwise draw and write a record. The key is another attach entry's, epoch 1 under another
    // incarnation, so a check of the epoch alone admits it.
    let another_attach = crate::failover::identity::Key::attachment(
        crate::failover::identity::Incarnation::new(sample().incarnation.get() + 1).unwrap(),
    );
    let absent = Setup::new();
    fs::remove_file(absent.state.join("authority")).unwrap();
    let steps = reached(|| {
        assert_eq!(
            (absent.lock).persist_standby(&absent.host.host, &Placement, another_attach),
            Err(AdmissionError::Key)
        );
    });
    assert!(steps.is_empty(), "absent: {steps:?}");
    assert!(!absent.state.join("authority").exists(), "absent");
    let setup = Setup::earlier();
    let before = snapshot(&setup);
    let steps = reached(|| {
        assert_eq!(
            (setup.lock).persist_standby(&setup.host.host, &Placement, another_attach),
            Err(AdmissionError::Key)
        );
    });
    assert!(steps.is_empty(), "another attachment: {steps:?}");
    assert_eq!(snapshot(&setup), before, "another attachment");

    // A record of this binding under the requested incarnation and another epoch is kept by no new enrollment: the
    // volume record would refuse its key, so the persist refuses before any write.
    let epoch_six = LocalRecord::fresh(
        record().binding().clone(),
        crate::failover::identity::Key::new(
            crate::failover::identity::Epoch::new(6).unwrap(),
            sample().incarnation,
        ),
        || Some([9; 16]),
    )
    .unwrap();
    let setup = Setup::seeded(&epoch_six);
    let before = snapshot(&setup);
    let steps = reached(|| assert_eq!(persist(&setup), Err(AdmissionError::Key)));
    assert!(steps.is_empty(), "{steps:?}");
    assert_eq!(snapshot(&setup), before);
    let steps = reached(|| {
        assert_eq!(
            (setup.lock).persist_standby(&setup.host.host, &Placement, epoch_six.pair().key),
            Ok(epoch_six.clone())
        );
    });
    assert_eq!(
        steps, WRITE,
        "the replay of a pair enrolled under the retained key"
    );
    // A retained key of another epoch replays only the kept record that holds it: over an absent file, a torn
    // sector or a record of another attachment the persist draws nothing under that key.
    let absent = Setup::new();
    fs::remove_file(absent.state.join("authority")).unwrap();
    let torn = Setup::new();
    let path = torn.state.join("authority");
    let mut sector = fs::read(&path).unwrap();
    sector[..76].copy_from_slice(&other_record().encode().unwrap()[..76]);
    fs::write(&path, &sector).unwrap();
    for (case, setup) in [
        ("absent", absent),
        ("torn", torn),
        ("another attachment", Setup::earlier()),
    ] {
        let path = setup.state.join("authority");
        let before = fs::read(&path).ok();
        let steps = reached(|| {
            assert_eq!(
                (setup.lock).persist_standby(&setup.host.host, &Placement, epoch_six.pair().key),
                Err(AdmissionError::Key),
                "{case}"
            );
        });
        assert!(steps.is_empty(), "{case}: {steps:?}");
        assert_eq!(fs::read(&path).ok(), before, "{case}");
    }

    let other = LocalRecord::fresh(
        record().binding().clone(),
        other_record().pair().key,
        || Some([9; 16]),
    )
    .unwrap();
    let setup = Setup::seeded(&other);
    let before = snapshot(&setup);
    let steps = reached(|| assert_eq!(persist(&setup), Err(AdmissionError::Key)));
    assert!(steps.is_empty(), "{steps:?}");
    assert_eq!(snapshot(&setup), before);

    let setup = Setup::new();
    let path = setup.state.join("authority");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let before = snapshot(&setup);
    let unreadable = AdmissionError::RecordCodec(RecordError::Length);
    let steps = reached(|| assert_eq!(persist(&setup), Err(unreadable)));
    assert!(steps.is_empty(), "{steps:?}");
    assert_eq!(snapshot(&setup), before);
    let steps = reached(|| {
        assert_eq!(
            (setup.lock).persist_standby(&setup.host.host, &Placement, another_attach),
            Err(AdmissionError::Key),
            "the assignment check runs before the record read"
        );
    });
    assert!(steps.is_empty(), "{steps:?}");
    assert_eq!(snapshot(&setup), before);

    let setup = Setup::earlier();
    crate::failover::fresh::LocalRecords::retain_refusal(&mut fresh_records(&setup), &record())
        .unwrap();
    let before = snapshot(&setup);
    let steps = reached(|| assert_eq!(persist(&setup), Err(AdmissionError::Retained)));
    assert!(steps.is_empty(), "{steps:?}");
    assert_eq!(snapshot(&setup), before);
    assert_eq!(local(&setup), Ok(earlier_record()));
}

/// A standby persist whose write fails returns `DurableWrite` at each step. A step before the rename leaves the
/// earlier record at the path; the directory steps after it leave the drawn record there, and the retry writes
/// that record again, through its directory sync, before it returns it, so the host ID of an enrollment is the one
/// a completed durable write holds.
#[test]
fn a_failed_standby_persist_refuses_and_its_retry_rewrites_the_landed_record() {
    for step in [
        RecordStep::Write,
        RecordStep::FileSync,
        RecordStep::Rename,
        RecordStep::DirectoryOpen,
        RecordStep::DirectorySync,
    ] {
        let setup = Setup::earlier();
        let path = setup.state.join("authority");
        SCRIPT.set(Some(Script {
            outcomes: vec![(step, Scripted::Errno(libc::EIO))],
            reached: vec![],
            observe: Box::new(|_| {}),
        }));
        let refused = setup
            .lock
            .persist_standby(&setup.host.host, &Placement, record().pair().key);
        assert!(SCRIPT.take().unwrap().outcomes.is_empty(), "{step:?}");
        assert_eq!(refused, Err(AdmissionError::DurableWrite), "{step:?}");
        let visible = LocalRecord::decode(&fs::read(&path).unwrap()).unwrap();
        let landed = matches!(step, RecordStep::DirectoryOpen | RecordStep::DirectorySync);
        if landed {
            assert!(drawn(&visible), "{step:?}: {visible:?}");
        } else {
            assert_eq!(visible, earlier_record(), "{step:?}");
        }
        if landed {
            // The same directory step fails on the retry that keeps the landed record.
            SCRIPT.set(Some(Script {
                outcomes: vec![(step, Scripted::Errno(libc::EIO))],
                reached: vec![],
                observe: Box::new(|_| {}),
            }));
            let refused =
                setup
                    .lock
                    .persist_standby(&setup.host.host, &Placement, record().pair().key);
            assert!(SCRIPT.take().unwrap().outcomes.is_empty(), "{step:?}");
            assert_eq!(refused, Err(AdmissionError::DurableWrite), "{step:?}");
            assert_eq!(local(&setup), Ok(visible.clone()), "{step:?}");
        }
        let mut retried = None;
        let steps = reached(|| {
            retried = Some(
                setup
                    .lock
                    .persist_standby(&setup.host.host, &Placement, record().pair().key)
                    .unwrap(),
            );
        });
        assert_eq!(
            steps, WRITE,
            "{step:?}: the retry reaches its directory sync"
        );
        let retried = retried.unwrap();
        assert!(drawn(&retried), "{step:?}: {retried:?}");
        if landed {
            assert_eq!(retried, visible, "{step:?}: the landed host ID is kept");
        }
        assert_eq!(local(&setup), Ok(retried), "{step:?}");
    }
}

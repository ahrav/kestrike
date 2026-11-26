//! The launch sequence persists intent and started before releasing the gate.
//! Teardown kills cgroup membership and waits for the kernel's populated-zero state.

use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use super::{Counters, Custody, Error, Launch, Timing};
use crate::record::{
    Binding, BoundEvidence, Class, Finished, Intent, Kernel, ProbeFinished, Record, Reservation,
    Started, Text, Verified,
};
use crate::step::{self, Step};
use crate::store::{self, Creation, Dir, Name, Store};
use crate::sys;

/// A running attempt owns its cgroup handle and child process descriptor.
/// Live controllers consume it through wait_any.
/// Dropping it leaves the launcher unreaped until the parent exits.
///
/// ```compile_fail,E0616
/// use campaign_supervisor::custody::Running;
/// fn swap(first: &mut Running, second: &mut Running) {
///     std::mem::swap(&mut first.started, &mut second.started);
/// }
/// ```
#[must_use]
pub struct Running {
    released_at: Instant,
    directory: (u64, u64),
    output: Dir,
    output_baseline: store::Usage,
    census_due: Instant,
    resource_error: Option<Error>,
    limits: super::Limits,
    group: store::cgroup::Group,
    process: sys::Process,
    before: Counters,
    deadline: Instant,
    stop_at: Option<Instant>,
    interruption: Option<i32>,
    status: Option<ExitStatus>,
    drain_deadline: Option<Instant>,
    watchdog: bool,
    residual_members: bool,
    started: Verified<Started>,
}

/// A stopped tree retains kernel counters until evidence publication and removal.
/// Its proof binds the attempt directory device and inode, Intent, Started cgroup
/// inode and baseline counters. Evidence publication rechecks these bindings.
///
/// ```compile_fail,E0616
/// use campaign_supervisor::custody::Stopped;
/// fn swap(first: &mut Stopped, second: &mut Stopped) {
///     std::mem::swap(&mut first.started, &mut second.started);
/// }
/// ```
///
/// ```compile_fail,E0616
/// use campaign_supervisor::custody::Stopped;
/// fn replace(stopped: &mut Stopped) {
///     stopped.status = None;
/// }
/// ```
pub struct Stopped {
    elapsed_ms: Option<u64>,
    resource_error: Option<Error>,
    directory: (u64, u64),
    cgroup_inode: Option<u64>,
    intent: Intent,
    baseline: Kernel,
    group: Option<store::cgroup::Group>,
    started: Option<Verified<Started>>,
    before: Option<Counters>,
    after: Option<Counters>,
    status: Option<ExitStatus>,
    interruption: Option<i32>,
    watchdog: bool,
    residual_members: bool,
}

const MAX_CPU_QUOTA_US: u64 = (1 << 44) - 1;
/// The largest process limit a cgroup takes.
pub(crate) const MAX_PIDS: u64 = 4 * 1024 * 1024;
const CENSUS_SPACING: u32 = 4;

fn next_census(finished: Instant, elapsed: Duration, poll: Duration, attempts: usize) -> Instant {
    let factor = CENSUS_SPACING.saturating_mul(u32::try_from(attempts).unwrap_or(u32::MAX));
    finished
        .checked_add(elapsed.saturating_mul(factor).max(poll))
        .unwrap_or(finished)
}

fn point(step: Step) -> Result<(), Error> {
    step::call(step, || Ok(())).map_err(Error::from)
}

fn name(text: &str) -> Name {
    Name::new(text).expect("lifecycle names are valid components")
}

pub(crate) fn charge(store: &Store, directory: &Dir, attempt: &Text) -> Result<Creation, Error> {
    let creation = store.create_record(
        directory,
        &name("reservation"),
        &Reservation {
            attempt: attempt.clone(),
        },
    )?;
    point(Step::Reservation)?;
    Ok(creation)
}

pub(crate) fn charged(
    store: &impl crate::store::ReadStore,
    directory: &Dir,
    attempt: &Text,
) -> Result<Option<Verified<Reservation>>, Error> {
    let found = store.read_record::<Reservation>(directory, &name("reservation"))?;
    if found
        .as_ref()
        .is_some_and(|record| &record.record().attempt != attempt)
    {
        return Err(Error::Held("reservation names another attempt"));
    }
    if let Some(found) = &found {
        store.barrier(found.read())?;
    }
    Ok(found)
}

impl Launch {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let launch = self;
        launch.limits.validate()?;
        let words = [
            launch.gate.as_os_str(),
            launch.launcher.as_os_str(),
            launch.directory.as_os_str(),
        ]
        .into_iter()
        .chain(launch.args.iter().map(|word| word.as_os_str()))
        .chain(
            launch
                .environment
                .iter()
                .flat_map(|(key, value)| [key.as_os_str(), value.as_os_str()]),
        );
        if launch.launcher.as_os_str().is_empty()
            || words.into_iter().any(|word| word.as_bytes().contains(&0))
            || launch
                .environment
                .keys()
                .any(|key| key.is_empty() || key.as_bytes().contains(&b'='))
        {
            return Err(Error::Rejected("invalid custody command"));
        }
        store::launch_paths(&launch.gate, &launch.directory).map_err(|error| {
            let unreadable = store::Unreadable::Io(error);
            let faulted = unreadable.faulted();
            match unreadable {
                store::Unreadable::Io(error) if faulted => Error::Io(error),
                _ => Error::Rejected("invalid custody launch paths"),
            }
        })?;
        Ok(())
    }
}

impl Custody {
    pub(crate) fn check_root(root: &Path) -> Result<(), Error> {
        if !root.is_absolute()
            || root
                .components()
                .any(|component| component == std::path::Component::ParentDir)
        {
            return Err(Error::Rejected("invalid custody root path"));
        }
        if root.to_str().and_then(Text::new).is_none() {
            return Err(Error::Rejected("cgroup path contains non-printable bytes"));
        }
        Ok(())
    }

    /// Opens the user-owned delegated root and moves this process into its controller child.
    /// The process's first thread must call this before it starts other threads,
    /// so those threads inherit the blocked interruption signals.
    pub fn open(root: &Path, timing: Timing) -> Result<Self, Error> {
        Self::check_root(root)?;
        if timing.poll.is_zero()
            || timing.kill_wait.is_zero()
            || timing.watchdog.is_zero()
            || Instant::now().checked_add(timing.kill_wait).is_none()
            || Instant::now().checked_add(timing.watchdog).is_none()
        {
            return Err(Error::Rejected("invalid custody timing"));
        }
        let signals = sys::Signals::open()?;
        let root = store::cgroup::Root::open(root)?;
        let boot =
            Text::new(&store::cgroup::boot()?).ok_or(Error::Held("invalid boot identity"))?;
        Ok(Self {
            root,
            boot,
            signals,
            timing,
            interrupted: None,
            release_deadline: None,
            held: None,
            resource_faults: Default::default(),
            retained: Vec::new(),
        })
    }

    /// Persists intent before exclusive cgroup creation, moves the waiting gate,
    /// persists started, then sends its go byte. The caller has already persisted
    /// the reservation and keeps it charged through every error.
    pub fn launch(
        &mut self,
        store: &Store,
        directory: &Dir,
        launch: Launch,
    ) -> Result<Running, Error> {
        self.check_release()?;
        launch.validate()?;
        let output = directory.duplicate()?;
        let path = self.root.path(&launch.name).map_err(|error| {
            if error.kind() == std::io::ErrorKind::InvalidInput {
                Error::Rejected("invalid custody cgroup name")
            } else {
                Error::Io(error)
            }
        })?;
        let intent = Intent {
            attempt: launch.attempt,
            boot: self.boot.clone(),
            cgroup: path
                .to_str()
                .and_then(Text::new)
                .expect("validated cgroup path is record text"),
        };
        for existing in ["started", "finished"] {
            if store
                .read(directory, &name(existing), crate::record::BOUND)
                .map_err(|_| Error::Held("existing lifecycle unreadable"))?
                .is_some()
            {
                return Err(Error::Held("lifecycle already recorded"));
            }
        }
        if crate::record::Record::encoded_len(&intent) as u64 > crate::record::BOUND {
            return Err(Error::Rejected("intent exceeds record bound"));
        }
        let stdout = store
            .launcher_output(directory, &name(super::LAUNCHER_STDOUT))?
            .ok_or(Error::Held("launcher stdout already present"))?;
        let stderr = store
            .launcher_output(directory, &name(super::LAUNCHER_STDERR))?
            .ok_or(Error::Held("launcher stderr already present"))?;
        let creation = store.create_record(directory, &name("intent"), &intent)?;
        if creation != Creation::Created {
            return Err(Error::Held("intent already recorded"));
        }
        point(Step::Intent)?;
        let intent = store
            .read_record::<Intent>(directory, &name("intent"))?
            .ok_or(Error::Held("intent vanished"))?;
        store.barrier(intent.read())?;
        let group = self.root.create(
            &launch.name,
            launch.limits.cpu_quota_us,
            launch.limits.memory_bytes,
            launch.limits.pids,
        )?;
        point(Step::Created)?;
        let before = group.snapshot()?;
        let mut command = Command::new(launch.gate);
        command
            .arg("gate")
            .arg("--")
            .arg(launch.launcher)
            .args(launch.args)
            .envs(launch.environment)
            .stdin(Stdio::piped())
            .stdout(stdout)
            .stderr(stderr);
        sys::gate_parent(
            &mut command,
            &launch.directory,
            launch.limits.file_bytes,
            launch.limits.cpu_seconds,
        );
        let mut child = step::call(Step::Spawn, || command.spawn())?;
        let process = sys::Process::open(&child)?;
        point(Step::Spawned)?;
        let mut go = child.stdin.take().expect("gate stdin was piped");
        group.move_gate(&child)?;
        point(Step::Moved)?;
        store.barrier(intent.read())?;
        let started = Started {
            baseline: kernel(&before),
            attempt: intent.record().attempt.clone(),
            boot: self.boot.clone(),
            cgroup: intent.record().cgroup.clone(),
            cgroup_inode: group.inode()?,
            launcher_pid: u64::from(child.id()),
        };
        if store.create_record(directory, &name("started"), &started)? != Creation::Created {
            return Err(Error::Held("started already recorded"));
        }
        point(Step::Started)?;
        let started = store
            .read_record::<Started>(directory, &name("started"))?
            .ok_or(Error::Held("started vanished"))?;
        store.barrier(started.read())?;
        let deadline = Instant::now()
            .checked_add(self.timing.watchdog)
            .ok_or(Error::Held("watchdog overflow"))?;
        self.check_release()?;
        let output_baseline = output.usage(crate::scan_bound())?;
        self.check_release()?;
        point(Step::Go)?;
        let released_at = Instant::now();
        go.write_all(b"G")?;
        drop(go);
        point(Step::ReleasedGate)?;
        Ok(Running {
            released_at,
            directory: directory.identity(),
            output,
            output_baseline,
            census_due: Instant::now(),
            resource_error: None,
            limits: launch.limits,
            group,
            process,
            before,
            deadline,
            stop_at: None,
            interruption: None,
            status: None,
            drain_deadline: None,
            watchdog: false,
            residual_members: false,
            started,
        })
    }

    /// Polls the child, signal descriptor and cgroup events on the owning thread.
    /// Child exit, interruption or watchdog expiry starts kill and drain.
    /// A populated tree or unreaped child past the kill wait stays held.
    /// A failed wait attempts to kill each tree except the held tree and
    /// retains every other attempt without a resource error, with the exit,
    /// interruption and watchdog state it observed, for
    /// [`Custody::take_retained`].
    pub fn wait_any(&mut self, running: Vec<Running>) -> Result<Waited, Error> {
        self.held = None;
        self.resource_faults.clear();
        self.retained.clear();
        let mut running = running;
        let result = self.wait_one(&mut running);
        if result.is_err() {
            for mut attempt in running {
                let identity = attempt.started.record().attempt.clone();
                if attempt.resource_error.is_some() {
                    self.resource_faults.insert(identity.clone());
                }
                if self.held.as_ref() == Some(&identity) {
                    continue;
                }
                if attempt.status.is_some() && attempt.drain_deadline.is_none() {
                    match attempt.group.populated() {
                        Ok(populated) => attempt.residual_members = populated,
                        Err(error) => {
                            attempt.resource_error.get_or_insert(error.into());
                            self.resource_faults.insert(identity);
                        }
                    }
                }
                let _ = point(Step::Kill).and_then(|_| attempt.group.kill().map_err(Error::from));
                if attempt.resource_error.is_none() {
                    self.retained.push(attempt);
                }
            }
        }
        result
    }

    pub(crate) fn inactive(&self, intent: &Intent) -> Result<bool, Error> {
        let path = Path::new(intent.cgroup.as_str());
        if intent.boot != self.boot && !self.root.contains(path) {
            return Ok(!store::cgroup_present(path)?);
        }
        Ok(self.root.recorded(path)?.is_none())
    }

    pub(crate) fn stop_for_reconcile(&mut self, running: Running) -> Result<(), Error> {
        point(Step::Kill)?;
        running.group.kill()?;
        let stopped = self.wait_any(vec![running])?.stopped;
        drop(stopped);
        Ok(())
    }

    /// Returns the attempts the last failed `wait_any` retained, each
    /// without a resource error, for [`Custody::stop`].
    pub fn take_retained(&mut self) -> Vec<Running> {
        std::mem::take(&mut self.retained)
    }

    /// Drains the retained attempt's cgroup and returns its stop proof with
    /// the exit, interruption and watchdog state the wait observed.
    pub fn stop(&mut self, running: Running) -> Result<Stopped, Error> {
        let Running {
            released_at,
            directory,
            group,
            before,
            interruption,
            started,
            status,
            watchdog,
            residual_members,
            mut resource_error,
            ..
        } = running;
        self.drain(&group)?;
        let after = match group.snapshot() {
            Ok(after) => Some(after),
            Err(error) => {
                resource_error.get_or_insert(error.into());
                None
            }
        };
        Ok(Stopped {
            elapsed_ms: Some(u64::try_from(released_at.elapsed().as_millis()).unwrap_or(u64::MAX)),
            resource_error,
            directory,
            cgroup_inode: Some(started.record().cgroup_inode),
            intent: Intent {
                attempt: started.record().attempt.clone(),
                boot: started.record().boot.clone(),
                cgroup: started.record().cgroup.clone(),
            },
            baseline: started.record().baseline.clone(),
            group: Some(group),
            started: Some(started),
            before: Some(before),
            after,
            status,
            interruption,
            watchdog,
            residual_members,
        })
    }

    /// `supervise` applies one pass of [`Custody::wait_any`]'s limit,
    /// interruption and stop rules and retains every tree in `running`. A
    /// populated tree or unreaped child past the kill wait sets the held
    /// identity, which the next [`Custody::wait_any`] clears, and returns
    /// `Held`.
    pub(crate) fn supervise(&mut self, running: &mut [Running]) -> Result<(), Error> {
        if running.is_empty() {
            return Ok(());
        }
        let signal = self.interruption()?;
        let attempts = running.len();
        for attempt in running {
            if self.enforce(attempt, signal, attempts)? {
                self.drained(attempt)?;
            }
        }
        Ok(())
    }

    fn drained(&mut self, attempt: &Running) -> Result<bool, Error> {
        if !attempt.group.populated()? && attempt.status.is_some() {
            return Ok(true);
        }
        let remaining = attempt
            .drain_deadline
            .expect("draining attempt has a deadline")
            .saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            self.held = Some(attempt.started.record().attempt.clone());
            return Err(Error::Held(
                "cgroup populated or child unreaped past kill wait",
            ));
        }
        Ok(false)
    }

    fn enforce(
        &self,
        attempt: &mut Running,
        signal: Option<i32>,
        attempts: usize,
    ) -> Result<bool, Error> {
        if attempt.status.is_none() {
            attempt.status = step::call(Step::Reap, || attempt.process.reap())?;
            if attempt.status.is_some() {
                point(Step::Exited)?;
            }
        }
        if attempt.drain_deadline.is_some() {
            return Ok(true);
        }
        let now = Instant::now();
        match attempt.group.cpu_usage() {
            Ok(cpu) => {
                match cpu.checked_sub(attempt.before.cpu.get("usage_usec").copied().unwrap_or(0)) {
                    Some(consumed)
                        if u128::from(consumed)
                            >= u128::from(attempt.limits.cpu_seconds) * 1_000_000 =>
                    {
                        attempt.interruption = Some(sys::CPU_SIGNAL)
                    }
                    Some(_) => {}
                    None => {
                        attempt
                            .resource_error
                            .get_or_insert(Error::Held("CPU counter regressed"));
                    }
                }
            }
            Err(error) => {
                attempt.resource_error.get_or_insert(error.into());
            }
        }
        if attempt.status.is_none() && attempt.interruption.is_none() {
            attempt.interruption = signal.or_else(|| {
                attempt
                    .stop_at
                    .filter(|deadline| now >= *deadline)
                    .map(|_| sys::KILL_SIGNAL as i32)
            });
        }
        if attempt.stopping(now) || now >= attempt.census_due {
            let began = Instant::now();
            let hit = attempt.output_exceeded();
            let finished = Instant::now();
            attempt.census_due =
                next_census(finished, finished - began, self.timing.poll, attempts);
            if hit && attempt.interruption != Some(sys::CPU_SIGNAL) {
                attempt.interruption = Some(sys::OUTPUT_SIGNAL);
            }
        }
        attempt.watchdog = attempt.interruption.is_none() && now >= attempt.deadline;
        if !attempt.stopping(now) {
            attempt.group.acknowledge_events()?;
            return Ok(false);
        }
        attempt.residual_members = attempt.status.is_some() && attempt.group.populated()?;
        point(Step::Kill)?;
        attempt.group.kill()?;
        point(Step::Killed)?;
        attempt.drain_deadline = Some(
            Instant::now()
                .checked_add(self.timing.kill_wait)
                .ok_or(Error::Held("kill wait overflow"))?,
        );
        Ok(true)
    }

    fn wait_one(&mut self, running: &mut Vec<Running>) -> Result<Waited, Error> {
        if running.is_empty() {
            return Err(Error::Rejected("empty custody wait set"));
        }
        loop {
            let signal = self.interruption()?;
            let attempts = running.len();
            let mut ready = None;
            for (index, attempt) in running.iter_mut().enumerate() {
                if !self.enforce(attempt, signal, attempts)? {
                    continue;
                }
                if self.drained(attempt)? && ready.is_none() {
                    point(Step::Drained)?;
                    ready = Some(index);
                }
            }
            if let Some(index) = ready {
                let Running {
                    released_at,
                    directory,
                    group,
                    before,
                    interruption,
                    started,
                    status,
                    watchdog,
                    residual_members,
                    mut resource_error,
                    ..
                } = running.swap_remove(index);
                let after = match group.snapshot() {
                    Ok(after) => Some(after),
                    Err(error) => {
                        resource_error.get_or_insert(error.into());
                        None
                    }
                };
                return Ok(Waited {
                    stopped: Stopped {
                        elapsed_ms: Some(
                            u64::try_from(released_at.elapsed().as_millis()).unwrap_or(u64::MAX),
                        ),
                        resource_error,
                        directory,
                        cgroup_inode: Some(started.record().cgroup_inode),
                        intent: Intent {
                            attempt: started.record().attempt.clone(),
                            boot: started.record().boot.clone(),
                            cgroup: started.record().cgroup.clone(),
                        },
                        baseline: started.record().baseline.clone(),
                        group: Some(group),
                        started: Some(started),
                        before: Some(before),
                        after,
                        status,
                        interruption,
                        watchdog,
                        residual_members,
                    },
                    to_drain: std::mem::take(running),
                });
            }
            let mut descriptors = sys::PollSet::new(&self.signals);
            for attempt in running.iter() {
                attempt.group.watch(
                    attempt.status.is_none().then_some(&attempt.process),
                    &mut descriptors,
                );
            }
            match step::last(Step::Poll, || {
                let now = Instant::now();
                let left = running
                    .iter()
                    .map(|attempt| {
                        attempt
                            .drain_deadline
                            .unwrap_or_else(|| {
                                attempt
                                    .stop_at
                                    .map_or(attempt.deadline, |stop| stop.min(attempt.deadline))
                            })
                            .saturating_duration_since(now)
                    })
                    .min()
                    .expect("wait set stays populated")
                    .min(self.timing.poll);
                descriptors.poll(left)
            }) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                result => result?,
            }
        }
    }

    fn drain(&mut self, group: &store::cgroup::Group) -> Result<(), Error> {
        point(Step::Kill)?;
        group.kill()?;
        let deadline = Instant::now()
            .checked_add(self.timing.kill_wait)
            .ok_or(Error::Held("kill wait overflow"))?;
        loop {
            self.interruption()?;
            if !group.populated()? {
                point(Step::Drained)?;
                return Ok(());
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Error::Held("cgroup populated past kill wait"));
            }
            group.poll(&self.signals, left.min(self.timing.poll))?;
        }
    }

    /// Restart stops recorded membership. Numeric pids remain diagnostic data.
    /// An existing prior-boot cgroup stays held. An absent prior-boot path reconciles as gone.
    /// A supplied Started must agree with Intent before the cgroup lookup.
    /// An existing cgroup requires Started with its recorded inode.
    /// The store barriers intent and any supplied started record before draining the cgroup.
    /// The caller publishes bound evidence and finished before removing the stopped tree.
    /// Restart callers recover after the previous controller exits.
    /// Reconciliation drains the recorded cgroup.
    pub fn reconcile(
        &mut self,
        store: &Store,
        intent: &Verified<Intent>,
        started: Option<&Verified<Started>>,
    ) -> Result<Stopped, Error> {
        store.barrier(intent.read())?;
        if let Some(started) = started {
            if started.read().directory_identity() != intent.read().directory_identity() {
                return Err(Error::Held("misbound stop proof: directory"));
            }
            if !started.record().agrees_with(intent.record()) {
                return Err(Error::Held("cgroup lacks matching started"));
            }
            store.barrier(started.read())?;
        }
        let path = Path::new(intent.record().cgroup.as_str());
        let group = if intent.record().boot != self.boot && !self.root.contains(path) {
            if store::cgroup_present(path)? {
                return Err(Error::Held("prior-boot path now contains a cgroup"));
            }
            None
        } else {
            self.root.recorded(path)?
        };
        if group.is_some() && intent.record().boot != self.boot {
            return Err(Error::Held("cgroup belongs to another boot"));
        }
        if let Some(group) = &group {
            let Some(started) = started else {
                return Err(Error::Held("cgroup lacks matching started"));
            };
            if started.record().cgroup_inode != group.inode()? {
                return Err(Error::Held("cgroup instance differs from started"));
            }
            self.drain(group)?;
        }
        let after = group.as_ref().map(|group| group.snapshot()).transpose()?;
        Ok(Stopped {
            elapsed_ms: None,
            resource_error: None,
            directory: intent.read().directory_identity(),
            cgroup_inode: started.map(|record| record.record().cgroup_inode),
            intent: intent.record().clone(),
            baseline: started
                .map(|record| record.record().baseline.clone())
                .unwrap_or_default(),
            group,
            started: None,
            before: None,
            after,
            status: None,
            interruption: None,
            watchdog: false,
            residual_members: false,
        })
    }

    pub(crate) fn pending(
        &self,
        store: &Store,
        directory: &Dir,
        identity: &Text,
    ) -> Result<(), Error> {
        let path = self.root.path(&name(identity.as_str()))?;
        if self.root.recorded(&path)?.is_some() {
            return Err(Error::Held("pending attempt has a cgroup"));
        }
        let intent = Intent {
            attempt: identity.clone(),
            boot: self.boot.clone(),
            cgroup: Text::new(
                path.to_str()
                    .ok_or(Error::Held("cgroup path is not ASCII"))?,
            )
            .ok_or(Error::Held("cgroup path is not ASCII"))?,
        };
        store.create_record(directory, &name("intent"), &intent)?;
        Ok(())
    }

    pub(crate) fn validate_limits(
        &self,
        limits: super::Limits,
        shares: u128,
    ) -> Result<(), store::cgroup::FitError> {
        self.root.limits_fit(
            limits.cpu_quota_us,
            limits.memory_bytes,
            limits.pids,
            shares,
        )
    }

    pub(crate) fn resource_faulted(&self, identity: &Text) -> bool {
        self.resource_faults.contains(identity)
    }

    pub(crate) fn check_release(&mut self) -> Result<(), Error> {
        if self.interruption()?.is_some() {
            return Err(Error::Held("controller interruption requires drain"));
        }
        if self
            .release_deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(Error::Held("dispatch deadline requires drain"));
        }
        Ok(())
    }

    pub(crate) fn held_identity(&self) -> Option<&Text> {
        self.held.as_ref()
    }

    pub(crate) fn set_watchdog(&mut self, seconds: u64) -> Result<(), Error> {
        let duration = std::time::Duration::from_secs(seconds);
        if duration.is_zero() || Instant::now().checked_add(duration).is_none() {
            return Err(Error::Rejected("invalid dispatch watchdog"));
        }
        self.timing.watchdog = duration;
        Ok(())
    }

    pub(crate) fn set_release_deadline(&mut self, deadline: Option<Instant>) {
        self.release_deadline = deadline;
    }

    pub fn interruption(&mut self) -> Result<Option<i32>, Error> {
        let signal = self.signals.take()?;
        self.interrupted = self.interrupted.or(signal);
        Ok(self.interrupted)
    }

    /// Callers hold these paths and start work only after reconciliation succeeds.
    pub fn unrecorded(
        &self,
        intents: &[&Verified<Intent>],
        scan_bound: usize,
    ) -> Result<Vec<std::path::PathBuf>, Error> {
        self.children_except(
            intents
                .iter()
                .map(|intent| Path::new(intent.record().cgroup.as_str()))
                .collect(),
            scan_bound,
        )
    }

    pub(crate) fn unattended(
        &self,
        running: &[Running],
        scan_bound: usize,
    ) -> Result<Vec<std::path::PathBuf>, Error> {
        self.children_except(
            running
                .iter()
                .map(|attempt| Path::new(attempt.started.record().cgroup.as_str()))
                .collect(),
            scan_bound,
        )
    }

    fn children_except(
        &self,
        known: std::collections::BTreeSet<&Path>,
        scan_bound: usize,
    ) -> Result<Vec<std::path::PathBuf>, Error> {
        let children = self.root.children(scan_bound)?;
        Ok(children
            .into_iter()
            .filter(|path| !known.contains(path.as_path()))
            .collect())
    }
}

impl Stopped {
    /// Duration from the go byte through the drained stop; recovered trees are unmeasured.
    pub(crate) fn elapsed_ms(&self) -> Option<u64> {
        self.elapsed_ms
    }

    pub fn finished(
        &self,
        class: Class,
        binding: Binding,
        bound: Option<BoundEvidence>,
    ) -> Result<Finished, Error> {
        use std::os::unix::process::ExitStatusExt;
        Ok(Finished {
            attempt: self.intent.attempt.clone(),
            binding,
            bound,
            class,
            exit: self
                .status
                .and_then(|status| status.code())
                .map(|code| code as u64),
            interruption: self.interruption.map(|signal| signal as u64),
            kernel: self.kernel()?,
            residual_members: self.residual_members,
            signal: self
                .status
                .and_then(|status| status.signal())
                .map(|signal| signal as u64),
            watchdog: self.watchdog,
        })
    }

    pub fn identity(&self) -> &Text {
        &self.intent.attempt
    }

    pub fn kernel(&self) -> Result<Kernel, Error> {
        if self.resource_error.is_some() {
            return Err(Error::Held("resource observation failed"));
        }
        let Some(after) = &self.after else {
            return Ok(Kernel::default());
        };
        let after = kernel(after);
        fn delta(
            before: &std::collections::BTreeMap<Text, u64>,
            after: &std::collections::BTreeMap<Text, u64>,
        ) -> Result<std::collections::BTreeMap<Text, u64>, Error> {
            if before.keys().any(|key| !after.contains_key(key)) {
                return Err(Error::Held("kernel counter vanished"));
            }
            after
                .iter()
                .map(|(key, value)| {
                    if key.as_str() == "peak" {
                        return Ok((key.clone(), *value));
                    }
                    value
                        .checked_sub(*before.get(key).unwrap_or(&0))
                        .map(|delta| (key.clone(), delta))
                        .ok_or(Error::Held("kernel counter regressed"))
                })
                .collect()
        }
        Ok(Kernel {
            cpu: delta(&self.baseline.cpu, &after.cpu)?,
            memory: delta(&self.baseline.memory, &after.memory)?,
            pids: delta(&self.baseline.pids, &after.pids)?,
        })
    }

    /// Consumes the stop proof after checking the directory, intent and started bindings.
    /// The store barriers the stopped evidence tree within evidence_bound.
    /// A changed directory or witness is held before evidence publication.
    pub fn evidence(
        mut self,
        store: &Store,
        directory: &Dir,
        evidence_bound: usize,
    ) -> Result<EvidenceTree, Error> {
        if let Some(error) = self.resource_error.take() {
            return Err(error);
        }
        if directory.identity() != self.directory {
            return Err(Error::Held("misbound stop proof: directory"));
        }
        let intent = store
            .read_record::<Intent>(directory, &name("intent"))?
            .ok_or(Error::Held("evidence lacks intent"))?;
        if intent.record() != &self.intent {
            return Err(Error::Held("misbound stop proof: intent"));
        }
        let started = store.read_record::<Started>(directory, &name("started"))?;
        if started.as_ref().map(|record| record.record().cgroup_inode) != self.cgroup_inode {
            return Err(Error::Held("misbound stop proof: started"));
        }
        if let Some(started) = &started {
            if !started.record().agrees_with(&self.intent)
                || started.record().baseline != self.baseline
                || self
                    .started
                    .as_ref()
                    .is_some_and(|proof| proof.record() != started.record())
            {
                return Err(Error::Held("misbound stop proof: started"));
            }
            store.barrier(started.read())?;
        }
        store.barrier(intent.read())?;
        let directory = store.evidence_barrier(directory, evidence_bound)?;
        Ok(EvidenceTree {
            stopped: self,
            directory,
        })
    }

    pub fn started(&self) -> Option<&Verified<Started>> {
        self.started.as_ref()
    }

    pub fn before(&self) -> Option<&Counters> {
        self.before.as_ref()
    }

    pub fn after(&self) -> Option<&Counters> {
        self.after.as_ref()
    }

    pub fn status(&self) -> Option<ExitStatus> {
        self.status
    }

    pub fn interruption(&self) -> Option<i32> {
        self.interruption
    }

    pub fn watchdog(&self) -> bool {
        self.watchdog
    }

    /// Removes the drained cgroup. A nested child or a busy directory holds the attempt.
    /// The caller first persists finished, then releases capacity only after this succeeds.
    /// Removal changes the cgroup filesystem; lifecycle records remain create-once.
    pub(crate) fn remove_group(self) -> Result<(), Error> {
        if let Some(group) = self.group {
            if group.populated()? {
                return Err(Error::Held("cgroup populated before removal"));
            }
            group.remove()?;
        }
        point(Step::Removed)
    }
}

pub struct Waited {
    pub stopped: Stopped,
    pub to_drain: Vec<Running>,
}

impl Running {
    fn stopping(&self, now: Instant) -> bool {
        self.status.is_some()
            || self.interruption.is_some()
            || self.resource_error.is_some()
            || now >= self.deadline
    }

    fn output_exceeded(&mut self) -> bool {
        let charge =
            crate::record::resource_charge(self.limits.output_bytes, self.limits.output_inodes);
        match self.output.usage(crate::scan_bound()) {
            Ok(usage) => {
                usage.bytes.saturating_sub(self.output_baseline.bytes) > self.limits.output_bytes
                    || usage.inodes.saturating_sub(self.output_baseline.inodes)
                        > self.limits.output_inodes
                    || u128::from(usage.bytes) + crate::record::COMPLETION_RECORD_BYTES
                        > charge.bytes
                    || u128::from(usage.inodes) + 2 > charge.inodes
            }
            Err(store::Error::ScanBound | store::Error::DepthBound)
                if charge.inodes < crate::scan_bound() as u128 =>
            {
                true
            }
            Err(error) => {
                self.resource_error.get_or_insert(error.into());
                false
            }
        }
    }

    pub(crate) fn request_stop(&mut self) {
        let now = Instant::now();
        self.stop_at = Some(self.stop_at.map_or(now, |deadline| deadline.min(now)));
    }

    pub(crate) fn stop_at(&mut self, deadline: Instant) {
        self.stop_at = Some(deadline);
    }

    pub fn started(&self) -> &Verified<Started> {
        &self.started
    }

    pub fn interruption(&self) -> Option<i32> {
        self.interruption
    }
}

fn kernel(counters: &Counters) -> Kernel {
    let map = |values: &std::collections::BTreeMap<String, u64>| {
        values
            .iter()
            .map(|(key, value)| {
                (
                    Text::new(key).expect("kernel counter names are ASCII"),
                    *value,
                )
            })
            .collect()
    };
    Kernel {
        cpu: map(&counters.cpu),
        memory: map(&counters.memory),
        pids: map(&counters.pids),
    }
}

/// ```compile_fail,E0616
/// use campaign_supervisor::custody::EvidenceTree;
/// fn replace(a: &mut EvidenceTree, b: &mut EvidenceTree) {
///     std::mem::swap(&mut a.directory, &mut b.directory);
/// }
/// ```
pub struct EvidenceTree {
    stopped: Stopped,
    directory: Dir,
}

impl EvidenceTree {
    pub fn directory(&self) -> &Dir {
        &self.directory
    }
    pub fn stopped(&self) -> &Stopped {
        &self.stopped
    }
    pub fn complete(self, store: &Store, finished: &Finished) -> Result<Verified<Finished>, Error> {
        let (found, directory) = self.retire(store, finished, &finished.attempt)?;
        store.delete(&directory, &name("reservation"))?;
        point(Step::Released)?;
        Ok(found)
    }

    pub(crate) fn complete_probe(
        self,
        store: &Store,
        finished: &ProbeFinished,
    ) -> Result<Verified<ProbeFinished>, Error> {
        let (found, directory) = self.retire(store, finished, &finished.attempt)?;
        store.delete(&directory, &name("reservation"))?;
        point(Step::Released)?;
        Ok(found)
    }

    fn retire<R: Record + Eq>(
        self,
        store: &Store,
        finished: &R,
        attempt: &Text,
    ) -> Result<(Verified<R>, Dir), Error> {
        let directory = &self.directory;
        if attempt != &self.stopped.intent.attempt {
            return Err(Error::Held("finished names another stopped attempt"));
        }
        if self.stopped.group.is_none() {
            charged(store, directory, attempt)?
                .ok_or(Error::Held("stopped attempt lacks reservation"))?;
        }
        store.create_record(directory, &name("finished"), finished)?;
        let found = store
            .read_record::<R>(directory, &name("finished"))?
            .ok_or(Error::Held("finished vanished"))?;
        if found.record() != finished {
            return Err(Error::Held("finished differs from stopped evidence"));
        }
        store.barrier(found.read())?;
        point(Step::Finished)?;
        charged(store, directory, attempt)?
            .ok_or(Error::Held("stopped attempt lacks reservation"))?;
        self.stopped.remove_group()?;
        Ok((found, self.directory))
    }
}

#[cfg(test)]
mod counter_tests {
    use super::*;

    #[test]
    fn nonzero_baselines_are_subtracted_and_regression_or_disappearance_holds() {
        let mut stopped = Stopped {
            elapsed_ms: None,
            resource_error: None,
            directory: (0, 0),
            cgroup_inode: None,
            intent: Intent {
                attempt: Text::new("attempt").unwrap(),
                boot: Text::new("boot").unwrap(),
                cgroup: Text::new("/group").unwrap(),
            },
            group: None,
            started: None,
            before: None,
            status: None,
            interruption: None,
            watchdog: false,
            residual_members: false,
            baseline: Kernel {
                cpu: [(Text::new("usage_usec").unwrap(), 100)].into(),
                memory: [
                    (Text::new("oom_kill").unwrap(), 3),
                    (Text::new("peak").unwrap(), 50),
                ]
                .into(),
                pids: [
                    (Text::new("max").unwrap(), 5),
                    (Text::new("peak").unwrap(), 50),
                ]
                .into(),
            },
            after: Some(Counters {
                cpu: [("usage_usec".to_owned(), 145)].into(),
                memory: [("oom_kill".to_owned(), 4), ("peak".to_owned(), 40)].into(),
                pids: [("max".to_owned(), 8), ("peak".to_owned(), 40)].into(),
            }),
        };
        let delta = stopped.kernel().unwrap();
        assert_eq!(delta.cpu[&Text::new("usage_usec").unwrap()], 45);
        assert_eq!(delta.memory[&Text::new("oom_kill").unwrap()], 1);
        assert_eq!(delta.pids[&Text::new("max").unwrap()], 3);
        assert_eq!(delta.memory[&Text::new("peak").unwrap()], 40);
        assert_eq!(delta.pids[&Text::new("peak").unwrap()], 40);
        stopped
            .after
            .as_mut()
            .unwrap()
            .cpu
            .insert("usage_usec".to_owned(), 99);
        assert!(matches!(
            stopped.kernel(),
            Err(Error::Held("kernel counter regressed"))
        ));
        stopped.after.as_mut().unwrap().cpu.clear();
        assert!(matches!(
            stopped.kernel(),
            Err(Error::Held("kernel counter vanished"))
        ));
    }
}

#[cfg(test)]
mod census_tests {
    use std::time::{Duration, Instant};

    #[test]
    fn census_spacing_scales_with_census_cost_and_wait_set_size_above_the_poll_floor() {
        let at = Instant::now();
        let poll = Duration::from_millis(50);
        let cheap = super::next_census(at, Duration::from_micros(100), poll, 8);
        assert_eq!(cheap, at + poll);
        let costly = super::next_census(at, Duration::from_millis(10), poll, 1);
        assert_eq!(costly, at + Duration::from_millis(50));
        let shared = super::next_census(at, Duration::from_millis(10), poll, 3);
        assert_eq!(shared, at + Duration::from_millis(120));
        assert_eq!(super::next_census(at, Duration::MAX, poll, 2), at);
    }
}

impl super::Limits {
    /// Checks numeric custody bounds and the controller inherited hard limits.
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if !(1000..=MAX_CPU_QUOTA_US).contains(&self.cpu_quota_us)
            || !(1..sys::CPU_HARD_MAX).contains(&self.cpu_seconds)
            || self.output_bytes == 0
            || !(1..=(crate::store::EVIDENCE_BOUND as u64 - 2)).contains(&self.output_inodes)
            || self.memory_bytes == 0
            || !(1..=MAX_PIDS).contains(&self.pids)
            || !(1..=sys::LIMIT_MAX).contains(&self.file_bytes)
        {
            return Err(Error::Rejected("invalid custody limits"));
        }
        if self.cpu_seconds >= sys::cpu_limit()? {
            return Err(Error::Rejected("CPU limit exceeds inherited hard bound"));
        }
        if self.file_bytes > sys::file_limit()? {
            return Err(Error::Rejected("file limit exceeds inherited hard bound"));
        }
        Ok(())
    }
}

impl Running {
    pub(crate) fn limits(&self) -> super::Limits {
        self.limits
    }
}

//! Work split across scoped threads. [`each`] and [`runs`] return their
//! results in input order and resume a worker's panic on the calling
//! thread. Work whose thread the OS refuses runs on the calling thread.

use std::thread::{Builder, Scope, ScopedJoinHandle};

/// The most runs, and so threads, [`runs`] splits its items into.
pub const THREADS: usize = 8;

/// Work started by [`start`]: a running thread, or the result of work
/// that ran on the calling thread because the OS refused the thread.
pub(crate) enum Worker<'scope, T> {
    Spawned(ScopedJoinHandle<'scope, T>),
    Ran(T),
}

impl<T> Worker<'_, T> {
    /// The work's result; a worker's panic resumes on the calling thread.
    pub(crate) fn finish(self) -> T {
        match self {
            Self::Spawned(worker) => worker
                .join()
                .unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
            Self::Ran(result) => result,
        }
    }
}

/// Starts `work` on a thread of `scope`, or runs it on the calling thread
/// when the OS refuses the thread.
pub(crate) fn start<'scope, T: Send + 'scope>(
    scope: &'scope Scope<'scope, '_>,
    work: &'scope (impl Fn() -> T + Sync),
) -> Worker<'scope, T> {
    match Builder::new().spawn_scoped(scope, work) {
        Ok(worker) => Worker::Spawned(worker),
        Err(_) => Worker::Ran(work()),
    }
}

/// The results of `work` on each item, in input order. Each item runs on
/// its own scoped thread when there is more than one item.
pub(crate) fn each<I: Sync, T: Send>(items: &[I], work: impl Fn(&I) -> T + Sync) -> Vec<T> {
    if items.len() <= 1 {
        return items.iter().map(work).collect();
    }
    let work = &work;
    let tasks: Vec<_> = items.iter().map(|item| move || work(item)).collect();
    std::thread::scope(|scope| {
        let workers: Vec<_> = tasks.iter().map(|task| start(scope, task)).collect();
        workers.into_iter().map(Worker::finish).collect()
    })
}

/// The results of `work` on contiguous runs of `items`, in input order.
/// It targets `(items.len() / least.max(1)).clamp(1, THREADS)` runs and
/// rounds the run length up, so it can form fewer runs. It returns an
/// empty vector for empty `items`; for
/// `0 < items.len() < 2 * least.max(1)`, it calls `work` once on the
/// calling thread.
pub(crate) fn runs<'a, I: Sync, T: Send>(
    items: &'a [I],
    least: usize,
    work: impl Fn(&'a [I]) -> T + Sync,
) -> Vec<T> {
    let threads = (items.len() / least.max(1)).clamp(1, THREADS);
    let runs: Vec<&'a [I]> = items.chunks(items.len().div_ceil(threads).max(1)).collect();
    each(&runs, |run| work(run))
}

/// Drops `items` in the contiguous runs [`runs`] would form, each on its
/// own scoped thread, so freeing a large array of rows spreads across
/// threads; fewer than twice `least` items drop on the calling thread. A
/// run whose thread fails to start drops on the calling thread.
pub(crate) fn drop_in_runs<T: Send>(mut items: Vec<T>, least: usize) {
    let threads = (items.len() / least.max(1)).clamp(1, THREADS);
    if threads == 1 {
        return;
    }
    let run = items.len().div_ceil(threads);
    let mut runs = Vec::with_capacity(threads);
    while items.len() > run {
        runs.push(items.split_off(items.len() - run));
    }
    runs.push(items);
    std::thread::scope(|scope| {
        for run in runs {
            let _ = Builder::new().spawn_scoped(scope, move || drop(run));
        }
    });
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::CommandExt;

    use super::*;

    #[test]
    fn dropping_in_runs_drops_every_item_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static DROPPED: AtomicUsize = AtomicUsize::new(0);
        struct Counted;
        impl Drop for Counted {
            fn drop(&mut self) {
                DROPPED.fetch_add(1, Ordering::Relaxed);
            }
        }
        for count in [0, 1, 5, 1000, 4097] {
            DROPPED.store(0, Ordering::Relaxed);
            drop_in_runs((0..count).map(|_| Counted).collect(), 100);
            assert_eq!(DROPPED.load(Ordering::Relaxed), count);
        }
    }

    #[test]
    fn runs_cover_every_item_once_in_order() {
        for count in [0, 1, 7, 64, 1000] {
            let items: Vec<usize> = (0..count).collect();
            for least in [1, 3, 100] {
                let runs = runs(&items, least, <[usize]>::to_vec);
                assert!(runs.len() <= THREADS);
                assert_eq!(runs.concat(), items, "{count} {least}");
                if count < 2 * least {
                    assert!(runs.len() <= 1, "{count} {least}");
                }
            }
        }
    }

    #[test]
    fn work_runs_on_the_calling_thread_when_no_thread_can_start() {
        const CHILD: &str = "CAMPAIGN_MONITOR_NO_THREADS";
        if std::env::var_os(CHILD).is_some() {
            assert!(
                Builder::new().spawn(|| ()).is_err(),
                "RLIMIT_NPROC refused no thread"
            );
            assert_eq!(each(&[1, 2, 3], |n| n * 2), [2, 4, 6]);
            let text = r#"{"format": 1, "observed_ms": 5, "state": "/s", "config": null, "probes": 0,
                "held_probes": [], "space": {"free_bytes": 1, "free_inodes": 1},
                "jobs": [{"id": "j"}], "findings": [{"id": "f"}], "failure_groups": []}"#;
            let snapshot = crate::rows::read(text).expect("the derived reader accepts the text");
            assert_eq!(snapshot.findings[0].id, "f");
            println!("NO_THREADS_OK");
            return;
        }
        // The kernel enforces `RLIMIT_NPROC` on unprivileged users only.
        // SAFETY: `geteuid` is safe to call unconditionally.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let mut command = std::process::Command::new(exe);
        command
            .args([
                "--exact",
                "--nocapture",
                "parallel::tests::work_runs_on_the_calling_thread_when_no_thread_can_start",
            ])
            .env(CHILD, "1");
        // SAFETY: `setrlimit` is async-signal-safe, touches only the child
        // between `fork` and `exec`, and the limit struct lives on the
        // closure's stack.
        unsafe {
            command.pre_exec(|| {
                let limit = libc::rlimit {
                    rlim_cur: 1,
                    rlim_max: 1,
                };
                if libc::setrlimit(libc::RLIMIT_NPROC, &limit) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        let output = command.output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success() && stdout.contains("NO_THREADS_OK"),
            "{}\n{stdout}\n{stderr}",
            output.status
        );
    }
}

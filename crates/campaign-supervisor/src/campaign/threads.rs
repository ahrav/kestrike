//! Threaded reads preserve result order and return the lowest-index
//! error. Every descriptor a worker opens is closed on that worker, and
//! results carry data alone.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use super::Error;

const WORKERS: usize = 16;

/// The result of `read` on each of `items`, in item order.
///
/// # Errors
///
/// The error of the lowest-index item whose read fails. Threads take items
/// in index order, so every item below a failing one was taken before it
/// and is read in full; a thread that sees a failure takes no new item.
pub(super) fn read_all<T: Sync, R: Send>(
    items: &[T],
    read: impl Fn(&T) -> Result<R, Error> + Sync,
) -> Result<Vec<R>, Error> {
    let workers = if crate::step::scripted_thread() {
        1
    } else {
        std::thread::available_parallelism()
            .map_or(1, std::num::NonZero::get)
            .min(WORKERS)
            .min(items.len())
    };
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    let work = || {
        let mut done = Vec::new();
        while !failed.load(Ordering::Relaxed) {
            let index = next.fetch_add(1, Ordering::Relaxed);
            let Some(item) = items.get(index) else {
                break;
            };
            let result = read(item);
            failed.fetch_or(result.is_err(), Ordering::Relaxed);
            done.push((index, result));
        }
        done
    };
    let mut done = if workers <= 1 {
        work()
    } else {
        std::thread::scope(|scope| {
            let threads: Vec<_> = (1..workers)
                .map_while(|_| std::thread::Builder::new().spawn_scoped(scope, work).ok())
                .collect();
            let mut done = work();
            for thread in threads {
                done.extend(
                    thread
                        .join()
                        .unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
                );
            }
            done
        })
    };
    done.sort_unstable_by_key(|(index, _)| *index);
    done.into_iter().map(|(_, result)| result).collect()
}

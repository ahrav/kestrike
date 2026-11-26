use std::sync::Barrier;

use super::threads::read_all;
use crate::store::Store;
use crate::store::fixture::Case;

/// Dropping `store` releases its lock while `read_all` workers remain
/// active.
#[test]
fn workers_hold_no_copy_of_another_store_lock() {
    if std::thread::available_parallelism().map_or(1, std::num::NonZero::get) < 2 {
        return;
    }
    let case = Case::new();
    let store = Store::open(&case.state).unwrap();
    let entered = Barrier::new(3);
    let release = Barrier::new(3);
    std::thread::scope(|scope| {
        let reader = scope.spawn(|| {
            read_all(&[0_u8, 1], |_| {
                entered.wait();
                release.wait();
                Ok(())
            })
        });
        entered.wait();
        drop(store);
        let reopened = Store::open(&case.state);
        release.wait();
        reader.join().unwrap().unwrap();
        assert!(
            reopened.is_ok(),
            "the dropped lock stays held while workers read: {:?}",
            reopened.err()
        );
    });
}

#[test]
fn read_all_reads_every_item_when_the_host_refuses_a_thread() {
    const CHILD: &str = "CAMPAIGN_THREAD_LIMIT_CASE";
    if std::env::var_os(CHILD).is_some() {
        crate::sys::restrict_process_limit(1, 1).unwrap();
        assert!(
            std::thread::Builder::new().spawn(|| ()).is_err(),
            "the process limit refuses a thread"
        );
        let items: Vec<u8> = (0..4).collect();
        let read = read_all(&items, |item| Ok(u32::from(*item) * 2)).unwrap();
        assert_eq!(read, [0, 2, 4, 6]);
        return;
    }
    if std::thread::available_parallelism().map_or(1, std::num::NonZero::get) < 2
        || crate::sys::euid() == 0
    {
        return;
    }
    let _processes = crate::store::fixture::processes();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "campaign::threads_tests::read_all_reads_every_item_when_the_host_refuses_a_thread",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{:?}\n{}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("test result: ok. 1 passed; 0 failed; 0 ignored;"),
        "the child must complete exactly one test\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
}

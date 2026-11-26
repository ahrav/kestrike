//! At most one `Serving` holds the SIGTERM disposition: while one is live, a
//! second `Serving::start` panics before it installs a handler or clears the
//! live loop's close request, and a start after the first is dropped
//! succeeds.

use std::panic::catch_unwind;
use std::time::Duration;

use super::serving::Serving;

/// The libtest ID of `a_second_start_beside_a_live_serving_panics_and_leaves_sigterm_as_it_was`, under which a child process runs that test's body.
const ID: &str =
    "net::serving_tests::a_second_start_beside_a_live_serving_panics_and_leaves_sigterm_as_it_was";
const LIMIT: Duration = Duration::from_secs(600);

/// The process's SIGTERM action as comparable parts: handler, flags and the mask's membership of signals 1 through 64, the signal range of x86-64 and aarch64 Linux.
fn sigterm_action() -> (libc::sighandler_t, libc::c_int, Vec<bool>) {
    // SAFETY: a zeroed `sigaction` is a valid out-parameter, a null new action reads the disposition without changing it, and `sigismember` reads the mask `sigaction` filled.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        assert_eq!(
            libc::sigaction(libc::SIGTERM, std::ptr::null(), &mut action),
            0
        );
        let mask = (1..=64)
            .map(|signal| libc::sigismember(&action.sa_mask, signal) == 1)
            .collect();
        (action.sa_sigaction, action.sa_flags, mask)
    }
}

/// Installs the process's own SIGTERM action again through the C library. The C library can add a restorer flag to an action it installs, as glibc does on x86_64, so after this call a later restore of the action reads back equal to it.
fn reinstall_inherited() {
    // SAFETY: reads the process's action and installs the same action; a zeroed `sigaction` is a valid out-parameter.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        assert_eq!(
            libc::sigaction(libc::SIGTERM, std::ptr::null(), &mut action),
            0
        );
        assert_eq!(
            libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut()),
            0
        );
    }
}

/// A start that must be refused: its panic's message, with any `Serving` it built dropped.
fn refused_start() -> String {
    let panic = catch_unwind(|| Serving::start(LIMIT))
        .err()
        .expect("a second start beside a live Serving returned a second Serving");
    panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap_or_default()
        .to_owned()
}

/// In a process of its own, one live `Serving` holds SIGTERM: a second start panics with the ownership message and leaves the installed action and the live loop's pending close request as they were, twice over; dropping the first restores the inherited action, and a later start then succeeds and installs the same handler again.
#[test]
fn a_second_start_beside_a_live_serving_panics_and_leaves_sigterm_as_it_was() {
    crate::exact_child::run(ID, Duration::from_secs(30), || {
        reinstall_inherited();
        let inherited = sigterm_action();
        let first = Serving::start(LIMIT);
        let held = sigterm_action();
        assert_ne!(
            held.0, inherited.0,
            "the live Serving installed its handler"
        );
        // SAFETY: raises SIGTERM on this thread, whose handler `Serving::start` installed.
        assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
        assert!(Serving::requested(), "the live loop saw its close request");

        for attempt in 0..2 {
            let message = refused_start();
            assert!(
                message.contains("one serving loop owns SIGTERM at a time"),
                "attempt {attempt} panicked with `{message}`"
            );
            assert_eq!(
                sigterm_action(),
                held,
                "attempt {attempt}: the refused start left the SIGTERM action alone"
            );
            assert!(
                Serving::requested(),
                "attempt {attempt}: the refused start kept the live loop's close request"
            );
        }

        drop(first);
        assert_eq!(
            sigterm_action(),
            inherited,
            "dropping the one Serving restores the inherited action"
        );
        let later = Serving::start(LIMIT);
        assert_eq!(
            sigterm_action(),
            held,
            "a start after the drop holds SIGTERM again"
        );
        assert!(!Serving::requested(), "a new loop starts with no request");
        assert!(
            refused_start().contains("one serving loop owns SIGTERM at a time"),
            "the later Serving is the one owner in its turn"
        );
        drop(later);
        assert_eq!(sigterm_action(), inherited);
    });
}

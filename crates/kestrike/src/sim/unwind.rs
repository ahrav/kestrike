//! A run's panic identity: the panic's source location and payload text.
//! A hook installed once per process records each panic's location and
//! text on its thread, and [`caught`] names the panic that unwound out of
//! its run by that panic's own payload, matched to the last panic recorded
//! since that `caught` began with the same text, so a panic caught and
//! handled during the unwind, by a nested `caught` included, leaves the
//! escaping panic's identity in place; a handled panic with the escaping
//! panic's exact text lends it its location. Two panics at different
//! locations, or with different text payloads, have different identities.
//! The hook passes every panic on to the hook it replaced, so a panic still
//! prints as it did.

use std::any::Any;
use std::cell::RefCell;
use std::panic::{self, AssertUnwindSafe, PanicHookInfo};
use std::sync::Once;

thread_local! {
    /// This thread's panics within the enclosing [`caught`] calls: each
    /// location and payload text. Each call owns the entries from its own
    /// start and removes them when it returns.
    static PANICS: RefCell<Vec<(String, String)>> = const { RefCell::new(Vec::new()) };
}

static INSTALLED: Once = Once::new();

/// Installs the identity hook in front of the process's current hook, once
/// per process; a later call returns at once.
pub(crate) fn install() {
    INSTALLED.call_once(|| {
        let prior = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            let entry = (location(info), text(info.payload()));
            let _ = PANICS.try_with(|panics| panics.borrow_mut().push(entry));
            prior(info);
        }));
    });
}

/// The panic's `file:line:column`.
fn location(info: &PanicHookInfo<'_>) -> String {
    info.location().map_or_else(
        || "an unknown location".into(),
        |at| format!("{}:{}:{}", at.file(), at.line(), at.column()),
    )
}

/// A payload's text when it is a `&str` or a `String`, on one line with
/// its control characters and backslashes escaped as Rust escapes them; a
/// payload of another type is the fixed marker `a non-text payload`, so
/// such panics at one location share an identity.
fn text(payload: &(dyn Any + Send)) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|text| (*text).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .map_or_else(
            || "a non-text payload".into(),
            |text| text.escape_debug().to_string(),
        )
}

/// Runs `run` under `catch_unwind`, with the identity hook installed.
///
/// # Errors
///
/// The identity of the panic that unwound out of `run`: `location: text`,
/// with the location of the last panic this thread recorded during `run`
/// with that text, or `an unknown location` when it recorded none.
pub(crate) fn caught<T>(run: impl FnOnce() -> T) -> Result<T, String> {
    install();
    let start = PANICS.with(|panics| panics.borrow().len());
    let result = panic::catch_unwind(AssertUnwindSafe(run));
    let recorded: Vec<(String, String)> =
        PANICS.with(|panics| panics.borrow_mut().drain(start..).collect());
    result.map_err(|payload| {
        let text = text(&*payload);
        let at = recorded
            .into_iter()
            .rev()
            .find(|(_, recorded)| *recorded == text)
            .map(|(at, _)| at);
        format!("{}: {text}", at.as_deref().unwrap_or("an unknown location"))
    })
}

#[cfg(test)]
mod tests {
    use super::caught;

    /// A panic's identity names its location and payload: two panics at
    /// different lines differ, as do two payloads at one line; a payload
    /// with a line break stays on one line; a non-text payload is the fixed
    /// marker; and a returning run passes its value through.
    #[test]
    fn a_panic_is_identified_by_its_location_and_payload() {
        let first = caught(|| panic!("one")).unwrap_err();
        let line = line!() - 1;
        assert!(
            first.starts_with(&format!("{}:{line}:", file!())),
            "{first}"
        );
        assert!(first.ends_with(": one"), "{first}");
        let other = caught(|| panic!("two")).unwrap_err();
        assert_ne!(first, other);
        let at = |text: &'static str| caught(move || panic!("{text}")).unwrap_err();
        let (left, right) = (at("left"), at("right"));
        assert_eq!(
            left.strip_suffix("left"),
            right.strip_suffix("right"),
            "one location"
        );
        assert_ne!(left, right);
        assert!(at("a\nb").ends_with(": a\\nb"));
        assert_ne!(at("a\nb"), at("a\\nb"), "a backslash escapes apart");
        let boxed = caught(|| std::panic::panic_any(3_u8)).unwrap_err();
        assert!(boxed.ends_with(": a non-text payload"), "{boxed}");
        assert_eq!(caught(|| 5), Ok(5));
    }

    /// Records its panic's identity when dropped during an unwind.
    struct Nested;

    impl Drop for Nested {
        fn drop(&mut self) {
            let _ = std::panic::catch_unwind(|| panic!("a handled panic"));
        }
    }

    struct Scoped;

    impl Drop for Scoped {
        fn drop(&mut self) {
            let inner = caught(|| panic!("a handled panic")).unwrap_err();
            assert!(inner.starts_with(file!()), "{inner}");
        }
    }

    /// A panic caught and handled while the run unwinds leaves the escaping
    /// panic's identity in place.
    #[test]
    fn a_panic_handled_during_the_unwind_keeps_the_escaping_identity() {
        let identity = caught(|| {
            let _nested = Nested;
            panic!("the escaping panic");
        })
        .unwrap_err();
        assert!(identity.ends_with(": the escaping panic"), "{identity}");
        assert!(identity.starts_with(file!()), "{identity}");
        let identity = caught(|| {
            let _scoped = Scoped;
            panic!("the escaping panic");
        })
        .unwrap_err();
        assert!(identity.ends_with(": the escaping panic"), "{identity}");
        assert!(identity.starts_with(file!()), "{identity}");
    }
}

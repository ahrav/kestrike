//! Device-boundary evidence: the write commands a publishing attempt's
//! device accepted, each with the terminal the device delivered for it, and
//! the census that reconciles captured device events with recorded rows.
//!
//! A live adapter builds this evidence from the simulated device's capture,
//! which records each command at acceptance and each completion the device
//! produced as it is delivered into the caller's sink. The census is a count-and-ordinal
//! reconciliation over the capture alone, anchored at ordinal 0 and at the
//! device's own count of accepted commands, then a check that every command
//! a row names is a captured write bound to the row's attempt. A command
//! omitted from both the capture and the rows still leaves a gap against
//! the device's count, and a terminal missing from both leaves its command
//! undelivered, which the publication rule refuses.

use super::action::ActionKind;
use super::row::Row;

/// One write command the device accepted for an attempt: its token, device
/// range and acceptance ordinal, and the terminal delivered for it, `None`
/// while none was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CommandEvidence {
    pub(crate) token: u64,
    pub(crate) start: u64,
    pub(crate) len: u32,
    pub(crate) ordinal: u64,
    /// `Some(true)` for a delivered success terminal, `Some(false)` for a
    /// delivered failure.
    pub(crate) delivered: Option<bool>,
}

impl CommandEvidence {
    pub(crate) const fn succeeded(&self) -> bool {
        matches!(self.delivered, Some(true))
    }
}

/// One captured device-boundary event, in the oracle's own terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BoundaryEvent {
    Submitted {
        token: u64,
        write: bool,
        start: u64,
        len: u32,
        ordinal: u64,
    },
    Delivered {
        token: u64,
        success: bool,
    },
}

/// One accepted command as the census tracks it.
#[derive(Debug, Clone, Copy)]
struct Accepted {
    token: u64,
    write: bool,
    start: u64,
    len: u32,
    ordinal: u64,
}

/// Reconciles a device capture with the rows recorded from it.
///
/// The capture must be complete (`overflow` false) and hold exactly the
/// `accepted` commands the device counted, with acceptance ordinals rising
/// by one from 0; each token must be accepted while it has no outstanding
/// command and delivered at most once after its acceptance; and every
/// command a write-completion or write-submission row names must be a
/// captured write with the same range and ordinal, bound by `bindings` to
/// the row's serial, whose recorded terminal the capture delivered. A
/// write completion names each captured write bound to its serial once.
/// Every captured write carries exactly one write binding.
///
/// # Errors
///
/// The first gap, with the token or ordinal it names.
pub(crate) fn census(
    events: &[BoundaryEvent],
    (overflow, counted): (bool, u64),
    bindings: &[(u64, u64)],
    rows: &[Row],
) -> Result<(), String> {
    if overflow {
        return Err("the device capture overflowed its bound; its evidence is incomplete".into());
    }
    let mut accepted: Vec<Accepted> = Vec::new();
    let mut outstanding: Vec<u64> = Vec::new();
    let mut delivered: Vec<(u64, u64, bool)> = Vec::new();
    for event in events {
        match *event {
            BoundaryEvent::Submitted {
                token,
                write,
                start,
                len,
                ordinal,
            } => {
                let expected = accepted.last().map_or(0, |last| last.ordinal + 1);
                if ordinal != expected {
                    return Err(format!(
                        "acceptance ordinal {ordinal} where {expected} is next"
                    ));
                }
                if outstanding.contains(&token) {
                    return Err(format!(
                        "token {token} accepted while its command is outstanding"
                    ));
                }
                outstanding.push(token);
                accepted.push(Accepted {
                    token,
                    write,
                    start,
                    len,
                    ordinal,
                });
            }
            BoundaryEvent::Delivered { token, success } => {
                let Some(at) = outstanding.iter().position(|&t| t == token) else {
                    return Err(format!(
                        "token {token} delivered with no outstanding command"
                    ));
                };
                outstanding.remove(at);
                let ordinal = accepted
                    .iter()
                    .rev()
                    .find(|a| a.token == token)
                    .map_or(0, |a| a.ordinal);
                delivered.push((token, ordinal, success));
            }
        }
    }
    if accepted.len() as u64 != counted {
        return Err(format!(
            "the capture holds {} accepted commands, the device counted {counted}",
            accepted.len()
        ));
    }
    for write in accepted.iter().filter(|a| a.write) {
        match bindings
            .iter()
            .filter(|&&(token, _)| token == write.token)
            .count()
        {
            1 => {}
            0 => {
                return Err(format!(
                    "a captured write, token {} ordinal {}, has no binding",
                    write.token, write.ordinal
                ));
            }
            _ => {
                return Err(format!(
                    "a captured write, token {} ordinal {}, has more than one binding",
                    write.token, write.ordinal
                ));
            }
        }
    }
    for row in rows.iter().filter(|row| {
        matches!(
            row.kind,
            ActionKind::WriteCompleted | ActionKind::WriteSubmit
        )
    }) {
        let commands = row.commands.as_deref().unwrap_or_default();
        let mut named: Vec<u64> = Vec::with_capacity(commands.len());
        for command in commands {
            let captured = accepted.iter().any(|a| {
                a.write
                    && a.token == command.token
                    && a.start == command.start
                    && a.len == command.len
                    && a.ordinal == command.ordinal
            });
            if !captured {
                return Err(format!(
                    "a recorded command, token {} ordinal {}, is no captured write",
                    command.token, command.ordinal
                ));
            }
            if let Some(serial) = row.serial
                && !bindings.contains(&(command.token, serial.0.get()))
            {
                return Err(format!(
                    "a recorded command, token {}, is bound to another attempt than serial {}",
                    command.token,
                    serial.0.get()
                ));
            }
            if let Some(success) = command.delivered
                && !delivered.contains(&(command.token, command.ordinal, success))
            {
                return Err(format!(
                    "the terminal recorded for token {} ordinal {} was not delivered",
                    command.token, command.ordinal
                ));
            }
            if named.contains(&command.token) {
                return Err(format!(
                    "a recorded command, token {} ordinal {}, is recorded twice",
                    command.token, command.ordinal
                ));
            }
            named.push(command.token);
        }
        if row.kind == ActionKind::WriteCompleted
            && let Some(serial) = row.serial
            && let Some(missing) = accepted.iter().find(|a| {
                a.write
                    && bindings.contains(&(a.token, serial.0.get()))
                    && !named.contains(&a.token)
            })
        {
            return Err(format!(
                "a captured write bound to serial {}, token {} ordinal {}, is not recorded",
                serial.0.get(),
                missing.token,
                missing.ordinal
            ));
        }
    }
    Ok(())
}

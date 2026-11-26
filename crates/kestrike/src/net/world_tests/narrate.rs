//! The narrative of a bundle: its records in stream order as named fields,
//! written to a new file, so an operator reads a retained run without a
//! decoder of their own.
//!
//! The narrative renders bytes `trace::load` accepted: the whole input
//! passes the format, checkpoint and record-count checks and its recorded
//! manifest parses within its own record maximum, as a replay admits a
//! bundle, before any line is written. A stream that ends before its
//! terminal's checkpoint, a run that ended in an infrastructure class, and
//! a narrative whose decoder cannot read its own executable are incomplete
//! evidence, and the header says so. Rendering walks the raw records, which
//! hold the clocks, turn times, outcomes and order `Loaded` keeps apart or
//! drops. Every rendered record shows the bytes no named field covers as
//! `spare@OFFSET=hex`, OFFSET counted from the record's first byte, a closed
//! code outside its table as `unknown(N)`, and a sentinel or saturated value
//! by its meaning, so every byte of a rendered record reads back from its line.
//!
//! Names come from this decoder's tables, interpreted in the world the
//! recorded profile names: mixed, cluster or recovery. Workload codes
//! collide across worlds, so a profile this decoder does not list leaves
//! its workload candidates, and a disk candidate's cell or ordinal, spare.
//! A mixed world's second owner has its own workload codes, and its disk
//! candidates read `owner=peer` beside its device's ordinal.
//! The header prints the pins the bundle recorded beside the decoder's own.
//!
//! Turns are numbered from zero in stream order. A clock move after `N`
//! turns is boundary `N`; an event belongs to the turn or clock it was
//! recorded after. The run's settlement follows every turn: its entropy
//! refusal, identity, coverage and stop events, a cluster run's `OBSERVED`
//! event recorded after its coverage event, a violation whose identity
//! names the settled site, and the terminal. A mixed or cluster turn that
//! collected a GET or PUT result names it, and a recovery turn names none;
//! the failure tier renders the whole bundle's failure view, which
//! [`mod@failure`] describes.

use std::io::Write;

use crate::sim::action::ActionKind;
use crate::sim::choice::Domain::{self, Disk, Link, Put, Workload};
use crate::sim::manifest::Manifest;
use crate::sim::trace::{Infrastructure, Loaded, PAYLOAD, RECORD, Tag, Terminal, is_semantic};

use super::branch::hex;
use super::bundle::{
    ACT, AUDIT, ENTROPY, FAILURE, IDENTITY, IDENTITY_VERSION, OBSERVED, PUT, RULE, STOP, Site,
    UPLOAD, WITNESS, stop_name,
};
use super::cluster::{COVERAGE, WINDOW};

/// Records the narrative reads unless `--max-records` names another bound.
pub(crate) const MAX_RECORDS: u64 = 1_000_000;

const REFUSED: i32 = 2;
const INCOMPLETE: i32 = 3;

/// The world whose vocabulary names a bundle's workload candidates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum World {
    Mixed,
    Cluster,
    Recovery,
    /// The recorded profile is not one this decoder lists.
    Unknown,
}

impl World {
    /// The world `manifest`'s profile names in this decoder's catalog.
    pub(crate) fn of(manifest: &Manifest) -> Self {
        match super::bundle::named(&manifest.profile, manifest.root).map(|named| named.1.world) {
            Some(super::WorldKind::Mixed) => Self::Mixed,
            Some(super::WorldKind::Cluster(_)) => Self::Cluster,
            Some(super::WorldKind::Recovery(_)) => Self::Recovery,
            None => Self::Unknown,
        }
    }
}

/// How a field's bytes read and print.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Form {
    /// An integer of at most eight bytes, little-endian unless `big`.
    Int {
        big: bool,
    },
    Hex,
    /// Text, printed without its trailing zero bytes and with other bytes
    /// escaped.
    Text,
}

/// One named field: `len` bytes at record offset `at`. An integer with a
/// `table` prints the name the table gives its value. A value outside its
/// table prints its decimal for an open table, `sat`, `max:WORD` or a list
/// whose last name is empty, and `unknown(N)` for every other table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Spec {
    pub(crate) name: &'static str,
    pub(crate) at: usize,
    pub(crate) len: usize,
    pub(crate) form: Form,
    pub(crate) table: Option<&'static str>,
}

/// A field's decoded value: an integer, or the bytes of a hex or text field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Value {
    Int(u64),
    Bytes(Vec<u8>),
}

/// A rendered record: its label, each field with its value, each run of
/// nonzero bytes no field covers with its record offset, and a note: what
/// its encoding cannot hold, its stop's name, or what this decoder skips.
pub(crate) struct Decoded {
    pub(crate) label: String,
    pub(crate) fields: Vec<(Spec, Value)>,
    pub(crate) spare: Vec<(usize, Vec<u8>)>,
    pub(crate) note: Option<String>,
}

/// The fields `layout` lists, space-separated, each `NAME@AT:LEN` at
/// payload offset `AT`, then `b` for a big-endian integer, `x` for hex or
/// `t` for text; a one-byte integer drops `:LEN`. `=TABLE` names values:
/// comma-separated names from value 0, an empty name naming nothing, or
/// one of the tables [`named`] resolves.
///
/// # Panics
///
/// On a field without `@` or with an offset or length that is no number, a
/// length of zero, or, once [`named`] reads it, a table it does not know;
/// every layout is a constant of this file.
pub(crate) fn specs(layout: &'static str) -> impl Iterator<Item = Spec> {
    layout.split_whitespace().map(|field| {
        let (field, table) = match field.split_once('=') {
            Some((field, table)) => (field, Some(table)),
            None => (field, None),
        };
        let (name, place) = field.split_once('@').expect("a field names its offset");
        let (at, size) = place.split_once(':').unwrap_or((place, "1"));
        let (len, form) = match size.as_bytes().last() {
            Some(b'b') => (&size[..size.len() - 1], Form::Int { big: true }),
            Some(b'x') => (&size[..size.len() - 1], Form::Hex),
            Some(b't') => (&size[..size.len() - 1], Form::Text),
            _ => (size, Form::Int { big: false }),
        };
        let number = |text: &str| text.parse::<usize>().expect("a field offset or length");
        Spec {
            name,
            at: 4 + number(at),
            len: Some(number(len))
                .filter(|len| *len > 0)
                .expect("a field of one byte or more"),
            form,
            table,
        }
    })
}

/// The mixed world's workload codes below its action codes; the `peer-`
/// codes are a second owner's own poll, client poll and disk service.
const MIXED: &str = ",owner-poll,client-poll,service,deliver,script,peer-owner-poll,\
    peer-client-poll,peer-service";
const CLUSTER: &str = ",owner-poll,client-poll,service,read,prepare,supply,outcome,probe,cover,,,,,,,\
    get,put,invalidate,cancel";
const OBLIGATIONS: &str = "none,Bytes,History,Custody,Resources,Restart,Progress,Isolation,Contain";
const CLASSES: &str = "Harness,Injected,Modeled,Containment,Production";
const REASONS: &str = ",Lost,RuleDrop,Isolated,Duplicated,Stale,Delayed,Reordered,Truncated,\
    Corrupted,Inapplicable,WouldBlock,CallFailed,DeadEnd,Missed,Full,ForeignPeer,Oversize,\
    NotHoldable,PrematureReturn,Altered,DeviceRefused,DeviceInjected,DeviceLost,Unattributed,\
    DeviceOmitted,DeviceFalseStopped,LostBurst,LostResend";
/// An activation's landing words, by count; at most four fit, so a larger count leaves spare.
const LANDING: [&str; 5] = [
    "",
    "landing@12:8",
    "landing@12:8 landing@20:8",
    "landing@12:8 landing@20:8 landing@28:8",
    "landing@12:8 landing@20:8 landing@28:8 landing@36:8",
];
const UPLOADS: &str = "uncollected,,published,failed,not-started,unknown";
const PUTS: &str = ",begin,prepare,supply,defer,cancel,abandon,outcome,retry";
const CHANGES: &str = ",began,emitted,consumed,intended";
const FLAGS: &str = "none,false,true";

/// The name `table` gives `value`, a field of `len` bytes, or `None`.
/// An uppercase table is one of this file's lists; `action` names an
/// action kind, `mixed` a mixed workload code, `message` a frame kind,
/// `class1` an audit class plus one, `variant` a failure variant whose bit
/// 7 marks a truncated failure, `flags` a capture's packed reorder and
/// truncation decisions, `status` a request status, `drained` an
/// activation's packed drained bit and evidence; `max:WORD` names the
/// field's largest value WORD and `sat` prints that value as saturated.
/// Any other table is a comma-separated list from value 0.
///
/// # Panics
///
/// For an uppercase table that names no list, or another table that is
/// neither one of those names nor holds a comma.
pub(crate) fn named(table: &str, value: u64, len: usize) -> Option<String> {
    let max = u64::MAX >> (64 - 8 * len.min(8));
    let list = |list: &str, value: u64| {
        let name = list.split(',').nth(usize::try_from(value).ok()?)?;
        (!name.is_empty()).then(|| name.to_owned())
    };
    let table = match table {
        "CLUSTER" => CLUSTER,
        "OBLIGATIONS" => OBLIGATIONS,
        "REASONS" => REASONS,
        "UPLOADS" => UPLOADS,
        "CLASSES" => CLASSES,
        "PUTS" => PUTS,
        "CHANGES" => CHANGES,
        alias if alias.starts_with(|first: char| first.is_ascii_uppercase()) => {
            panic!("no list is named {alias}")
        }
        table => table,
    };
    match table {
        "action" => {
            ActionKind::from_code(u8::try_from(value).ok()?).map(|kind| format!("{kind:?}"))
        }
        "mixed" => list(MIXED, value)
            .or_else(|| named("action", value.checked_sub(u64::from(super::ACTION))?, 1)),
        "status" => super::super::frame::Status::from_wire(u16::try_from(value).ok()?)
            .map(|status| format!("{status:?}")),
        "message" if value == 0 => Some("none".into()),
        "message" => super::super::frame::Kind::from_wire(u8::try_from(value).ok()?)
            .map(|kind| format!("{kind:?}")),
        "class1" if value == 0 => Some("none".into()),
        "class1" => list(CLASSES, value - 1),
        "variant" if value == 4 => Some("audit".into()),
        "variant" => {
            let name = list(",violation,oracle,unsuccessful", value & 0x7f)?;
            Some(if value & 0x80 == 0 {
                name
            } else {
                name + "+truncated"
            })
        }
        "flags" => Some(format!(
            "{}/{}",
            list(FLAGS, value & 3)?,
            list(FLAGS, value >> 2)?
        )),
        "drained" => {
            let evidence = list("attributed,ambiguous,unmatched", value >> 1)?;
            Some(format!("{}/{evidence}", list("no,yes", value & 1)?))
        }
        "sat" => (value == max).then(|| format!("{value}(saturated)")),
        _ => match table.strip_prefix("max:") {
            Some(word) => (value == max).then(|| word.to_owned()),
            None if table.contains(',') => list(table, value),
            None => panic!("no table is named {table}"),
        },
    }
}

/// The fields of an audit record's canonical code at payload offset 1, in
/// an `AUDIT` event and an audit's violation record alike, and the note on
/// its last byte, which packs the link end it faced with the actor's high
/// byte four bits up.
const AUDIT_RECORD: &str = "class@1=CLASSES reason@2=REASONS reason_arg@3 reason_arg2@4 \
    place@5=,link,device actor_low@6 toward_xor_actor_high@7:1x";
const PACKED: &str = "toward_xor_actor_high holds the link end XORed with the actor's high \
    byte shifted 4 bits up, so an actor above 4095 or an end above 15 does not read back";

/// Whether a failure variant, bit 7 masked, names a rule.
fn names_rule(variant: u8) -> bool {
    (1..=3).contains(&(variant & 0x7f))
}

/// The fields of a violation record or a `FAILURE` or `OBSERVED` event,
/// with its note.
fn failure(payload: &[u8]) -> (Vec<&'static str>, Option<String>) {
    if payload[0] == 4 {
        return (vec!["variant@0=variant", AUDIT_RECORD], Some(PACKED.into()));
    }
    if !names_rule(payload[0]) {
        return (vec!["variant@0=variant"], None);
    }
    let cut = usize::from(payload[2]) == PAYLOAD - 3;
    let note = cut.then(|| "the rule may continue past its 41 recorded bytes".into());
    let layout = "variant@0=variant obligation@1=OBLIGATIONS length@2 rule@3:41t";
    (vec![layout], note)
}

/// The fields of a turn's candidate, at payload offset 8, its outcome, at
/// offset 24, in `world`, and its request observation, at offset 32, as
/// [`super::bundle::Collected::code`] lays it out; a turn that observed
/// nothing, as every turn of a build that records no request results,
/// names no request field.
fn turn(world: World, payload: &[u8]) -> Vec<&'static str> {
    let mut layouts = vec!["now_us@0:8 domain@8=,Workload,Disk,Link,Clock,Entropy,Put,Persistence"];
    let (domain, code) = (Domain::from_code(payload[8]), payload[9]);
    layouts.push(match (domain, world) {
        (Some(Workload), World::Mixed) if code == super::SCRIPT => {
            "code@9=mixed actor@10 step@11:4b"
        }
        (Some(Workload), World::Mixed) if code == super::DELIVER => {
            "code@9=mixed actor@10 update@11:4b kind@15=action"
        }
        (Some(Workload), World::Mixed) => "code@9=mixed actor@10 arg@11:4b",
        (Some(Workload), World::Cluster) => {
            "code@9=CLUSTER cell@10 client@11 arg@12:4b key@16 slot@17"
        }
        (Some(Workload), World::Recovery) => "code@9=,fill,crash,relaunch,lookup,hold operation@10",
        (Some(Disk), World::Cluster) => {
            "stage@9=,execute,post,admit cell@10 ordinal@11:7b op@18=read,write sectors@19:2b \
                start_unit@21:3b"
        }
        (Some(Disk), World::Unknown) => {
            "stage@9=,execute,post,admit op@18=read,write sectors@19:2b start_unit@21:3b"
        }
        // A second owner's device writes one in its ordinal's top byte.
        (Some(Disk), World::Mixed) if payload[10] != 0 => {
            "stage@9=,execute,post,admit owner@10=,peer ordinal@11:7b op@18=read,write \
                sectors@19:2b start_unit@21:3b"
        }
        (Some(Disk), World::Mixed | World::Recovery) => {
            "stage@9=,execute,post,admit ordinal@10:8b op@18=read,write sectors@19:2b \
                start_unit@21:3b"
        }
        (Some(Link), _) => "event@9=,,,,release net@10 nth@11:4b",
        (Some(Put), _) if code == 3 => "action@9=PUTS key@10:4b attempt@14:2b fragment@16:4b",
        (Some(Put), _) if code == 4 => "action@9=PUTS key@10:4b attempt@14:2b ready_us@16:4b",
        (Some(Put), _) => "action@9=PUTS key@10:4b attempt@14:2b arg@16:4b",
        _ => "",
    });
    // Cluster codes 4 to 8 are read through probe, and 16 to 19 get
    // through cancel: the operations whose outcome 0 is a refusal.
    layouts.push(match (world, domain, code) {
        (World::Mixed | World::Cluster, Some(Workload), super::CLIENT_POLL)
        | (World::Mixed, Some(Workload), super::PEER_CLIENT_POLL) => "received@24:4 sent@28:4",
        (World::Mixed, Some(Workload), super::SCRIPT) => "outcome@24:8=max:stay",
        (World::Mixed, Some(Workload), super::DELIVER) => {
            "outcome@24:8=,,delivered,rekeyed,rekey-busy,rekey-refused,rekey-cut,rekey-zero"
        }
        (World::Mixed, Some(Workload), code) if code > super::ACTION => "outcome@24:8=refused,",
        (World::Mixed, Some(Put), _) => "outcome@24:8=refused,",
        (World::Cluster, Some(Workload), 4..=8 | 16..=19) => "outcome@24:8=refused,",
        _ => "outcome@24:8",
    });
    let request = "request@32=,get-complete,get-missing,get-pressure,get-failed,get-incomplete,\
        put-published,put-failed,put-not-started,put-unknown,multiple";
    if payload[32] != 0 {
        layouts.push(request);
    }
    layouts.push(match payload[32] {
        1 | 2 | 6 | 8 | 9 => "request_client@35:2 request_owner@37:2",
        3..=5 | 7 => "status@33:2=status request_client@35:2 request_owner@37:2",
        _ => "",
    });
    layouts
}

/// The fields of the event of `kind` with `payload`, and its note.
fn event(kind: u8, payload: &[u8]) -> (Vec<&'static str>, Option<String>) {
    let (layout, note) = match kind {
        ACT | WITNESS => ("action@0=action outcome@1:8", None),
        PUT => (
            "action@0=action attempt@1:2 session@3:8 fragment@11:4 supplied@15:16x \
                held_until_us@31:8 outcome@39:4",
            Some("outcome holds the low 32 bits of the action's outcome"),
        ),
        UPLOAD => (
            "attempt@0:2 serial@2:8 base@10:4 grant@14:4 held_slots@18:2 outcome@20=UPLOADS \
                bound@21=no,yes",
            None,
        ),
        AUDIT => return (vec!["net@0", AUDIT_RECORD], Some(PACKED.into())),
        FAILURE | OBSERVED => return failure(payload),
        RULE => (
            "net@0 tap@1:2 link@3:2 toward@5 ordinal@6:8 message@14=message index@15:4=max:none \
                dropped@19=no,fault,rule,isolated,burst,resend rule_at@20:2 duplicate@22=no,yes \
                delay@23:8=max:none reorder_truncate@31=flags \
                corrupt@32=none,Header,Tag,GetBody,PutBody,Unsupported",
            Some(
                "rule_at holds the low 16 bits of the rule index; index and delay print none at \
                their largest value, which their encoder also writes for absent",
            ),
        ),
        crate::sim::ledger::LEDGER => {
            let stage = "stage@0=,planned,reached,activated,recovered,checked,skipped cut@1:4";
            let rest = match payload[0] {
                2 => "queue@5:2",
                3 => {
                    let class = "class@5=,ProcessDeath,HostOrDevice,ControllerReset,\
                        ReplacementAttach queue@6:2 held@8:2 words@10 drained_evidence@11=drained";
                    let landing = LANDING.get(usize::from(payload[10])).copied().unwrap_or("");
                    return (vec![stage, class, landing], None);
                }
                5 => "verdict@5=,pass,fail",
                _ => "",
            };
            return (vec![stage, rest], None);
        }
        super::super::witness::OBSERVATION => (
            match payload[0] {
                1 => {
                    "change@0=CHANGES op@1:4 peer@5 slot@6:2 generation@8:8 epoch@16:8 \
                        effect@24=live,exclusion,freshness effect_fields@25:17x"
                }
                2 => "change@0=CHANGES op@1:4",
                3 => {
                    "change@0=CHANGES peer@1 slot@2:2 generation@4:8 epoch@12:8 \
                        acknowledged@20=no,yes"
                }
                4 => "change@0=CHANGES op@1:4 digest@5:32x",
                _ => "change@0=CHANGES",
            },
            None,
        ),
        ENTROPY => (
            "actor@0:2 site@2:2 incarnation@4:4 error@8:36t",
            Some("error holds at most the first 36 bytes of the refusal"),
        ),
        STOP => {
            let layout = "class@0 detail@1 composed@2=no,yes checked@3:8 owners@11:2 clients@13:2";
            let note = format!("stop {}", stop_name((payload[0], payload[1])));
            return (vec![layout], Some(note));
        }
        COVERAGE => (
            "owners@0 keys@1 hot@2 published@3:4=sat hits@7:4=sat misses@11:4=sat \
                refused@15:4=sat invalidated@19:4=sat cancelled@23:4=sat cross@27:4=sat \
                reused@31:4=sat healthy@35:4=sat faults@39:4=sat",
            None,
        ),
        WINDOW => (
            "index@0:4 verdict@4=not-passed,passed carried@5:4=sat registry@9:4=sat \
                outstanding@13:4=sat kept@17:4=sat published@21:4=sat hits@25:4=sat \
                faults@29:4=sat reused@33:4=sat healed@37:4=sat",
            None,
        ),
        IDENTITY if payload[0] != IDENTITY_VERSION => (
            "version@0",
            Some("this decoder reads the fields of identity version 2 alone"),
        ),
        IDENTITY => (
            "version@0 variant@1=variant obligation@2=OBLIGATIONS class@3=class1 \
                site@4=,run,settled length@5:2=sat hash@7:32x",
            None,
        ),
        _ => ("", None),
    };
    (vec![layout], note.map(str::to_owned))
}

/// The name of event kind `kind`.
pub(crate) fn kind_name(kind: u8) -> Option<&'static str> {
    let names = ",ACT,WITNESS,PUT,UPLOAD,AUDIT,FAILURE,RULE,OBSERVED,LEDGER,OBSERVATION,ENTROPY,\
        STOP,COVERAGE,WINDOW,IDENTITY";
    names
        .split(',')
        .nth(usize::from(kind))
        .filter(|name| !name.is_empty())
}

/// The label, fields and note of `record` in `world`.
fn layout(world: World, record: &[u8; RECORD]) -> (String, Vec<&'static str>, Option<String>) {
    let payload = &record[4..];
    match Tag::from_code(record[0]) {
        Some(Tag::Turn) => (String::new(), turn(world, payload), None),
        Some(Tag::Clock) => (String::new(), vec!["now_us@0:8"], None),
        Some(Tag::Violation) => {
            let (layouts, note) = failure(payload);
            ("violation".into(), layouts, note)
        }
        Some(Tag::Terminal) => {
            let class = match payload[0] {
                1 => {
                    "class@0=,complete outcome@1=,pass,violation,inconclusive,unsuccessful \
                    fired@2:1x required@3:1x"
                }
                2 => "class@0=,complete,infrastructure infrastructure@1=,sink,cap,truncated,defect",
                _ => "class@0=,complete,infrastructure",
            };
            let work = "turns@4:8 decisions@12:8 progress@20:8 virtual_us@28:8 skipped_us@36:8";
            ("terminal".into(), vec![class, work], None)
        }
        Some(Tag::Event) => {
            let label = match kind_name(record[1]) {
                Some(name) => format!("event {name}"),
                None => format!("event unknown({})", record[1]),
            };
            let (layouts, note) = event(record[1], payload);
            (label, layouts, note)
        }
        _ => (format!("tag {}", record[0]), Vec::new(), None),
    }
}

/// `record`'s fields in `world`: every named field with its value, and
/// every run of nonzero bytes outside the tag byte, an event's kind byte
/// and the named fields.
pub(crate) fn decode(world: World, record: &[u8; RECORD]) -> Decoded {
    let (label, layouts, note) = layout(world, record);
    let mut covered = [false; RECORD];
    covered[0] = true;
    covered[1] = record[0] == Tag::Event as u8;
    let fields = layouts
        .into_iter()
        .flat_map(specs)
        .map(|spec| {
            let bytes = &record[spec.at..spec.at + spec.len];
            covered[spec.at..spec.at + spec.len].fill(true);
            let mut word = [0; 8];
            let value = match spec.form {
                Form::Int { big: true } => {
                    word[8 - spec.len..].copy_from_slice(bytes);
                    Value::Int(u64::from_be_bytes(word))
                }
                Form::Int { big: false } => {
                    word[..spec.len].copy_from_slice(bytes);
                    Value::Int(u64::from_le_bytes(word))
                }
                Form::Hex | Form::Text => Value::Bytes(bytes.to_vec()),
            };
            (spec, value)
        })
        .collect();
    let mut spare: Vec<(usize, Vec<u8>)> = Vec::new();
    for (at, &byte) in record.iter().enumerate() {
        match spare.last_mut() {
            _ if covered[at] || byte == 0 => {}
            Some((start, bytes)) if *start + bytes.len() == at => bytes.push(byte),
            _ => spare.push((at, vec![byte])),
        }
    }
    Decoded {
        label,
        fields,
        spare,
        note,
    }
}

impl Decoded {
    /// The record as one line: its label, `name=value` fields, spare runs
    /// and note.
    pub(crate) fn line(&self) -> String {
        let mut parts = vec![self.label.clone()];
        for (spec, value) in &self.fields {
            let shown = match value {
                Value::Int(value) => {
                    let open = |table: &str| table.ends_with(',') || table.starts_with("max:");
                    match spec.table.and_then(|name| named(name, *value, spec.len)) {
                        Some(name) => name,
                        None if spec.table.is_some_and(|t| !open(t) && t != "sat") => {
                            format!("unknown({value})")
                        }
                        None => value.to_string(),
                    }
                }
                Value::Bytes(bytes) if spec.form == Form::Text => {
                    let end = bytes
                        .iter()
                        .rposition(|&byte| byte != 0)
                        .map_or(0, |at| at + 1);
                    format!("\"{}\"", bytes[..end].escape_ascii())
                }
                Value::Bytes(bytes) => hex(bytes),
            };
            parts.push(format!("{}={shown}", spec.name));
        }
        for (at, bytes) in &self.spare {
            parts.push(format!("spare@{at}={}", hex(bytes)));
        }
        if let Some(note) = &self.note {
            parts.push(format!("({note})"));
        }
        parts.retain(|part| !part.is_empty());
        parts.join(" ")
    }
}

/// Where a record stands in the run: before the first clock, at the clock
/// boundary after `N` turns, at turn `N`, or at settlement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Place {
    Setup,
    Clock(u64),
    Turn(u64),
    Settle,
}

impl Place {
    /// The place as a narrative line names it.
    fn label(self) -> String {
        match self {
            Self::Setup => "setup".to_owned(),
            Self::Clock(turns) => format!("clock {turns}"),
            Self::Turn(turn) => format!("turn {turn}"),
            Self::Settle => "settle".to_owned(),
        }
    }
}

/// Each record's place. The settlement starts at its first entropy,
/// identity, coverage or stop event, at a violation whose next semantic
/// record is a version-2 identity naming the settled site, or at the
/// terminal, and holds every record after it up to a later turn or clock.
pub(crate) fn places(records: &[[u8; RECORD]]) -> Vec<Place> {
    let (mut place, mut turns, mut settled) = (Place::Setup, 0, false);
    let mut out = Vec::with_capacity(records.len());
    for (at, record) in records.iter().enumerate() {
        let settled_identity = |next: &[u8; RECORD]| {
            next[..2] == [Tag::Event as u8, IDENTITY]
                && next[4] == IDENTITY_VERSION
                && next[8] == Site::Settled as u8
        };
        settled |= match Tag::from_code(record[0]) {
            Some(Tag::Event) => [ENTROPY, IDENTITY, COVERAGE, STOP].contains(&record[1]),
            Some(Tag::Violation) => records[at + 1..]
                .iter()
                .find(|next| is_semantic(next[0]))
                .is_some_and(settled_identity),
            tag => tag == Some(Tag::Terminal),
        };
        place = match Tag::from_code(record[0]) {
            Some(Tag::Turn) => {
                (turns, settled) = (turns + 1, false);
                Place::Turn(turns - 1)
            }
            Some(Tag::Clock) => {
                settled = false;
                Place::Clock(turns)
            }
            _ if settled => Place::Settle,
            _ => place,
        };
        out.push(place);
    }
    out
}

/// What the narrative selects: the turns `from..to` at `tier`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Window {
    pub(crate) from: u64,
    pub(crate) to: u64,
    pub(crate) tier: Tier,
}

/// What a narrative renders of its window: its turns, also the clocks and
/// events among them, or the whole bundle's failure view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tier {
    Turns,
    Events,
    Failure,
}

impl Window {
    /// For each record, `None` when it does not render, else its mark: ""
    /// inside the window, " context" outside it. Turns and clock boundaries
    /// `from..to` lie inside. Turns render inside the window, every
    /// violation and the terminal always; at [`Tier::Events`], clocks and events
    /// inside the window, the last clock before boundary `from` when no
    /// clock at `from` opens a nonempty window, and every failure, observed
    /// failure, entropy, identity, coverage and stop event.
    pub(crate) fn select(
        self,
        records: &[[u8; RECORD]],
        places: &[Place],
    ) -> Vec<Option<&'static str>> {
        let inside = |place: &Place| matches!(place, Place::Turn(at) | Place::Clock(at) if (self.from..self.to).contains(at));
        let opens = self.from < self.to && places.contains(&Place::Clock(self.from));
        let before = records
            .iter()
            .zip(places)
            .rposition(|(record, place)| {
                record[0] == Tag::Clock as u8
                    && matches!(place, Place::Clock(at) if *at < self.from)
            })
            .filter(|_| self.tier == Tier::Events && !opens);
        let global = [FAILURE, OBSERVED, ENTROPY, IDENTITY, COVERAGE, STOP];
        let events = self.tier == Tier::Events;
        let picked = records.iter().zip(places).enumerate();
        picked
            .map(|(at, (record, place))| {
                let shown = match Tag::from_code(record[0]) {
                    Some(Tag::Turn) => inside(place),
                    Some(Tag::Clock) => events && (inside(place) || before == Some(at)),
                    Some(Tag::Event) => events && (inside(place) || global.contains(&record[1])),
                    tag => matches!(tag, Some(Tag::Violation | Tag::Terminal)),
                };
                shown.then(|| if inside(place) { "" } else { " context" })
            })
            .collect()
    }
}

/// A decoder's executable digest, or why it cannot read itself, and its
/// platform.
pub(crate) type Pins = (Result<String, String>, String);

/// Writes the narrative of `bytes`, which loaded as `loaded` under its
/// recorded `manifest`, to `out`: a header naming its record counts,
/// digest, completeness, terminal, the recorded pins beside `decoder`'s,
/// where its names come from and the window, then one line per selected
/// record, or at [`Tier::Failure`] the failure view. A violation that no
/// version-2 identity event follows notes that its site is unrecorded, a
/// rule violation names its full rule as the catalog resolves it, and a
/// mixed script turn notes its step's name, `unknown` unless the bundle pins
/// this decoder. Returns the records rendered.
///
/// # Errors
///
/// A failed write.
pub(crate) fn write(
    out: &mut impl Write,
    (bytes, loaded, manifest): (&[u8], &Loaded, &Manifest),
    window: Window,
    (own, platform): &Pins,
) -> std::io::Result<u64> {
    let (records, tail) = bytes.as_chunks::<RECORD>();
    let counts: Vec<String> = (1..=u8::MAX)
        .filter_map(|code| Tag::from_code(code).map(|tag| (code, tag)))
        .map(|(code, tag)| {
            let count = records.iter().filter(|record| record[0] == code).count();
            format!("{}={count}", format!("{tag:?}").to_lowercase())
        })
        .collect();
    let evidence = match (loaded.terminal, own) {
        (Terminal::Infrastructure(Infrastructure::Truncated), _) => {
            "incomplete: the stream ends before its terminal's checkpoint"
        }
        (Terminal::Infrastructure(_), _) => "incomplete: the run ended in an infrastructure class",
        (_, Err(_)) => "incomplete: the decoder cannot read its own executable",
        (Terminal::Complete { .. }, Ok(_)) => "complete",
    };
    let (decoder, same) = match own {
        Ok(digest) => (digest.clone(), *digest == manifest.executable),
        Err(reason) => (format!("unreadable ({reason})"), false),
    };
    let here = same && *platform == manifest.platform;
    let provenance = if here {
        "this decoder's tables, built into the executable the bundle pins"
    } else {
        "this decoder's tables; the bundle pins another executable or platform, or the decoder \
            cannot read itself, so names and the world assume this decoder's layouts and catalog"
    };
    let world = World::of(manifest);
    let vocabulary = match world {
        World::Unknown => "a profile outside this catalog: workload and disk-ordinal bytes spare",
        World::Mixed => "the mixed world; script steps by index, named when pinned here",
        World::Cluster => "the cluster world",
        World::Recovery => "the recovery world",
    };
    let tier = format!("{:?}", window.tier).to_lowercase();
    let (whole, trailing, counts) = (records.len(), tail.len(), counts.join(" "));
    let (from, to, turns) = (window.from, window.to, loaded.turns.len());
    let Manifest {
        executable,
        platform: pinned,
        profile,
        root,
        scenario,
        build,
        toolchain,
        ..
    } = manifest;
    let [pinned, profile, scenario, toolchain] =
        [pinned, profile, scenario, toolchain].map(|text| format!("{text:?}"));
    writeln!(
        out,
        "narrative: 1\nrecords: {whole} whole, {trailing} trailing bytes; {counts}\n\
        digest: {digest}\nevidence: {evidence}\nterminal: {terminal}\n\
        pins: executable={executable} platform={pinned} build={build} toolchain={toolchain}\n\
        decoder: executable={decoder} platform={platform}\nnames: {provenance}; {vocabulary}\n\
        profile: {profile} root={root} scenario={scenario}\n\
        window: turns {from}..{to} of {turns}, tier {tier}",
        digest = hex(&loaded.digest),
        terminal = super::branch::terminal_text(loaded.terminal),
    )?;
    let places = places(records);
    if window.tier == Tier::Failure {
        return failure::write(out, (records, &places, world), loaded, manifest);
    }
    let script = super::bundle::named(&manifest.profile, manifest.root).filter(|_| here);
    let mut rendered = 0;
    for (at, mark) in window.select(records, &places).into_iter().enumerate() {
        let Some(mark) = mark else {
            continue;
        };
        let place = places[at].label();
        let decoded = decode(world, &records[at]);
        let mut line = decoded.line();
        if records[at][0] == Tag::Violation as u8 {
            let identity = failure::identity_after(records, at).map(|at| &records[at]);
            if identity.is_none() {
                line.push_str(" (site unrecorded: no version-2 identity event follows)");
            }
            line.extend(failure::note(&records[at], identity));
        }
        let step = decoded.fields.iter().find(|(spec, _)| spec.name == "step");
        if let Some((_, Value::Int(step))) = step {
            let step = script
                .as_ref()
                .and_then(|named| named.1.script.get(*step as usize));
            let name = step.map_or("unknown", |step| step.name);
            line.push_str(&format!(" (step {name})"));
        }
        writeln!(out, "#{at} {place}{mark}: {line}")?;
        rendered += 1;
    }
    Ok(rendered)
}

/// The narrative form's command line after `--narrate`.
struct Command<'a> {
    bundle: &'a str,
    output: &'a str,
    tier: Tier,
    from: Option<u64>,
    to: Option<u64>,
    max_records: Option<u64>,
}

fn parse(args: &[String]) -> Result<Command<'_>, String> {
    let (bundle, flags) = args
        .split_first()
        .ok_or("--narrate takes BUNDLE --output FILE")?;
    let (mut output, mut events, mut failure) = (None, false, false);
    let (mut from, mut to, mut max_records) = (None, None, None);
    let mut flags = flags.iter().map(String::as_str);
    while let Some(flag) = flags.next() {
        let slot = match flag {
            "--events" if !events => {
                events = true;
                continue;
            }
            "--failure" if !failure => {
                failure = true;
                continue;
            }
            "--output" if output.is_none() => {
                output = Some(flags.next().ok_or("--output needs a value")?);
                continue;
            }
            "--from" => &mut from,
            "--to" => &mut to,
            "--max-records" => &mut max_records,
            flag => return Err(format!("{flag}: unknown or repeated after --narrate")),
        };
        let value = flags.next().ok_or(format!("{flag} needs a value"))?;
        let count = value
            .parse::<u64>()
            .ok()
            .filter(|count| count.to_string() == value);
        match (count, &slot) {
            (Some(count), None) => *slot = Some(count),
            (None, _) => return Err(format!("{flag} {value}: not a canonical count")),
            _ => return Err(format!("{flag} given twice")),
        }
    }
    let output = output.ok_or("--output is required")?;
    if failure && (events || from.is_some() || to.is_some()) {
        return Err("--failure covers the whole bundle: no --events, --from or --to".into());
    }
    let tier = match (events, failure) {
        (true, _) => Tier::Events,
        (_, true) => Tier::Failure,
        _ => Tier::Turns,
    };
    Ok(Command {
        bundle,
        output,
        tier,
        from,
        to,
        max_records,
    })
}

/// Writes `error: REASON` to `err`, REASON cut within 4096 bytes at a character boundary and
/// marked ` [cut]`, so a refusal or host failure stays far below the launcher's stream bound.
fn complain(err: &mut impl Write, code: i32, reason: &str) -> i32 {
    let end = reason.floor_char_boundary(4096);
    let cut = if end < reason.len() { " [cut]" } else { "" };
    let _ = writeln!(err, "error: {}{cut}", &reason[..end]);
    code
}

/// The bytes of the regular file at `path`, opened once without blocking on
/// a FIFO or taking a terminal as the controlling one, when it holds at most
/// `max` whole records; the exit code and reason of
/// a refusal or a host failure otherwise. A `max` of 0, or one whose byte
/// limit, `max + 1` records, overflows a `u64`, is refused before the
/// open. A path whose open fails, as a socket's does, is refused as
/// irregular when its metadata names another kind of file.
pub(crate) fn bounded(path: &str, max: u64) -> Result<Vec<u8>, (i32, String)> {
    let limit = max
        .checked_add(1)
        .and_then(|n| n.checked_mul(RECORD as u64));
    if max == 0 || limit.is_none() {
        return Err((
            REFUSED,
            format!("--max-records {max}: not a readable bound"),
        ));
    }
    use std::os::unix::fs::OpenOptionsExt;
    let host = |error: std::io::Error| (INCOMPLETE, error.to_string());
    let irregular = || (REFUSED, "not a regular file".to_owned());
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .map_err(|error| match (error.kind(), std::fs::metadata(path)) {
            (std::io::ErrorKind::NotFound, _) => (REFUSED, error.to_string()),
            (_, Ok(metadata)) if !metadata.is_file() => irregular(),
            _ => host(error),
        })?;
    let metadata = file.metadata().map_err(host)?;
    if !metadata.is_file() {
        return Err(irregular());
    }
    let past = || (REFUSED, format!("more than {max} records"));
    if metadata.len() / RECORD as u64 > max {
        return Err(past());
    }
    let bytes = crate::sim::trace::read(&file, max).map_err(host)?;
    if (bytes.len() / RECORD) as u64 > max {
        return Err(past());
    }
    Ok(bytes)
}

/// Runs the narrative form over `args`, the arguments after `--narrate`:
/// `BUNDLE --output FILE [--events] [--from N] [--to N] [--max-records N]`
/// or `BUNDLE --output FILE --failure [--max-records N]`, each flag at most
/// once. `decoder` names this executable; it runs once
/// the bundle is admitted and FILE is created. Writes one line to `out`,
/// and refusals and host failures to `err`.
///
/// Exit 0 when a complete bundle rendered; 2 for a refused command line, a
/// missing or irregular BUNDLE, one past `--max-records` or its recorded
/// manifest's maximum, one that does not load or records no manifest that
/// parses, a window outside `0 <= from <= to <= turns`, or a FILE that
/// exists; 3 when the bundle is incomplete evidence, the decoder cannot
/// read itself, the host cannot read BUNDLE, create or write FILE or print
/// the line, naming the partial FILE a failed write leaves.
pub(crate) fn run(
    args: &[String],
    decoder: impl FnOnce() -> Pins,
    out: &mut impl Write,
    err: &mut impl Write,
) -> i32 {
    let command = match parse(args) {
        Ok(command) => command,
        Err(reason) => return complain(err, REFUSED, &reason),
    };
    let (path, output) = (command.bundle, command.output);
    let max = command.max_records.unwrap_or(MAX_RECORDS);
    let admitted = bounded(path, max).and_then(|bytes| {
        let (loaded, manifest) =
            super::replay::recorded(&bytes).map_err(|refusal| (REFUSED, format!("{refusal:?}")))?;
        Ok((bytes, loaded, manifest))
    });
    let (bytes, loaded, manifest) = match admitted {
        Ok(admitted) => admitted,
        Err((code, reason)) => return complain(err, code, &format!("bundle {path}: {reason}")),
    };
    let turns = loaded.turns.len() as u64;
    let window = Window {
        from: command.from.unwrap_or(0),
        to: command.to.unwrap_or(turns),
        tier: command.tier,
    };
    if window.from > window.to || window.to > turns {
        let (from, to) = (window.from, window.to);
        let reason = format!("--from {from} --to {to}: outside the {turns} turns");
        return complain(err, REFUSED, &reason);
    }
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output);
    let file = match file {
        Ok(file) => std::io::BufWriter::new(file),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            return complain(err, REFUSED, &format!("output {output}: {error}"));
        }
        Err(error) => return complain(err, INCOMPLETE, &format!("output {output}: {error}")),
    };
    let input = (bytes.as_slice(), &loaded, &manifest);
    emit((file, output), input, window, &decoder(), out, err)
}

/// Writes the narrative of `input` within `window` into `sink`, the new
/// file `output` names, and prints its one line to `out`: exit 0 for a
/// complete bundle `decoder` read, 3 for incomplete evidence or a decoder
/// that cannot read itself, and 3 for a failed write or flush, which names
/// the partial file on `err`, or a failed write of that line.
pub(crate) fn emit(
    (mut sink, output): (impl Write, &str),
    input: (&[u8], &Loaded, &Manifest),
    window: Window,
    decoder: &Pins,
    out: &mut impl Write,
    err: &mut impl Write,
) -> i32 {
    let written = write(&mut sink, input, window, decoder)
        .and_then(|rendered| sink.flush().map(|()| rendered));
    let rendered = match written {
        Ok(rendered) => rendered,
        Err(error) => {
            let reason = format!("output {output}: {error}; {output} holds a partial narrative");
            return complain(err, INCOMPLETE, &reason);
        }
    };
    let complete = matches!(input.1.terminal, Terminal::Complete { .. }) && decoder.0.is_ok();
    let evidence = if complete { "complete" } else { "incomplete" };
    let records = input.0.len() / RECORD;
    let printed = writeln!(
        out,
        "narrate: {output}: {rendered} of {records} records, {evidence}"
    );
    if let Err(error) = printed.and_then(|()| out.flush()) {
        let reason = format!("stdout: {error}; {output} holds the whole narrative");
        return complain(err, INCOMPLETE, &reason);
    }
    if complete { 0 } else { INCOMPLETE }
}

mod failure;
pub(crate) mod rules;

#[cfg(test)]
pub(crate) mod tests;

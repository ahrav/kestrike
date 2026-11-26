use super::admission::{self, AdmissionError};
use super::assignment::AuthenticatedAssignment;
use super::assignment_tests::{other_record, record, sample, verified};
use super::record::{Binding, LocalRecord, RecordError};

fn binding() -> Binding {
    record().binding().clone()
}

/// An AZ observation `admit` may make at most once.
type Observe<'a> = Box<dyn FnOnce() -> Result<String, AdmissionError> + 'a>;

/// The admission-order witness over `admit`: the sample assignment admits, and with each check and every later
/// observation bad the earliest check refuses, the AZ being observed only once the three earlier checks pass.
fn refuses_in_order(
    admit: impl Fn(&AuthenticatedAssignment, &str, Observe<'_>, &str) -> Result<Binding, AdmissionError>,
) {
    let a = sample();
    let valid = verified(&a);
    assert_eq!(
        admit(
            &valid,
            &a.instance,
            Box::new(|| Ok(a.az.clone())),
            &a.volume
        ),
        Ok(binding())
    );
    let failures = [
        AdmissionError::Instance,
        AdmissionError::Volume,
        AdmissionError::DeleteOnTermination,
        AdmissionError::Az,
    ];
    for (at, expected) in failures.iter().enumerate() {
        let mut a = sample();
        let (mut instance, mut volume, mut az) =
            (a.instance.clone(), a.volume.clone(), Ok(a.az.clone()));
        for later in &failures[at..] {
            match later {
                AdmissionError::Instance => instance = "i-clone".into(),
                AdmissionError::Volume => volume = "vol-0fffffffffffffff0".into(),
                AdmissionError::DeleteOnTermination => a.delete_on_termination = Some(true),
                AdmissionError::Az => az = Ok("us-east-1b".into()),
                _ => unreachable!(),
            }
        }
        let valid = verified(&a);
        assert_eq!(
            admit(
                &valid,
                &instance,
                Box::new(|| {
                    assert_eq!(
                        *expected,
                        AdmissionError::Az,
                        "AZ observed before an earlier refusal"
                    );
                    az
                }),
                &volume
            ),
            Err(*expected)
        );
    }
}

/// The admission checks refuse in instance, volume, deletion observation and AZ order, each with every later observation also bad, and an assignment that passes all four yields its (instance, volume, attachment) binding. The AZ observation runs only once the three earlier checks pass.
#[test]
fn admission_refuses_in_instance_volume_deletion_az_order() {
    refuses_in_order(|assignment, instance, az: Observe<'_>, volume| {
        admission::admit(assignment, instance, az, volume)
    });
}

/// The negative control "the AZ observed first": an admission that observes the AZ before its instance check, then
/// decides as `admission::admit` does on the value it observed, makes the observation the witness forbids while the
/// instance check still refuses.
#[test]
#[should_panic(expected = "AZ observed before an earlier refusal")]
fn negative_control_an_admission_that_observes_the_az_first_fails_the_order() {
    refuses_in_order(|assignment, instance, az: Observe<'_>, volume| {
        let observed = az();
        admission::admit(assignment, instance, || observed, volume)
    });
}

/// Only an explicit `false` deletion observation admits: an unknown observation and `true` both refuse `DeleteOnTermination` before the AZ is observed.
#[test]
fn deletion_requires_an_explicit_false_observation() {
    for deletion in [None, Some(true)] {
        let mut a = sample();
        a.delete_on_termination = deletion;
        let valid = verified(&a);
        assert_eq!(
            admission::admit(&valid, &a.instance, || panic!("AZ observed"), &a.volume),
            Err(AdmissionError::DeleteOnTermination),
            "{deletion:?}"
        );
    }
}

/// The fresh path draws a record only at `E = 0`, redrawing an all-zero host ID and keeping the supplied binding and key. It returns a landed valid record of the same binding and key incarnation without drawing; draws over an absent record, a sector that fails decoding and a record that differs in any one binding field; refuses `Key` for a record of the same binding with another key incarnation and passes on the record read's error, both without drawing; and refuses `AttemptConsumed` at every `E > 0` before reading the record or drawing.
#[test]
fn fresh_records_only_at_attempt_zero() {
    let key = record().pair().key;
    let mut draws = vec![[0; 16], [5; 16]].into_iter();
    let fresh = admission::fresh(binding(), key, 0, || Ok(None), || draws.next()).unwrap();
    assert_eq!(fresh.pair().exhid.bytes(), [5; 16]);
    assert_eq!(fresh.pair().key.encode(), (1u64 << 32) | 2);
    assert_eq!(fresh.binding(), &binding());
    assert_eq!(
        admission::fresh(
            binding(),
            key,
            0,
            || Ok(Some(Ok(record()))),
            || panic!("a bound record keeps its host ID")
        ),
        Ok(record())
    );
    let mut elsewhere = vec![Some(Err(RecordError::Torn)), Some(Ok(other_record()))];
    for field in 0..3 {
        let mut other = binding();
        match field {
            0 => other.instance = "i-0fffffffffffffff0".into(),
            1 => other.volume = "vol-0fffffffffffffff0".into(),
            _ => other.attachment = "attach-2".into(),
        }
        elsewhere.push(Some(Ok(
            LocalRecord::fresh(other, key, || Some([7; 16])).unwrap()
        )));
    }
    for existing in elsewhere {
        let drawn = admission::fresh(binding(), key, 0, || Ok(existing), || Some([5; 16])).unwrap();
        assert_eq!(drawn.pair(), fresh.pair());
        assert_eq!(drawn.binding(), &binding());
    }
    let other_key =
        LocalRecord::fresh(binding(), other_record().pair().key, || Some([7; 16])).unwrap();
    assert_eq!(
        admission::fresh(
            binding(),
            key,
            0,
            || Ok(Some(Ok(other_key))),
            || panic!("a key conflict draws nothing")
        ),
        Err(AdmissionError::Key)
    );
    assert_eq!(
        admission::fresh(
            binding(),
            key,
            0,
            || Err(AdmissionError::RecordCodec(RecordError::Length)),
            || panic!("an unreadable record draws nothing")
        ),
        Err(AdmissionError::RecordCodec(RecordError::Length))
    );
    assert_eq!(
        admission::fresh(binding(), key, 0, || Ok(None), || None),
        Err(AdmissionError::Entropy)
    );
    assert_eq!(
        admission::fresh(binding(), key, 0, || Ok(None), || Some([0; 16])),
        Err(AdmissionError::Entropy)
    );
    for attempt in [1, 2, u32::MAX] {
        assert_eq!(
            admission::fresh(
                binding(),
                key,
                attempt,
                || panic!("no record read at E > 0"),
                || panic!("no draw at E > 0")
            ),
            Err(AdmissionError::AttemptConsumed)
        );
    }
}

/// A connect accepts only a present, valid record bound to the assignment's instance, volume and attachment and holding its key incarnation, and returns it unchanged.
#[test]
fn connect_requires_the_bound_record() {
    let key = record().pair().key;
    assert_eq!(
        admission::validate_record(&binding(), key, Some(Ok(record()))),
        Ok(record())
    );
    assert_eq!(
        admission::validate_record(&binding(), key, None),
        Err(AdmissionError::Record)
    );
    assert_eq!(
        admission::validate_record(&binding(), key, Some(Err(RecordError::Torn))),
        Err(AdmissionError::RecordCodec(RecordError::Torn))
    );
    for field in 0..3 {
        let mut other = binding();
        match field {
            0 => other.instance = "i-0fffffffffffffff0".into(),
            1 => other.volume = "vol-0fffffffffffffff0".into(),
            _ => other.attachment = "attach-2".into(),
        }
        assert_eq!(
            admission::validate_record(&other, key, Some(Ok(record()))),
            Err(AdmissionError::Binding)
        );
    }
    assert_eq!(
        admission::validate_record(&binding(), other_record().pair().key, Some(Ok(record()))),
        Err(AdmissionError::Key)
    );
}

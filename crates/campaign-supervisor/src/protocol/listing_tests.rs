//! Capability listing tests: the parser requires each fact once and
//! refuses a removed, repeated, malformed or torn line for that line's own
//! reason.

use super::fixture::{LISTING, edited, twice, without};
use super::{Class, Error, Expected, Fails, Fixed, Form, Listing};

#[test]
fn the_listing_parses_every_fact_into_its_value() {
    let listing = Listing::parse(LISTING).expect("the fixture parses");
    assert_eq!(
        (listing.capabilities, listing.summary, listing.manifest),
        (2, 1, 2)
    );
    assert_eq!(listing.keys[0].form, Form::Version(2));
    assert_eq!(listing.keys[2].form, Form::Sha256);
    assert_eq!(
        listing.keys[3].form,
        Form::Count {
            min: 1,
            max: u64::MAX
        }
    );
    assert_eq!(listing.held, ["actors", "slots"]);
    let history = listing.profile("h1-get-unheld").expect("listed");
    assert_eq!(history.class, Class::History);
    assert_eq!(history.expected, Some(Expected::Unsuccessful));
    assert_eq!(
        history.held,
        [("actors".to_owned(), 7), ("slots".to_owned(), 1)]
    );
    assert_eq!(history.topology, None);
    let paired = listing.profile("h6-get").expect("listed");
    assert_eq!(
        paired.topology,
        Some(Fixed {
            owners: 2,
            clients: 4
        })
    );
    assert_eq!(
        listing.profile("recovery-512").map(|p| p.class),
        Some(Class::Recovery)
    );
    assert_eq!((listing.max_suffixes, listing.max_siblings), (16, 4));
    assert_eq!(listing.milestones, ["pending-put", "recovery-reached"]);
    assert_eq!(
        listing.topology,
        Fixed {
            owners: 1,
            clients: 2
        }
    );
    let cluster = listing.cluster("cluster-broad").expect("declared");
    assert_eq!(cluster.fields[1], ("owners".to_owned(), "2..4".to_owned()));
    let family = &listing.family;
    assert_eq!(
        (family.declared.name.as_str(), family.prefix.as_str()),
        ("settled-WORDS", "settled-")
    );
    assert_eq!(family.words, ["batched", "scaled"]);
    assert_eq!(
        family.held,
        [("actors".to_owned(), 7), ("slots".to_owned(), 1)]
    );
}

/// The milestone family patterns a worker lists under the `milestone:`
/// key, after the fixed names as the worker prints them, parse as
/// milestones in that order, and the rest of the listing parses as before.
/// The captured worker listing lists the same milestones.
#[test]
fn milestone_family_patterns_parse_beside_the_fixed_milestones() {
    let text = edited(
        LISTING,
        "milestone: recovery-reached\n",
        "milestone: recovery-reached\nmilestone: turn-N\nmilestone: script-N\n",
    );
    let listing = Listing::parse(&text).expect("the families parse");
    assert_eq!(
        listing.milestones,
        ["pending-put", "recovery-reached", "turn-N", "script-N"]
    );
    let captured = include_str!("../../testdata/worker-listing.txt");
    let captured = Listing::parse(captured).expect("the captured listing parses");
    assert_eq!(captured.milestones, listing.milestones);
    let fixed = Listing::parse(LISTING).expect("the fixture parses");
    assert_eq!(
        Listing {
            milestones: fixed.milestones.clone(),
            ..listing
        },
        fixed
    );
}

/// Each class and expected-ending word parses as its variant and no other
/// word does.
#[test]
fn each_profile_word_names_its_variant() {
    for (word, class) in [
        ("live", Class::Live),
        ("control", Class::Control),
        ("recovery", Class::Recovery),
        ("history", Class::History),
    ] {
        assert_eq!(Class::parse(word, "profile"), Ok(class), "{word}");
    }
    for (word, expected) in [
        ("pass", Expected::Pass),
        ("violation", Expected::Violation),
        ("unsuccessful", Expected::Unsuccessful),
    ] {
        assert_eq!(Expected::parse(word, "profile"), Ok(expected), "{word}");
    }
    assert_eq!(
        Class::parse("Live", "profile"),
        Err(Error::Value("profile"))
    );
    assert_eq!(
        Expected::parse("inconclusive", "profile"),
        Err(Error::Value("profile"))
    );
}

/// Each once-printed fact is required exactly once, and each list needs at
/// least one line; a repeated entry is refused by its name.
#[test]
fn each_listing_fact_is_required_exactly_once() {
    for key in [
        "capabilities",
        "summary",
        "manifest",
        "held",
        "branch",
        "topology",
        "key",
        "constraint",
        "profile",
        "family",
        "milestone",
        "cluster",
    ] {
        assert_eq!(
            Listing::parse(&without(LISTING, key)),
            Err(Error::Missing(key)),
            "{key} removed"
        );
        let Err(Error::Repeated(repeated)) = Listing::parse(&twice(LISTING, key)) else {
            panic!("{key} repeated parsed");
        };
        assert!(
            repeated == key || repeated.starts_with(&format!("{key} ")),
            "{key}: {repeated}"
        );
    }
    let renamed = edited(LISTING, "profile: planted ", "profile: upload ");
    assert_eq!(
        Listing::parse(&renamed),
        Err(Error::Repeated("profile upload".to_owned()))
    );
    let second = edited(
        LISTING,
        "milestone: pending-put",
        "family: rekey-WORDS words=fast each=at-most-once class=live,control-when-planted held=actors=7,slots=1\nmilestone: pending-put",
    );
    assert_eq!(
        Listing::parse(&second),
        Err(Error::Repeated("family".to_owned()))
    );
}

#[test]
fn listing_values_outside_their_form_are_refused() {
    let expected = Error::Inconsistent("only a history profile declares its expected ending");
    for (from, to, error) in [
        (
            "capabilities: 2",
            "capabilities: 6",
            Error::Value("capabilities"),
        ),
        (
            "capabilities: 2",
            "capabilities: 0",
            Error::Value("capabilities"),
        ),
        ("summary: 1", "summary: 01", Error::Value("summary")),
        ("summary: 1", "summary: 2", Error::Value("summary")),
        (
            "each=at-most-once",
            "each=unbounded",
            Error::Value("family"),
        ),
        (" each=at-most-once", "", Error::Value("family")),
        (
            "class=live,control-when-planted",
            "class=recovery",
            Error::Value("family"),
        ),
        (
            " class=live,control-when-planted",
            "",
            Error::Value("family"),
        ),
        (
            "configurable=no",
            "configurable=yes",
            Error::Value("topology"),
        ),
        (
            "clients=2 configurable",
            "clients=x configurable",
            Error::Value("topology"),
        ),
        (
            "actors=7,slots=1\nprofile: planted",
            "actors=7,actors=1\nprofile: planted",
            Error::Inconsistent("a profile's held bounds name other keys than the held line"),
        ),
        (
            "actors=7,slots=1\nprofile: planted",
            "actors=7\nprofile: planted",
            Error::Inconsistent("a profile's held bounds name other keys than the held line"),
        ),
        (
            "actors=7,slots=1\nprofile: planted",
            "slots=1,actors=7\nprofile: planted",
            Error::Inconsistent("a profile's held bounds name other keys than the held line"),
        ),
        ("version=2", "version=x", Error::Value("key")),
        (
            "max=18446744073709551615",
            "max=18446744073709551616",
            Error::Value("key"),
        ),
        (
            "actors=7,slots=1\nprofile: planted",
            "actors=-7,slots=1\nprofile: planted",
            Error::Value("profile"),
        ),
        ("class=live", "class=dead", Error::Value("profile")),
        ("suffixes=1..16", "suffixes=0x..16", Error::Value("branch")),
        (
            "owners=2..4 ",
            "owners=2..4 owners=3 ",
            Error::Repeated("cluster field owners".to_owned()),
        ),
        ("owners=2..4 ", "=2..4 ", Error::Value("cluster")),
        (
            "key: version version=2",
            "key: version version=3",
            Error::Inconsistent("a version key's form names another manifest version"),
        ),
        (
            "each=at-most-once class=live,control-when-planted held=actors=7,slots=1",
            "each=at-most-once class=live,control-when-planted held=slots=1,actors=7",
            Error::Inconsistent("the family's held bounds name other keys than the held line"),
        ),
        (
            "each=at-most-once class=live,control-when-planted held=actors=7,slots=1",
            "each=at-most-once class=live,control-when-planted held=actors=7",
            Error::Inconsistent("the family's held bounds name other keys than the held line"),
        ),
        ("words=batched,scaled ", "words= ", Error::Value("family")),
        (
            "words=batched,scaled ",
            "words=batched, ",
            Error::Value("family"),
        ),
        (
            "words=batched,scaled ",
            "words=batched,,scaled ",
            Error::Value("family"),
        ),
        (
            "words=batched,scaled ",
            "words=batched,batched ",
            Error::Repeated("family batched".to_owned()),
        ),
        (
            "family: settled-WORDS",
            "family: settled-NAMES",
            Error::Value("family"),
        ),
        ("owners=2..4 ", "owners= ", Error::Value("cluster")),
        (
            "clients=2 unavailable",
            "clients=x unavailable",
            Error::Value("cluster"),
        ),
        (
            "owners=2..4 keys",
            "owners=2-4 keys",
            Error::Value("cluster"),
        ),
        (
            "owners=2..4 keys",
            "owners=4..2 keys",
            Error::Value("cluster"),
        ),
        (
            "keys=3..6 clients",
            "keys=6..3 clients",
            Error::Value("cluster"),
        ),
        (" keys=3..6 clients", " clients", Error::Value("cluster")),
        (
            "words=batched,scaled",
            "words=batched,scaled-up",
            Error::Value("family"),
        ),
        (
            " clients=2 unavailable",
            " unavailable",
            Error::Value("cluster"),
        ),
        (
            "cluster: cluster-broad generator=1 owners=2..4 keys=3..6 clients=2 unavailable=node-lifecycle,membership",
            "cluster: cluster-broad",
            Error::Value("cluster"),
        ),
        (
            "cluster: cluster-broad generator=1",
            "cluster: h6-get generator=1",
            Error::Inconsistent("a cluster line names a profile with its own topology"),
        ),
        (
            "each=at-most-once class=live,control-when-planted held=actors=7,slots=1",
            "each=at-most-once",
            Error::Value("family"),
        ),
        ("words=batched,scaled ", "", Error::Value("family")),
        (
            "family: settled-WORDS",
            "family:  settled-WORDS",
            Error::Value("family"),
        ),
        (
            "milestone: pending-put",
            "milestone: ",
            Error::Value("milestone"),
        ),
        ("held: actors,slots", "held: actors,", Error::Value("held")),
        ("profile: upload ", "profile:  ", Error::Value("profile")),
        (
            "actors=7,slots=1\nprofile: planted",
            "actors=7,=1\nprofile: planted",
            Error::Value("profile"),
        ),
        (
            "owners=2..4 ",
            "owners ",
            Error::Unpaired("owners".to_owned()),
        ),
        ("expected=unsuccessful ", "", expected.clone()),
        (
            "upload class=live support=implemented campaign=unqualified held=actors=7,slots=1\n",
            "upload class=live support=implemented campaign=unqualified held=actors=7,slots=1 owners=2 clients=4\n",
            Error::Inconsistent("only a history profile declares its own topology"),
        ),
        (
            "slots=1 owners=2 clients=4",
            "slots=1 owners=2",
            Error::Value("profile"),
        ),
        (
            "upload class=live ",
            "upload class=live expected=pass ",
            expected,
        ),
        (
            "cluster: cluster-broad",
            "cluster: cluster-other",
            Error::Inconsistent("a cluster line names no listed profile"),
        ),
        (
            "milestone: pending-put",
            "milestones: pending-put",
            Error::Unknown("milestones".to_owned()),
        ),
        (
            "milestone: pending-put",
            "milestone pending-put",
            Error::Unpaired("milestone pending-put".to_owned()),
        ),
    ] {
        assert_eq!(
            Listing::parse(&edited(LISTING, from, to)),
            Err(error),
            "{from} -> {to}"
        );
    }
}

#[test]
fn each_listing_version_reads_its_own_profile_grammar() {
    let paired = LISTING
        .lines()
        .find(|line| line.starts_with("profile: h6-get "))
        .expect("the fixture lists a two-owner history");
    let first = edited(LISTING, "capabilities: 2", "capabilities: 1");
    let plain = edited(&first, &format!("{paired}\n"), "");
    assert_eq!(Listing::parse(&first), Err(Error::Value("profile")));
    let parsed = Listing::parse(&plain).expect("a version 1 listing parses");
    assert_eq!(parsed.capabilities, 1);
    assert!(
        parsed
            .profiles
            .iter()
            .all(|profile| profile.topology.is_none())
    );
    let second = Listing::parse(LISTING).expect("a version 2 listing parses");
    let third = Listing::parse(&edited(LISTING, "capabilities: 2", "capabilities: 3"))
        .expect("a version 3 listing parses");
    assert_eq!((second.capabilities, third.capabilities), (2, 3));
    assert_eq!(second.profiles, third.profiles);
    assert!(third.capabilities >= super::RULE_CATALOG && second.capabilities < super::RULE_CATALOG);
}

/// A version 4 listing declares the failure of each history that expects
/// no pass, and the parser attaches it to that history alone. It refuses
/// a listing that leaves one undeclared, a `fails` line in an earlier
/// version, one that names another ending than its profile expects, a
/// profile the listing lacks or a history twice, and a line outside its
/// form.
#[test]
fn a_version_4_listing_declares_the_failure_of_each_failing_history() {
    let fourth = edited(LISTING, "capabilities: 2", "capabilities: 4");
    assert_eq!(Listing::parse(&fourth), Err(Error::Missing("fails")));
    for witness in [
        "é held".to_owned(),
        "old\tread held".to_owned(),
        format!("{}é", "a".repeat(40)),
    ] {
        let text = format!("{fourth}fails: h1-get-unheld unsuccessful {witness}\n");
        assert_eq!(
            Listing::parse(&text),
            Err(Error::Value("fails")),
            "{witness:?}"
        );
    }
    let long = format!("{}é", "a".repeat(41));
    let text = format!("{fourth}fails: h1-get-unheld unsuccessful {long}\n");
    assert!(Listing::parse(&text).is_ok());
    let unheld = "fails: h1-get-unheld unsuccessful old read held\n";
    let declared = format!("{fourth}{unheld}");
    let listing = Listing::parse(&declared).expect("a version 4 listing parses");
    let fifth = edited(&declared, "capabilities: 4", "capabilities: 5");
    assert_eq!(Listing::parse(&fifth).unwrap().capabilities, 5);
    for profile in &listing.profiles {
        let fails = (profile.name == "h1-get-unheld")
            .then(|| Fails::Unsuccessful("old read held".to_owned()));
        assert_eq!(profile.fails, fails, "{}", profile.name);
    }
    assert_eq!(
        Listing::parse(&format!("{LISTING}{unheld}")),
        Err(Error::Unknown("fails".to_owned()))
    );
    let violating = edited(&fourth, "expected=unsuccessful", "expected=violation");
    let exposed = "fails: h1-get-unheld violation 8 a refused read exposed bytes\n";
    let listing = Listing::parse(&format!("{violating}{exposed}")).expect("a violation parses");
    assert_eq!(
        listing
            .profile("h1-get-unheld")
            .and_then(|p| p.fails.clone()),
        Some(Fails::Violation(
            8,
            "a refused read exposed bytes".to_owned()
        ))
    );
    let other = Error::Inconsistent("a fails line names another ending than its profile expects");
    let absent = Error::Inconsistent("a fails line names no listed profile");
    for (listing, line, error) in [
        (
            &declared,
            "fails: h6-get unsuccessful old read held\n",
            other.clone(),
        ),
        (
            &declared,
            "fails: upload unsuccessful old read held\n",
            other.clone(),
        ),
        (
            &declared,
            "fails: absent unsuccessful old read held\n",
            absent,
        ),
        (&fourth, exposed, other.clone()),
        (&violating, unheld, other),
        (
            &declared,
            unheld,
            Error::Repeated("fails h1-get-unheld".to_owned()),
        ),
        (
            &fourth,
            "fails: h1-get-unheld pass old read held\n",
            Error::Value("fails"),
        ),
        (
            &fourth,
            "fails: h1-get-unheld unsuccessful \n",
            Error::Value("fails"),
        ),
        (
            &fourth,
            "fails: h1-get-unheld unsuccessful\n",
            Error::Value("fails"),
        ),
        (&fourth, "fails: h1-get-unheld\n", Error::Value("fails")),
        (
            &violating,
            "fails: h1-get-unheld violation 0 a rule\n",
            Error::Value("fails"),
        ),
        (
            &violating,
            "fails: h1-get-unheld violation 256 a rule\n",
            Error::Value("fails"),
        ),
        (
            &violating,
            "fails: h1-get-unheld violation 08 a rule\n",
            Error::Value("fails"),
        ),
        (
            &violating,
            "fails: h1-get-unheld violation x a rule\n",
            Error::Value("fails"),
        ),
        (
            &violating,
            "fails: h1-get-unheld violation 8 \n",
            Error::Value("fails"),
        ),
        (
            &violating,
            "fails: h1-get-unheld violation 8\n",
            Error::Value("fails"),
        ),
    ] {
        assert_eq!(
            Listing::parse(&format!("{listing}{line}")),
            Err(error),
            "{line}"
        );
    }
}

/// Output cut short of its last newline, or empty, is torn.
#[test]
fn a_listing_cut_short_is_torn() {
    assert_eq!(
        Listing::parse(&LISTING[..LISTING.len() - 1]),
        Err(Error::Torn)
    );
    assert_eq!(Listing::parse(""), Err(Error::Torn));
}

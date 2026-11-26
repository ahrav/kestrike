use std::fs;
use std::os::unix::fs::PermissionsExt;

use kestrike::failover::arbiter::Partition;
use kestrike::failover::records::Host;
use kestrike::failover::standbys::Zone;
use kestrike::failover::zone_loop::config::{ConfigRefusal, Field, TICK_US};
use kestrike::failover::zone_loop::directory::{
    Color, DirectoryRefusal, DirectoryState, Placement,
};
use serde_json::json;

use super::{ConfigError, load};
use crate::directory::DirectoryError;
use crate::file::FileError;
use crate::fixture::Scratch;

/// One edit of a fixture file's JSON.
type Edit<'a> = Box<dyn Fn(&mut serde_json::Value) + 'a>;

fn refusal(scratch: &Scratch, edit: impl FnOnce(&mut serde_json::Value)) -> ConfigError {
    let path = scratch.config(edit);
    load(&path).err().expect("the configuration is refused")
}

/// The fixture names no timer, so each takes its owner default, and no cap, so the census cap is the directory's
/// two shards.
#[test]
fn a_configuration_without_limits_takes_the_owner_defaults_and_the_directory_shard_count() {
    let scratch = Scratch::new("defaults");
    let service = load(&scratch.config(|_| {})).unwrap();
    let config = service.bounds.config();
    assert_eq!(config.tick_us, TICK_US);
    assert_eq!(config.population_cap, 2);
    assert_eq!(config.name, "us-east-1a");
    assert_eq!(service.writer.get(), 900);
    assert_eq!(service.state, scratch.path().join("state"));
}

#[test]
fn a_limit_present_in_the_file_replaces_its_default() {
    let scratch = Scratch::new("limits");
    let path = scratch.config(|config| {
        config["population_cap"] = json!(1);
        config["host_hold"] = json!({ "numerator": 1, "denominator": 3 });
        config["loss_ticks"] = json!(3);
    });
    let service = load(&path).unwrap();
    let config = service.bounds.config();
    assert_eq!(config.population_cap, 1);
    assert_eq!(
        (config.host_hold.numerator, config.host_hold.denominator),
        (1, 3)
    );
    assert_eq!(config.loss_ticks, 3);
}

#[test]
fn an_unknown_configuration_field_is_refused_by_name() {
    let scratch = Scratch::new("unknown-config");
    let error = refusal(&scratch, |config| config["tick_seconds"] = json!(10));
    let ConfigError::Syntax(message) = &error else {
        panic!("{error:?}");
    };
    assert!(
        message.contains("unknown field `tick_seconds`"),
        "{message}"
    );
    let owner = refusal(&scratch, |config| config["owner"]["slack"] = json!(1));
    assert!(
        owner.to_string().contains("unknown field `slack`"),
        "{owner}"
    );
}

#[test]
fn an_unknown_directory_field_is_refused_by_its_position() {
    let scratch = Scratch::new("unknown-directory");
    let path = scratch.config(|_| {});
    scratch.directory(|directory| directory["hosts"][0]["role"] = json!("owner"));
    let error = load(&path).err().unwrap();
    let ConfigError::Directory(DirectoryError::Syntax(message)) = &error else {
        panic!("{error:?}");
    };
    assert!(
        message.contains("unknown field at line 1 column"),
        "{message}"
    );
    assert!(!message.contains("role"), "{message}");
}

#[test]
fn a_directory_error_quotes_no_text_of_the_file() {
    let scratch = Scratch::new("key-text");
    let path = scratch.config(|_| {});
    let sentinel = "5a".repeat(32);
    let edits: [(&str, Edit<'_>); 6] = [
        (
            "host",
            Box::new(|d| d["hosts"][0]["host"] = json!(sentinel)),
        ),
        (
            "instance",
            Box::new(|d| d["hosts"][0]["instance"] = json!(sentinel)),
        ),
        (
            "state",
            Box::new(|d| d["hosts"][0]["state"] = json!(sentinel)),
        ),
        (
            "report key entry",
            Box::new(|d| d["report_keys"][0] = json!(sentinel)),
        ),
        (
            "field name",
            Box::new(|d| d["hosts"][0][sentinel.as_str()] = json!(1)),
        ),
        ("format", Box::new(|d| d["format"] = json!(sentinel))),
    ];
    for (place, edit) in edits {
        scratch.directory(|directory| edit(directory));
        let error = load(&path).err().unwrap();
        assert!(
            matches!(
                error,
                ConfigError::Directory(DirectoryError::Syntax(_) | DirectoryError::Value(_))
            ),
            "{place}: {error:?}"
        );
        assert!(
            !format!("{error} {error:?}").contains(&sentinel),
            "{place}: {error}"
        );
    }
}

#[test]
fn a_directory_reads_each_host_with_its_state_placement_and_report_key() {
    let scratch = Scratch::new("read-back");
    let key = |byte: u8| -> String { (0u8..32).map(|at| format!("{:02x}", at ^ byte)).collect() };
    let path = scratch.directory(|directory| {
        directory["hosts"][1]["state"] = json!("draining");
        directory["hosts"][1]["partition"] = json!(5);
        directory["hosts"][1]["color"] = json!(3);
        directory["hosts"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "host": 13, "instance": "i-0000000000000000d", "zone": 1, "partition": 3, "color": 2, "state": "retired" }));
        directory["report_keys"] = json!([
            { "host": 13, "key": key(0x30) },
            { "host": 11, "key": key(0x10) },
            { "host": 12, "key": key(0x20) },
        ]);
    });
    let directory = crate::directory::read(&path).unwrap();
    let expected = [
        (
            11,
            DirectoryState::Active,
            1,
            0,
            "i-0000000000000000b",
            0x10,
        ),
        (
            12,
            DirectoryState::Draining,
            5,
            3,
            "i-0000000000000000c",
            0x20,
        ),
        (
            13,
            DirectoryState::Retired,
            3,
            2,
            "i-0000000000000000d",
            0x30,
        ),
    ];
    for (host, state, partition, color, instance, byte) in expected {
        let id = Host::new(host).unwrap();
        let entry = directory.host(id).unwrap();
        assert_eq!(entry.state, state, "{host}");
        assert_eq!(
            entry.placement,
            Placement {
                zone: Zone(1),
                partition: Partition(partition),
                color: Color(color),
            },
            "{host}"
        );
        assert_eq!(entry.instance.as_str(), instance, "{host}");
        let bytes: [u8; 32] = std::array::from_fn(|at| at as u8 ^ byte);
        assert_eq!(directory.keys().report(id).unwrap().0, bytes, "{host}");
    }
}

#[test]
fn a_zero_number_or_a_malformed_instance_is_refused_by_its_field() {
    let scratch = Scratch::new("values-directory");
    let path = scratch.config(|_| {});
    let cases: [(&str, Edit<'_>); 4] = [
        ("host 0", Box::new(|d| d["hosts"][0]["host"] = json!(0))),
        ("shard 0", Box::new(|d| d["shards"][0]["shard"] = json!(0))),
        (
            "the instance of host 11",
            Box::new(|d| d["hosts"][0]["instance"] = json!("vol-0a")),
        ),
        (
            "host 0",
            Box::new(|d| d["report_keys"][0]["host"] = json!(0)),
        ),
    ];
    for (named, edit) in cases {
        scratch.directory(|directory| edit(directory));
        let error = load(&path).err().unwrap();
        assert!(
            matches!(&error, ConfigError::Directory(DirectoryError::Value(text)) if text == named),
            "{named}: {error:?}"
        );
    }
}

#[test]
fn a_null_optional_limit_is_refused() {
    let scratch = Scratch::new("null-limit");
    for field in ["population_cap", "host_hold", "tick_us"] {
        let error = refusal(&scratch, |config| config[field] = serde_json::Value::Null);
        assert!(
            matches!(&error, ConfigError::Syntax(message) if message.contains("invalid type: null")),
            "{field}: {error:?}"
        );
    }
}

/// Two values fail: a zero tick and a loss count of one. Validation reports the zero, the earlier check.
#[test]
fn the_first_failed_zone_check_is_the_one_named() {
    let scratch = Scratch::new("first-check");
    let error = refusal(&scratch, |config| {
        config["tick_us"] = json!(0);
        config["loss_ticks"] = json!(1);
    });
    assert!(
        matches!(error, ConfigError::Zone(ConfigRefusal::Zero(Field::TickUs))),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        "zone configuration refused: Zero(TickUs)"
    );
    let loss = refusal(&scratch, |config| config["loss_ticks"] = json!(1));
    assert!(
        matches!(loss, ConfigError::Zone(ConfigRefusal::LossTicks)),
        "{loss:?}"
    );
}

#[test]
fn service_values_outside_their_types_are_refused_by_field() {
    let scratch = Scratch::new("values");
    for (field, value) in [
        ("region", json!("US_EAST_1")),
        ("table", json!("t")),
        ("state", json!("relative/state")),
        ("writer", json!(0)),
    ] {
        let error = refusal(&scratch, |config| config[field] = value);
        assert!(
            matches!(error, ConfigError::Value(named) if named == field),
            "{field}: {error:?}"
        );
    }
    let name = refusal(&scratch, |config| config["name"] = json!("eu-west-1a"));
    assert!(matches!(name, ConfigError::Value("name")), "{name:?}");
}

/// A file of a later format reports its format, ahead of the fields the earlier shape does not know.
#[test]
fn a_file_of_another_format_is_refused_by_its_format() {
    let scratch = Scratch::new("format");
    let format = refusal(&scratch, |config| {
        config["format"] = json!(2);
        config["tick_seconds"] = json!(10);
    });
    assert!(matches!(format, ConfigError::Format(2)), "{format:?}");
    let path = scratch.config(|_| {});
    scratch.directory(|directory| {
        directory["format"] = json!(2);
        directory["hosts"][0]["role"] = json!("owner");
    });
    let error = load(&path).err().unwrap();
    assert!(
        matches!(error, ConfigError::Directory(DirectoryError::Format(2))),
        "{error:?}"
    );
}

#[test]
fn a_configuration_others_may_write_is_refused() {
    let scratch = Scratch::new("writable");
    let path = scratch.config(|_| {});
    fs::set_permissions(&path, fs::Permissions::from_mode(0o664)).unwrap();
    assert!(matches!(
        load(&path).err().unwrap(),
        ConfigError::File(FileError::Writable)
    ));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load(&path).is_ok());
}

#[test]
fn a_directory_readable_by_others_is_refused() {
    let scratch = Scratch::new("shared-directory");
    let path = scratch.config(|_| {});
    let directory = scratch.path().join("directory.json");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o644)).unwrap();
    let error = load(&path).err().unwrap();
    assert!(
        matches!(
            error,
            ConfigError::Directory(DirectoryError::File(FileError::Shared))
        ),
        "{error:?}"
    );
}

#[test]
fn a_directory_refusal_names_the_listing_check() {
    let scratch = Scratch::new("refused-directory");
    let path = scratch.config(|_| {});
    scratch.directory(|directory| directory["hosts"][1]["host"] = json!(11));
    let error = load(&path).err().unwrap();
    assert!(
        matches!(
            error,
            ConfigError::Directory(DirectoryError::Refused(DirectoryRefusal::DuplicateHost(host)))
                if host.get() == 11
        ),
        "{error:?}"
    );
    scratch.directory(|directory| directory["report_keys"][1]["key"] = json!("12"));
    let error = load(&path).err().unwrap();
    assert!(
        matches!(error, ConfigError::Directory(DirectoryError::Value(_))),
        "{error:?}"
    );
}

#[test]
fn a_directory_of_another_zone_is_refused() {
    let scratch = Scratch::new("zone");
    let path = scratch.config(|_| {});
    scratch.directory(|directory| directory["zone"] = json!(2));
    let error = load(&path).err().unwrap();
    assert!(
        matches!(error, ConfigError::DirectoryZone { config, directory } if config.0 == 1 && directory.0 == 2),
        "{error:?}"
    );
}

#[test]
fn a_status_key_other_than_64_hexadecimal_digits_is_refused() {
    let scratch = Scratch::new("status-key");
    let path = scratch.config(|_| {});
    scratch.write("status.key", "abcd\n");
    assert!(matches!(
        load(&path).err().unwrap(),
        ConfigError::StatusKeyDigits
    ));
    scratch.write("status.key", &"A".repeat(64));
    assert!(matches!(
        load(&path).err().unwrap(),
        ConfigError::StatusKeyDigits
    ));
    scratch.write("status.key", &format!("{}\n\n", "a".repeat(64)));
    assert!(matches!(
        load(&path).err().unwrap(),
        ConfigError::StatusKey(FileError::TooLarge(65))
    ));
    scratch.write("status.key", &"a".repeat(64));
    assert!(load(&path).is_ok());
    let key = scratch.path().join("status.key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(
        load(&path).err().unwrap(),
        ConfigError::StatusKey(FileError::Shared)
    ));
}

//! A [`Lenient`] field holds its value when the JSON has the shape its
//! type accepts, and stores `Other` when a [`Shape`] method returns
//! `None`. [`IgnoredAny`] discards the elements and entries of a refused
//! value. A `Vec` field and a `BTreeMap` field read the first
//! [`ELEMENTS`] elements or distinct keys of an array or object. One more
//! makes the value a refused shape, and `IgnoredAny` discards the rest.

use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

use serde::de::value::MapAccessDeserializer;
use serde::de::{Deserialize, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};

/// The element bound of a `Vec` field and the distinct-key bound of a
/// `BTreeMap` field.
pub const ELEMENTS: usize = 1 << 16;

#[derive(Debug, Default, PartialEq)]
pub enum Lenient<T> {
    #[default]
    Absent,
    Null,
    /// A JSON value of a shape `T` refuses.
    Other,
    Typed(T),
}

impl<T> Lenient<T> {
    pub fn get(&self) -> Option<&T> {
        match self {
            Self::Typed(value) => Some(value),
            _ => None,
        }
    }

    pub fn is_none(&self) -> bool {
        matches!(self, Self::Absent | Self::Null)
    }
}

impl<T> From<Option<T>> for Lenient<T> {
    fn from(value: Option<T>) -> Self {
        value.map_or(Self::Other, Self::Typed)
    }
}

/// Each method returns `None` for a shape the type refuses.
pub trait Shape: Sized {
    fn of_u64(_: u64) -> Option<Self> {
        None
    }

    fn of_i64(_: i64) -> Option<Self> {
        None
    }

    fn of_f64(_: f64) -> Option<Self> {
        None
    }

    fn of_bool(_: bool) -> Option<Self> {
        None
    }

    fn of_text(_: &str) -> Option<Self> {
        None
    }

    fn of_seq<'de, A: SeqAccess<'de>>(mut seq: A) -> Result<Option<Self>, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(None)
    }

    fn of_map<'de, A: MapAccess<'de>>(mut map: A) -> Result<Option<Self>, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(None)
    }
}

/// An error in one of the struct's fields fails the whole document.
pub fn object<'de, T: Deserialize<'de>, A: MapAccess<'de>>(map: A) -> Result<Option<T>, A::Error> {
    T::deserialize(MapAccessDeserializer::new(map)).map(Some)
}

impl Shape for u64 {
    fn of_u64(value: u64) -> Option<Self> {
        Some(value)
    }
}

impl Shape for f64 {
    fn of_u64(value: u64) -> Option<Self> {
        Some(value as f64)
    }

    fn of_i64(value: i64) -> Option<Self> {
        Some(value as f64)
    }

    fn of_f64(value: f64) -> Option<Self> {
        Some(value)
    }
}

impl Shape for bool {
    fn of_bool(value: bool) -> Option<Self> {
        Some(value)
    }
}

impl Shape for String {
    fn of_text(value: &str) -> Option<Self> {
        Some(value.to_owned())
    }
}

impl<V: Shape> Shape for BTreeMap<String, Lenient<V>> {
    fn of_map<'de, A: MapAccess<'de>>(map: A) -> Result<Option<Self>, A::Error> {
        entries(map)
    }
}

/// At [`ELEMENTS`] distinct keys, replacements still keep the last value for each key.
pub(crate) fn entries<'de, V: Deserialize<'de>, A: MapAccess<'de>>(
    mut map: A,
) -> Result<Option<BTreeMap<String, V>>, A::Error> {
    let mut entries = BTreeMap::new();
    while let Some(key) = map.next_key::<String>()? {
        if entries.len() == ELEMENTS && !entries.contains_key(&key) {
            map.next_value::<IgnoredAny>()?;
            while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
            return Ok(None);
        }
        entries.insert(key, map.next_value()?);
    }
    Ok(Some(entries))
}

impl<V: Shape> Shape for Vec<Lenient<V>> {
    fn of_seq<'de, A: SeqAccess<'de>>(mut seq: A) -> Result<Option<Self>, A::Error> {
        let mut elements = Self::new();
        while elements.len() < ELEMENTS {
            match seq.next_element()? {
                Some(element) => elements.push(element),
                None => return Ok(Some(elements)),
            }
        }
        let mut longer = false;
        while seq.next_element::<IgnoredAny>()?.is_some() {
            longer = true;
        }
        Ok((!longer).then_some(elements))
    }
}

impl<'de, T: Shape> Deserialize<'de> for Lenient<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(Read(PhantomData))
    }
}

struct Read<T>(PhantomData<T>);

impl<'de, T: Shape> Visitor<'de> for Read<T> {
    type Value = Lenient<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(T::of_u64(value).into())
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(T::of_i64(value).into())
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E> {
        Ok(T::of_f64(value).into())
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(T::of_bool(value).into())
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(T::of_text(value).into())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Lenient::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Lenient::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        Lenient::deserialize(deserializer)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
        T::of_seq(seq).map(Into::into)
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
        T::of_map(map).map(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize, Default)]
    #[serde(default)]
    struct Pair {
        count: Lenient<u64>,
        names: Lenient<Vec<Lenient<String>>>,
    }

    impl Shape for Pair {
        fn of_map<'de, A: MapAccess<'de>>(map: A) -> Result<Option<Self>, A::Error> {
            object(map)
        }
    }

    fn read(text: &str) -> Lenient<Pair> {
        serde_json::from_str(text).expect("valid JSON")
    }

    #[test]
    fn each_field_reads_its_shape_and_records_any_other() {
        let Lenient::Typed(pair) = read(r#"{"count": 3, "names": ["a", 1, null], "extra": [1]}"#)
        else {
            panic!("an object reads as a pair");
        };
        assert_eq!(pair.count, Lenient::Typed(3));
        assert_eq!(
            pair.names,
            Lenient::Typed(vec![
                Lenient::Typed("a".to_owned()),
                Lenient::Other,
                Lenient::Null
            ])
        );
        for (text, count) in [
            (r#"{"count": -1}"#, Lenient::Other),
            (r#"{"count": 1.5}"#, Lenient::Other),
            (r#"{"count": "3"}"#, Lenient::Other),
            (r#"{"count": [3]}"#, Lenient::Other),
            (r#"{"count": null}"#, Lenient::Null),
            ("{}", Lenient::Absent),
        ] {
            let Lenient::Typed(pair) = read(text) else {
                panic!("{text} reads as a pair");
            };
            assert_eq!(pair.count, count, "{text}");
        }
        assert!(matches!(read("[1, 2]"), Lenient::Other));
        assert!(matches!(read("7"), Lenient::Other));
        assert!(serde_json::from_str::<Lenient<Pair>>(r#"{"count": 1, "count": 2}"#).is_err());
    }

    #[test]
    fn an_array_or_object_past_the_element_bound_reads_as_other() {
        let array = |length: usize| format!("[{}]", vec!["0"; length].join(","));
        let object = |length: usize| {
            let entries: Vec<String> = (0..length).map(|key| format!(r#""{key}":0"#)).collect();
            format!("{{{}}}", entries.join(","))
        };
        type Numbers = Lenient<Vec<Lenient<u64>>>;
        type Counts = Lenient<BTreeMap<String, Lenient<u64>>>;
        let full: Numbers = serde_json::from_str(&array(ELEMENTS)).expect("valid JSON");
        assert_eq!(full.get().map(Vec::len), Some(ELEMENTS));
        let long: Numbers = serde_json::from_str(&array(ELEMENTS + 1)).expect("valid JSON");
        assert!(matches!(long, Lenient::Other), "an array past the bound");
        let full: Counts = serde_json::from_str(&object(ELEMENTS)).expect("valid JSON");
        assert_eq!(full.get().map(BTreeMap::len), Some(ELEMENTS));
        let long: Counts = serde_json::from_str(&object(ELEMENTS + 1)).expect("valid JSON");
        assert!(matches!(long, Lenient::Other), "an object past the bound");
        // Repeated keys replace existing values, so the bound counts
        // distinct keys.
        let repeated = format!(r#"{},"0":1}}"#, object(ELEMENTS).trim_end_matches('}'));
        let repeated: Counts = serde_json::from_str(&repeated).expect("valid JSON");
        assert_eq!(
            repeated.get().and_then(|counts| counts.get("0")),
            Some(&Lenient::Typed(1))
        );
        // The parser consumes a refused array to its end: the field after
        // it reads, and a syntax error past the bound fails the document.
        let names = array(ELEMENTS + 1).replace('0', r#""a""#);
        let Lenient::Typed(pair) = read(&format!(r#"{{"names": {names}, "count": 3}}"#)) else {
            panic!("an object reads as a pair");
        };
        assert!(matches!(pair.names, Lenient::Other), "a refused array");
        assert_eq!(pair.count, Lenient::Typed(3));
        let cut = array(ELEMENTS + 2);
        assert!(serde_json::from_str::<Numbers>(cut.trim_end_matches(']')).is_err());
    }
}

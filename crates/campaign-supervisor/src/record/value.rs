//! The generic form of a decoded record file. [`Value`] keeps every object
//! entry in file order, duplicates included, so the codec sees each key the
//! file holds. It admits only the record domain: null, booleans, integers
//! from 0 to `u64::MAX`, strings, arrays and objects. A float, a negative
//! integer or a larger integer fails the parse.
//!
//! A `Value` is also a serde deserializer whose [`Fault`] tells an unknown
//! field apart from every other typed-decode failure.

use std::fmt;

use serde::de::value::{MapDeserializer, SeqDeserializer};
use serde::de::{self, Deserialize, Deserializer, IntoDeserializer, MapAccess, SeqAccess, Visitor};

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Value {
    Null,
    Bool(bool),
    Integer(u64),
    Text(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(Generic)
    }
}

struct Generic;

impl<'de> Visitor<'de> for Generic {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON with no floats or negative integers")
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Integer(value))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E> {
        Ok(Value::Text(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::Text(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut entries = Vec::new();
        while let Some(entry) = map.next_entry()? {
            entries.push(entry);
        }
        Ok(Value::Object(entries))
    }
}

/// Why a typed decode of a [`Value`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Fault {
    /// An object holds a field its type does not declare.
    UnknownField,
    /// The decoded record fails its field types, static rules or derivations.
    Mismatch,
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnknownField => "an unknown field",
            Self::Mismatch => "failed field types, static rules or derivations",
        })
    }
}

impl std::error::Error for Fault {}

impl de::Error for Fault {
    fn custom<T: fmt::Display>(_: T) -> Self {
        Self::Mismatch
    }

    fn unknown_field(_: &str, _: &'static [&'static str]) -> Self {
        Self::UnknownField
    }
}

impl<'de> Deserializer<'de> for Value {
    type Error = Fault;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Fault> {
        match self {
            Self::Null => visitor.visit_unit(),
            Self::Bool(value) => visitor.visit_bool(value),
            Self::Integer(value) => visitor.visit_u64(value),
            Self::Text(value) => visitor.visit_string(value),
            Self::Array(items) => {
                let mut seq = SeqDeserializer::new(items.into_iter());
                let value = visitor.visit_seq(&mut seq)?;
                seq.end()?;
                Ok(value)
            }
            Self::Object(entries) => {
                let mut map = MapDeserializer::new(entries.into_iter());
                let value = visitor.visit_map(&mut map)?;
                map.end()?;
                Ok(value)
            }
        }
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Fault> {
        match self {
            Self::Null => visitor.visit_none(),
            value => visitor.visit_some(value),
        }
    }

    /// A struct decodes only from an object, so an array in a struct's
    /// place is [`Fault::Mismatch`].
    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        _: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Fault> {
        match self {
            Self::Object(_) => self.deserialize_any(visitor),
            _ => Err(Fault::Mismatch),
        }
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf unit
        unit_struct newtype_struct seq tuple tuple_struct map enum identifier ignored_any
    }
}

impl IntoDeserializer<'_, Fault> for Value {
    type Deserializer = Self;

    fn into_deserializer(self) -> Self {
        self
    }
}

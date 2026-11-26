//! Record text. [`Text`] holds printable ASCII, bytes 0x20 to 0x7e,
//! because compact JSON encodes that range the same way in every encoder
//! the identities must agree with. Construction and decoding refuse every
//! other byte, so no other text reaches an identity derivation.

use serde::de::{self, Deserialize, Deserializer, Unexpected};
use serde::{Serialize, Serializer};

pub(super) fn printable(text: &str) -> bool {
    text.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

/// Printable ASCII text. `Text` orders bytewise, so a `BTreeMap` keyed by
/// `Text` encodes its keys in byte order.
///
/// ```
/// use campaign_supervisor::record::Text;
/// assert_eq!(Text::new("a b").map(|text| text.as_str().to_owned()), Some("a b".to_owned()));
/// ```
///
/// ```compile_fail,E0423
/// let text = campaign_supervisor::record::Text("\u{e9}".to_owned());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Text(String);

impl Text {
    /// `text` as record text; `None` when it holds a byte outside 0x20 to
    /// 0x7e.
    pub fn new(text: &str) -> Option<Self> {
        printable(text).then(|| Self(text.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for Text {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Text {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if printable(&text) {
            Ok(Self(text))
        } else {
            Err(de::Error::invalid_value(
                Unexpected::Str(&text),
                &"printable ASCII",
            ))
        }
    }
}

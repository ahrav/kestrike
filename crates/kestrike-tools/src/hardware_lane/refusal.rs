use std::fmt;

use crate::text::Text;

pub(super) const MALFORMED: &str = "malformed hardware manifest: ";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    sentence: Text,
}

impl Refusal {
    pub(super) fn new(sentence: Text) -> Self {
        Self { sentence }
    }

    pub(super) fn malformed(message: &Text) -> Self {
        let mut sentence = Text::from(MALFORMED);
        sentence.push_text(message);
        Self::new(sentence)
    }

    pub fn sentence(&self) -> &Text {
        &self.sentence
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.sentence.fmt(f)
    }
}

impl std::error::Error for Refusal {}

pub(super) fn need(condition: bool, message: impl FnOnce() -> Text) -> Result<(), Refusal> {
    if condition {
        Ok(())
    } else {
        Err(Refusal::malformed(&message()))
    }
}

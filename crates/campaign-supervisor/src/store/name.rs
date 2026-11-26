use std::ffi::{CStr, CString};

/// The longest name. A staging name adds 17 bytes and stays within the
/// kernel's 255-byte component limit.
const MAX: usize = 200;

/// One path component under the state directory: 1 to 200 bytes of ASCII
/// letters, digits, `-`, `_`, `+` and `.`, never starting with `.`, so a
/// shared library's file name such as `libstdc++.so.6` is a name. A name is
/// therefore never `.` or `..`, never holds `/` or NUL, and never collides
/// with the store's own dot-named entries.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(CString);

impl Name {
    /// `text` as a name, or `None` when it breaks the name rules.
    pub fn new(text: &str) -> Option<Self> {
        Self::from_bytes(text.as_bytes())
    }

    pub(super) fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let admitted =
            |&byte: &u8| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'+' | b'.');
        let valid =
            (1..=MAX).contains(&bytes.len()) && bytes[0] != b'.' && bytes.iter().all(admitted);
        valid.then(|| Self(CString::new(bytes).expect("admitted bytes hold no NUL")))
    }

    /// The name's text.
    pub fn as_str(&self) -> &str {
        self.0.to_str().expect("admitted bytes are ASCII")
    }

    pub(super) fn as_c_str(&self) -> &CStr {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Name;

    /// Traversal, separators, NUL, dot-leading names, empty and overlong
    /// names are refused, so no name addresses anything but one entry of
    /// its directory.
    #[test]
    fn a_name_is_one_confined_component() {
        for refused in [
            "",
            ".",
            "..",
            ".tmp",
            "a/b",
            "/",
            "a\0b",
            "a b",
            "é",
            &"a".repeat(201),
        ] {
            assert_eq!(Name::new(refused), None, "{refused:?}");
        }
        for admitted in [
            "state",
            "0001",
            "job-1_a.json",
            "libstdc++.so.6",
            &"a".repeat(200),
        ] {
            assert_eq!(
                Name::new(admitted)
                    .map(|name| name.as_str().to_owned())
                    .as_deref(),
                Some(admitted)
            );
        }
    }
}

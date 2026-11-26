//! Test fixtures: a scratch directory per test holding the committed fixture configuration, directory file and
//! status key, with every `@DIR@` in them replaced by the scratch directory's path.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

pub(crate) const CONFIG: &str = include_str!("../tests/fixtures/config.json");
pub(crate) const DIRECTORY: &str = include_str!("../tests/fixtures/directory.json");
pub(crate) const STATUS_KEY: &str = include_str!("../tests/fixtures/status.key");

/// A directory under the system temporary directory, mode 0700, removed when the value drops.
pub(crate) struct Scratch(PathBuf);

impl Scratch {
    pub(crate) fn new(name: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let count = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "kestrike-reconciler-{name}-{}-{count}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    /// Writes `text` with `@DIR@` replaced at `name` under the scratch directory, mode 0600: into a staged file,
    /// renamed over `name`, so a reader sees the old or the new file whole.
    pub(crate) fn write(&self, name: &str, text: &str) -> PathBuf {
        let path = self.0.join(name);
        let staged = self.0.join(format!(".{name}.staged"));
        let text = text.replace("@DIR@", &self.0.to_string_lossy());
        let _ = fs::remove_file(&staged);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&staged)
            .unwrap();
        file.write_all(text.as_bytes()).unwrap();
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap();
        fs::rename(&staged, &path).unwrap();
        path
    }

    /// The fixture configuration after `edit` changes its JSON, with the fixture directory and status key beside
    /// it; returns the configuration's path.
    pub(crate) fn config(&self, edit: impl FnOnce(&mut serde_json::Value)) -> PathBuf {
        self.directory(|_| {});
        self.write("status.key", STATUS_KEY);
        let mut config: serde_json::Value = serde_json::from_str(CONFIG).unwrap();
        edit(&mut config);
        self.write("config.json", &config.to_string())
    }

    /// Writes the fixture directory after `edit` changes its JSON.
    pub(crate) fn directory(&self, edit: impl FnOnce(&mut serde_json::Value)) -> PathBuf {
        let mut directory: serde_json::Value = serde_json::from_str(DIRECTORY).unwrap();
        edit(&mut directory);
        self.write("directory.json", &directory.to_string())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

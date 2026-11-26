//! The inventory `kestrike-bind` writes and the owner reads: one
//! `key=value` line per field, written to a temporary file, synced and
//! renamed into place, so a reader sees either the old file or the new one.
//!
//! The file's `format` field names its format, and a reader refuses a file
//! with no `format` line naming [`FORMAT`] before it reads any other key.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::num::NonZeroU32;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use super::eni::{Eni, NetState, format_mac, parse_cidr, parse_mac};
use super::record_step::{RecordStep, StepWriter, step};
use super::wc::{WcManifest, WcModule};
use crate::net::MAX_PEERS;

/// One NVMe controller bound to `vfio-pci`, as identified while it was on its kernel driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvmeBinding {
    /// The volume ID in its `vol-` form.
    pub volume: String,
    /// The PCI address, `dddd:bb:dd.f`.
    pub bdf: String,
    pub nsid: u32,
    pub sector_size: u32,
    /// Namespace capacity in bytes.
    pub capacity: u64,
    /// The kernel driver the controller was bound to.
    pub original_driver: String,
    /// The `driver_override` the controller held, if any.
    pub original_override: Option<String>,
}

/// The dataplane ENI bound to `vfio-pci`, as identified while it was on
/// `ena`, with the kernel network state release restores and the next-hop
/// MAC toward each peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EniBinding {
    pub eni: Eni,
    pub original_driver: String,
    pub original_override: Option<String>,
    pub net: NetState,
    /// Each peer's address and the MAC of its next hop.
    pub next_hops: Vec<(Ipv4Addr, [u8; 6])>,
}

/// The host's bound devices, the write-combining kernel and modules checked
/// before they bound, and the instance and boot they were bound in. An owner
/// binds the NVMe controller and the ENI; a client binds the ENI alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mappings {
    pub instance: String,
    pub boot: String,
    pub wc: WcManifest,
    pub nvme: Option<NvmeBinding>,
    pub eni: Option<EniBinding>,
}

/// Why a mappings file was refused.
#[derive(Debug)]
pub enum MappingsError {
    Io(io::Error),
    /// A field is missing, repeated, unknown or malformed, or no device is recorded.
    Format(&'static str),
    /// The file's format version is not this reader's.
    Version,
    /// The file was written on another instance.
    Instance,
    /// The file was written during another boot.
    Boot,
}

/// The format version of the file this reader and writer understand.
const FORMAT: &str = "3";

/// One `eni.next_hops` entry at its longest, `255.255.255.255@ff:ff:ff:ff:ff:ff`, with its `;` separator.
const NEXT_HOP_BYTES: u64 = 34;

/// The file's byte bound: the next hops of [`MAX_PEERS`] peers at their longest, plus 1 MiB for the other fields.
pub(crate) const MAPPINGS_BYTES: u64 = MAX_PEERS as u64 * NEXT_HOP_BYTES + (1 << 20);

const HEAD: [&str; 7] = [
    "format",
    "instance",
    "boot",
    "wc.kernel",
    "wc.config_sha256",
    "wc.patch",
    "wc.modules",
];
const NVME: [&str; 7] = [
    "nvme.volume",
    "nvme.bdf",
    "nvme.nsid",
    "nvme.sector_size",
    "nvme.capacity",
    "nvme.original_driver",
    "nvme.original_override",
];
const ENI: [&str; 16] = [
    "eni.id",
    "eni.mac",
    "eni.ipv4",
    "eni.subnet",
    "eni.cidr",
    "eni.device_number",
    "eni.network_card",
    "eni.netdev",
    "eni.bdf",
    "eni.original_driver",
    "eni.original_override",
    "eni.mtu",
    "eni.up",
    "eni.addresses",
    "eni.routes",
    "eni.next_hops",
];

/// Whether `bdf` is a canonical PCI address, `dddd:bb:dd.f` in lowercase
/// hexadecimal with the device below 32 and the function below 8, the one
/// spelling SPDK and sysfs agree on.
fn canonical_bdf(bdf: &str) -> bool {
    let bytes = bdf.as_bytes();
    let hex = |range: std::ops::Range<usize>| {
        bytes[range]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    };
    bytes.len() == 12
        && bytes[4] == b':'
        && bytes[7] == b':'
        && bytes[10] == b'.'
        && hex(0..4)
        && hex(5..7)
        && (b'0'..=b'1').contains(&bytes[8])
        && hex(8..10)
        && (b'0'..=b'7').contains(&bytes[11])
}

/// A kernel driver name: nonempty, of alphanumerics, `_` and `-`.
fn driver_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn split(text: &str) -> Vec<String> {
    if text.is_empty() {
        Vec::new()
    } else {
        text.split(';').map(str::to_owned).collect()
    }
}

/// One field a reader looks up: its key and the value the file gives it.
/// Every accessor of a `Field` refuses a missing value with `Format`
/// naming the key.
type Field<'t> = (&'static str, Option<&'t str>);

/// Pairs each of a section's keys with the value the file gives it.
fn fields<'t, const N: usize>(
    keys: [&'static str; N],
    values: [Option<&'t str>; N],
) -> [Field<'t>; N] {
    std::array::from_fn(|index| (keys[index], values[index]))
}

/// The field's value.
fn given((key, value): Field<'_>) -> Result<&str, MappingsError> {
    value.ok_or(MappingsError::Format(key))
}

/// The field's value as an owned string.
fn owned(field: Field<'_>) -> Result<String, MappingsError> {
    given(field).map(str::to_owned)
}

/// The field's value parsed as `T`; `Format` naming the field when it
/// does not parse.
fn parse<T: std::str::FromStr>(field: Field<'_>) -> Result<T, MappingsError> {
    given(field)?
        .parse()
        .map_err(|_| MappingsError::Format(field.0))
}

/// The field's value when `valid` accepts it; `Format` naming the field
/// when `valid` refuses it.
fn checked(field: Field<'_>, valid: fn(&str) -> bool) -> Result<String, MappingsError> {
    Some(given(field)?)
        .filter(|value| valid(value))
        .map(str::to_owned)
        .ok_or(MappingsError::Format(field.0))
}

/// The field's value, `None` when it is empty.
fn optional(field: Field<'_>) -> Result<Option<String>, MappingsError> {
    given(field).map(|value| {
        Some(value)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
}

impl Mappings {
    /// The first recorded device's address: the controller's, else the ENI's.
    pub(crate) fn first_bdf(&self) -> &str {
        match (&self.nvme, &self.eni) {
            (Some(nvme), _) => &nvme.bdf,
            (None, Some(eni)) => &eni.eni.bdf,
            (None, None) => "",
        }
    }

    /// The fields in file order, every recorded section present.
    fn fields(&self) -> io::Result<Vec<(&'static str, String)>> {
        let w = &self.wc;
        let list = |items: &[String]| {
            if items
                .iter()
                .any(|item| item.is_empty() || item.contains(';'))
            {
                Err(io::Error::from(io::ErrorKind::InvalidInput))
            } else {
                Ok(items.join(";"))
            }
        };
        let modules: Vec<String> = w.modules.iter().map(WcModule::format).collect();
        let mut fields: Vec<(&str, String)> = HEAD
            .into_iter()
            .zip([
                FORMAT.to_owned(),
                self.instance.clone(),
                self.boot.clone(),
                w.kernel.clone(),
                w.config_sha256.clone(),
                w.patch.clone(),
                list(&modules)?,
            ])
            .collect();
        if let Some(n) = &self.nvme {
            fields.extend(NVME.into_iter().zip([
                n.volume.clone(),
                n.bdf.clone(),
                n.nsid.to_string(),
                n.sector_size.to_string(),
                n.capacity.to_string(),
                n.original_driver.clone(),
                n.original_override.clone().unwrap_or_default(),
            ]));
        }
        if let Some(binding) = &self.eni {
            let e = &binding.eni;
            let hops: Vec<String> = binding
                .next_hops
                .iter()
                .map(|(ip, mac)| format!("{ip}@{}", format_mac(mac)))
                .collect();
            fields.extend(ENI.into_iter().zip([
                e.id.clone(),
                format_mac(&e.mac),
                e.ipv4.to_string(),
                e.subnet.clone(),
                format!("{}/{}", e.cidr.0, e.cidr.1),
                e.device_number.to_string(),
                e.network_card.to_string(),
                e.netdev.clone(),
                e.bdf.clone(),
                binding.original_driver.clone(),
                binding.original_override.clone().unwrap_or_default(),
                binding.net.mtu.to_string(),
                u8::from(binding.net.up).to_string(),
                list(&binding.net.addresses)?,
                list(&binding.net.routes)?,
                list(&hops)?,
            ]));
        }
        Ok(fields)
    }

    /// Writes the file atomically, readable by its owner only.
    ///
    /// # Errors
    ///
    /// The I/O error of the first failed step, or `InvalidInput` for a file
    /// recording no device, a value that would forge a field, or a record
    /// [`Mappings::read`] would refuse or read as another. A failure
    /// before the rename leaves `path` unchanged, and one after the
    /// temporary file's creation leaves that file, which the next write
    /// replaces; a failed directory open or sync after the rename leaves the
    /// new file in place and visible, its durability unconfirmed. A failed
    /// unlink of a stale temporary file is ignored, and the exclusive
    /// creation then refuses a file that unlink left.
    pub fn write(&self, path: &Path) -> io::Result<()> {
        if self.nvme.is_none() && self.eni.is_none() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut text = String::new();
        for (key, value) in self.fields()? {
            if value.contains(['\n', '=']) {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            text.extend([key, "=", &value, "\n"]);
        }
        if text.len() as u64 > MAPPINGS_BYTES {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // The record must read back as itself, so no device moves under a
        // record its reader refuses or reads as another.
        if !matches!(Self::parse(&text), Ok(read) if read == *self) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Self::write_bytes(path, text.as_bytes())
    }

    /// `read_bytes` reads the regular file at `path` in full when `accept` admits the opened file's metadata.
    /// Opening a final symbolic link returns `ELOOP`; opening a FIFO uses nonblocking mode.
    ///
    /// # Errors
    ///
    /// `read_bytes` propagates open, metadata and read errors, including `NotFound` for an absent file. It returns
    /// `InvalidData` for directories, special files, metadata `accept` refuses, or files longer than `bound` bytes,
    /// checked against the opened file's length before the read and against the bytes read after it.
    pub(crate) fn read_bytes(
        path: &Path,
        bound: u64,
        accept: impl FnOnce(&fs::Metadata) -> bool,
    ) -> io::Result<Vec<u8>> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file() || !accept(&meta) || meta.len() > bound {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
        file.take(bound.saturating_add(1)).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > bound {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(bytes)
    }

    pub(crate) fn write_bytes(path: &Path, bytes: &[u8]) -> io::Result<()> {
        Self::write_kept(path, bytes).map(drop)
    }

    /// Replaces the file at `path` with `bytes` as [`write_bytes`](Self::write_bytes) does and returns the written
    /// file, open for writing. The handle names the file this call wrote even after another writer renames a file
    /// over `path`, which a later open of `path` would follow.
    pub(crate) fn write_kept(path: &Path, bytes: &[u8]) -> io::Result<File> {
        let mut temporary = path.as_os_str().to_owned();
        temporary.push(".tmp");
        let temporary = PathBuf::from(temporary);
        // A fresh, unlinked-first temporary file gets this mode and follows no planted link.
        let _ = step(RecordStep::TemporaryUnlink, || fs::remove_file(&temporary));
        let file = step(RecordStep::Create, || {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temporary)
        })?;
        StepWriter(&file).write_all(bytes)?;
        step(RecordStep::FileSync, || file.sync_all())?;
        step(RecordStep::Rename, || fs::rename(&temporary, path))?;
        Self::sync_directory_of(path)?;
        Ok(file)
    }

    /// Removes the file at `path` durably.
    ///
    /// # Errors
    ///
    /// The unlink error, which leaves the file in place, or the directory's
    /// open or sync error, which follows the file's removal.
    pub(crate) fn discard(path: &Path) -> io::Result<()> {
        step(RecordStep::Unlink, || fs::remove_file(path))?;
        Self::sync_directory_of(path)
    }

    /// Syncs the directory holding `path`, so a rename into it or an unlink
    /// from it is durable.
    ///
    /// # Errors
    ///
    /// The open or sync error.
    pub(crate) fn sync_directory_of(path: &Path) -> io::Result<()> {
        // `Path::parent` of a bare file name is the empty path; the current
        // directory holds the file then.
        let directory = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let directory = step(RecordStep::DirectoryOpen, || File::open(directory))?;
        step(RecordStep::DirectorySync, || directory.sync_all())
    }

    /// Reads the file at `path`, its lines in any order. A device section
    /// is present when any of its fields is, and then every one of its
    /// fields must be. `read` rejects files larger than [`MAPPINGS_BYTES`]
    /// before parsing.
    ///
    /// # Errors
    ///
    /// `Io` for an unreadable file or one larger than [`MAPPINGS_BYTES`];
    /// `Version` for a file without this
    /// format's `format` line, whatever its other lines; `Format` naming a
    /// missing, repeated or malformed field, `line` or `key` for a line
    /// without `=` or with an unknown key, or `device` when no device is
    /// recorded.
    pub fn read(path: &Path) -> Result<Self, MappingsError> {
        let mut text = String::with_capacity(4096);
        File::open(path)
            .and_then(|file| {
                file.take(MAPPINGS_BYTES.saturating_add(1))
                    .read_to_string(&mut text)
            })
            .map_err(MappingsError::Io)?;
        if text.len() as u64 > MAPPINGS_BYTES {
            return Err(MappingsError::Io(io::ErrorKind::InvalidData.into()));
        }
        Self::parse(&text)
    }

    pub(crate) fn read_regular(path: &Path) -> Result<Self, MappingsError> {
        let bytes = Self::read_bytes(path, MAPPINGS_BYTES, |_| true).map_err(MappingsError::Io)?;
        let text = String::from_utf8(bytes)
            .map_err(|_| MappingsError::Io(io::ErrorKind::InvalidData.into()))?;
        Self::parse(&text)
    }

    fn parse(text: &str) -> Result<Self, MappingsError> {
        // A file of another format can name keys outside this format, so its
        // version is checked before its keys.
        if !text
            .lines()
            .any(|line| line.strip_prefix("format=") == Some(FORMAT))
        {
            return Err(MappingsError::Version);
        }
        let mut head = [None; HEAD.len()];
        let mut nvme = [None; NVME.len()];
        let mut eni = [None; ENI.len()];
        for line in text.lines() {
            let (key, value) = line.split_once('=').ok_or(MappingsError::Format("line"))?;
            // Every `NVME` key starts with `nvme.` and every `ENI` key with
            // `eni.`, and no `HEAD` key does, so a key's prefix names the one
            // section that can hold it.
            let (keys, values): (&[&'static str], &mut [Option<&str>]) = if key.starts_with("nvme.")
            {
                (&NVME, &mut nvme)
            } else if key.starts_with("eni.") {
                (&ENI, &mut eni)
            } else {
                (&HEAD, &mut head)
            };
            let index = keys
                .iter()
                .position(|field| *field == key)
                .ok_or(MappingsError::Format("key"))?;
            if values[index].replace(value).is_some() {
                return Err(MappingsError::Format(keys[index]));
            }
        }
        let present = |values: &[Option<&str>]| values.iter().any(Option::is_some);
        let nvme = if present(&nvme) {
            let [
                volume,
                bdf,
                nsid,
                sector_size,
                capacity,
                original_driver,
                original_override,
            ] = fields(NVME, nvme);
            Some(NvmeBinding {
                volume: owned(volume)?,
                bdf: checked(bdf, canonical_bdf)?,
                nsid: parse(nsid)?,
                sector_size: parse(sector_size)?,
                capacity: parse(capacity)?,
                original_driver: checked(original_driver, driver_name)?,
                original_override: optional(original_override)?,
            })
        } else {
            None
        };
        let eni = if present(&eni) {
            let [
                id,
                mac,
                ipv4,
                subnet,
                cidr,
                device_number,
                network_card,
                netdev,
                bdf,
                original_driver,
                original_override,
                mtu,
                up,
                addresses,
                routes,
                next_hops,
            ] = fields(ENI, eni);
            let cidr = parse_cidr(given(cidr)?).ok_or(MappingsError::Format(cidr.0))?;
            let next_hops = split(given(next_hops)?)
                .iter()
                .map(|hop| {
                    let (ip, mac) = hop.split_once('@')?;
                    Some((ip.parse().ok()?, parse_mac(mac)?))
                })
                .collect::<Option<Vec<_>>>()
                .ok_or(MappingsError::Format(next_hops.0))?;
            let mtu = parse::<NonZeroU32>(mtu)?;
            let up = match given(up)? {
                "1" => true,
                "0" => false,
                _ => return Err(MappingsError::Format(up.0)),
            };
            Some(EniBinding {
                eni: Eni {
                    id: owned(id)?,
                    mac: parse_mac(given(mac)?).ok_or(MappingsError::Format(mac.0))?,
                    ipv4: parse(ipv4)?,
                    subnet: owned(subnet)?,
                    cidr,
                    device_number: parse(device_number)?,
                    network_card: parse(network_card)?,
                    netdev: owned(netdev)?,
                    bdf: checked(bdf, canonical_bdf)?,
                },
                original_driver: checked(original_driver, driver_name)?,
                original_override: optional(original_override)?,
                net: NetState {
                    mtu,
                    up,
                    addresses: split(given(addresses)?),
                    routes: split(given(routes)?),
                },
                next_hops,
            })
        } else {
            None
        };
        if nvme.is_none() && eni.is_none() {
            return Err(MappingsError::Format("device"));
        }
        let [_, instance, boot, kernel, config_sha256, patch, modules] = fields(HEAD, head);
        let modules = split(given(modules)?)
            .iter()
            .map(|module| WcModule::parse(module))
            .collect::<Option<Vec<_>>>()
            .ok_or(MappingsError::Format(modules.0))?;
        Ok(Self {
            instance: owned(instance)?,
            boot: owned(boot)?,
            wc: WcManifest {
                kernel: owned(kernel)?,
                config_sha256: owned(config_sha256)?,
                patch: owned(patch)?,
                modules,
            },
            nvme,
            eni,
        })
    }

    /// Refuses a file written on another instance or during another boot.
    ///
    /// # Errors
    ///
    /// `Instance`, then `Boot`.
    pub fn check_current(&self, instance: &str, boot: &str) -> Result<(), MappingsError> {
        match (self.instance == instance, self.boot == boot) {
            (false, _) => Err(MappingsError::Instance),
            (true, false) => Err(MappingsError::Boot),
            (true, true) => Ok(()),
        }
    }
}

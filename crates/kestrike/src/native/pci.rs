//! One PCI function's configuration space through its sysfs directory: the
//! bus-master enable, whose clear the function confirms on read-back, and
//! function-level reset.
//!
//! A function whose bus-master enable reads back clear issues no further
//! memory request, so neither DMA nor an interrupt message reaches memory
//! after it, and the memory writes it issued before land ahead of the
//! read-back's completion: a configuration completion carries neither
//! relaxed nor ID-based ordering, so PCIe orders it behind them. That
//! read-back is the device-stop proof a driver hands its registration.
//! The proof assumes the configuration space the guest reads is the
//! function's own command register, as for a passed-through function whose
//! hardware enforces bus-master enable, and requires host evidence that a
//! cleared enable stops receive DMA into posted buffers.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::FileExt;
use std::path::Path;

const COMMAND: u64 = 0x04;
pub(crate) const BUS_MASTER: u16 = 1 << 2;
const STATUS: u64 = 0x06;
const CAPABILITIES_LISTED: u16 = 1 << 4;
const CAPABILITIES: u64 = 0x34;
const PCI_EXPRESS: u8 = 0x10;
/// Device Capabilities, at this offset in the PCI Express capability, and its function-level-reset bit.
const DEVICE_CAPABILITIES: u64 = 4;
const FLR: u32 = 1 << 28;

/// The configuration space and reset control of one PCI function.
#[derive(Debug)]
pub struct Function {
    config: File,
    reset: File,
    flr: bool,
    #[cfg(test)]
    stall: Stall,
}

/// A pause the next bus-master clear takes after its write and before its read-back.
#[cfg(test)]
#[derive(Default)]
struct Stall(std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>);

#[cfg(test)]
impl std::fmt::Debug for Stall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Stall")
    }
}

impl Function {
    /// Opens the function at `dir`, `/sys/bus/pci/devices/<address>`, and reads whether it supports function-level reset.
    ///
    /// # Errors
    ///
    /// The I/O error of opening or reading `config` or opening `reset`.
    pub fn open(dir: &Path) -> io::Result<Self> {
        let config = OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.join("config"))?;
        // sysfs exposes `reset` as write-only; requesting read access causes the open to fail.
        let reset = OpenOptions::new().write(true).open(dir.join("reset"))?;
        let flr = flr_capable(&config)?;
        Ok(Self {
            config,
            reset,
            flr,
            #[cfg(test)]
            stall: Stall::default(),
        })
    }

    /// Whether the function advertises function-level reset in its PCI Express capability.
    pub fn flr(&self) -> bool {
        self.flr
    }

    /// Reads the command register, whose [`BUS_MASTER`] bit a stop
    /// certificate records.
    ///
    /// # Errors
    ///
    /// An I/O error, or `InvalidData` when the register reads all zeroes: a live function decodes memory, so its command register is nonzero, and all zeroes is a read of something else.
    pub(crate) fn command(&self) -> io::Result<u16> {
        let command = read_u16(&self.config, COMMAND)?;
        if command == 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(command)
    }

    /// Sets or clears bus-master enable, leaving the command register's other bits as they were.
    ///
    /// # Errors
    ///
    /// An I/O error, or `InvalidData` when the command register reads all zeroes, before the write or on the read-back, or does not read back exactly as written. A clear that wrote zero therefore proves nothing: its read-back is the all-zero read [`command`](Self::command) refuses.
    pub fn set_bus_master(&self, on: bool) -> io::Result<()> {
        let command = self.command()?;
        let wanted = if on {
            command | BUS_MASTER
        } else {
            command & !BUS_MASTER
        };
        self.config.write_all_at(&wanted.to_le_bytes(), COMMAND)?;
        #[cfg(test)]
        if !on {
            let stall = self
                .stall
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            if let Some(stall) = stall {
                stall();
            }
        }
        if self.command()? == wanted {
            Ok(())
        } else {
            Err(io::ErrorKind::InvalidData.into())
        }
    }

    /// Makes the next bus-master clear run `stall` after its write and before its read-back.
    #[cfg(test)]
    pub(crate) fn stall_before_readback(&self, stall: impl FnOnce() + Send + 'static) {
        *self.stall.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(Box::new(stall));
    }

    /// Resets the function through the kernel, which saves and restores its configuration around the reset.
    ///
    /// # Errors
    ///
    /// `Unsupported` without function-level reset, or the I/O error of the write.
    pub fn reset(&self) -> io::Result<()> {
        if !self.flr {
            return Err(io::ErrorKind::Unsupported.into());
        }
        self.reset.write_all_at(b"1", 0)
    }
}

fn read_u16(config: &File, at: u64) -> io::Result<u16> {
    let mut bytes = [0; 2];
    config.read_exact_at(&mut bytes, at)?;
    Ok(u16::from_le_bytes(bytes))
}

/// Walks the capability list to the PCI Express capability and reads its function-level-reset bit.
fn flr_capable(config: &File) -> io::Result<bool> {
    if read_u16(config, STATUS)? & CAPABILITIES_LISTED == 0 {
        return Ok(false);
    }
    let mut byte = [0; 1];
    config.read_exact_at(&mut byte, CAPABILITIES)?;
    let mut at = byte[0] & !3;
    // The 48 dwords past the header bound a well-formed list.
    for _ in 0..48 {
        if at < 0x40 {
            return Ok(false);
        }
        let mut entry = [0; 2];
        config.read_exact_at(&mut entry, u64::from(at))?;
        if entry[0] == PCI_EXPRESS {
            let mut caps = [0; 4];
            config.read_exact_at(&mut caps, u64::from(at) + DEVICE_CAPABILITIES)?;
            return Ok(u32::from_le_bytes(caps) & FLR != 0);
        }
        at = entry[1] & !3;
    }
    Ok(false)
}

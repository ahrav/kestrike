//! The install's static pkg-config link metadata and release header, read
//! into the final link's plan or refused.
//!
//! The plan links every SPDK and DPDK archive whole, from libdpdk's libdir,
//! in the order the metadata reports, and links only system libraries
//! dynamically, because the NVMe PCIe transport, the PCI bus, the ENA PMD and
//! the ring mempool handlers register from constructors that a plain static
//! link drops without a link error. Every refusal is an `Err` that names
//! the token, archive or header field it refuses, or states that the
//! metadata holds no archive in a whole-archive scope.

use std::collections::BTreeSet;
use std::path::Path;
use std::string::{String, ToString};
use std::vec::Vec;

/// The SPDK release the checked-in bindings were generated from, as the
/// major, minor and patch fields of `spdk/version.h`.
pub const SPDK_VERSION: [&str; 3] = ["25", "5", "1"];

/// The archives and system libraries of the final link, in reported order.
#[derive(Debug, PartialEq, Eq)]
pub struct LinkPlan {
    /// SPDK and DPDK archives, linked whole.
    pub archives: Vec<String>,
    /// The other archives the metadata names by path, such as ISA-L's,
    /// linked plainly. An SPDK or DPDK archive named by path is in
    /// `archives`.
    pub bundled: Vec<String>,
    pub system: Vec<String>,
}

/// SPDK archives come from SPDK's static metadata `spdk` and DPDK archives
/// from the whole-archive scope of libdpdk's static metadata `dpdk`. A DPDK
/// library SPDK names outside that scope, or a DPDK library offered for
/// dynamic linking, would bring a second DPDK copy into the link, so the plan
/// names each DPDK library once, as a static archive from the install's
/// `libdir`. Any other archive the metadata names by absolute path, such as
/// ISA-L's, links plainly from the same libdir, by its file name. Under
/// `sanitizer`, the `asan` system library an ASan install's metadata names
/// is left out: the Rust sanitizer runtime the final link carries supplies
/// it, and a second runtime would conflict with it.
///
/// # Errors
///
/// Refuses a token in the whole-archive scope other than a search path or a
/// `-l:lib<name>.a` archive of a library name, metadata that holds no
/// archive in a whole-archive scope, whether the scope is absent or holds
/// search paths alone, a token [`classify`] does not recognize, a DPDK
/// library outside the scope, and an archive of the plan that is not a file
/// in `libdir`.
pub fn link_plan(
    spdk: &str,
    dpdk: &str,
    libdir: &Path,
    sanitizer: Option<&str>,
) -> Result<LinkPlan, String> {
    let mut dpdk_archives = Vec::new();
    let mut outside = Vec::new();
    let mut whole = false;
    for token in dpdk.split_whitespace() {
        match token {
            "-Wl,--whole-archive" => whole = true,
            "-Wl,--no-whole-archive" => whole = false,
            _ if whole && token.starts_with("-L") => {}
            _ if whole => match token
                .strip_prefix("-l:lib")
                .and_then(|t| t.strip_suffix(".a"))
            {
                Some(archive) if is_library_name(archive) => {
                    dpdk_archives.push(archive.to_string());
                }
                _ => {
                    return Err(std::format!(
                        "libdpdk's whole-archive scope holds {token}, not a search path or a -l:lib<name>.a archive whose name holds ASCII letters, digits and underscores alone"
                    ));
                }
            },
            _ => outside.push(token),
        }
    }
    if dpdk_archives.is_empty() {
        return Err(
            "libdpdk's static metadata holds no archive in a whole-archive scope".to_string(),
        );
    }

    let mut archives = Vec::new();
    let mut bundled = Vec::new();
    let mut system = Vec::new();
    for token in spdk.split_whitespace().chain(outside) {
        match classify(token)? {
            Token::Ignored => {}
            Token::Spdk(lib) => archives.push(lib.to_string()),
            Token::Bundled(lib) => bundled.push(lib.to_string()),
            Token::Dpdk(lib) if dpdk_archives.iter().any(|a| a == lib) => {}
            Token::Dpdk(lib) => {
                return Err(std::format!(
                    "{lib} is outside libdpdk's static whole-archive scope"
                ));
            }
            Token::System(lib) => system.push(lib.to_string()),
        }
    }
    archives.extend(dpdk_archives);
    for archive in archives.iter().chain(&bundled) {
        let file = libdir.join(std::format!("lib{archive}.a"));
        if !file.is_file() {
            return Err(std::format!("missing static archive {}", file.display()));
        }
    }
    let mut seen = BTreeSet::new();
    system.retain(|lib| seen.insert(lib.clone()));
    if sanitizer.is_some() {
        system.retain(|lib| lib != "asan");
    }
    Ok(LinkPlan {
        archives,
        bundled,
        system,
    })
}

/// One metadata token outside libdpdk's whole-archive scope.
enum Token<'a> {
    /// A flag the Rust link already provides or the static link makes moot.
    Ignored,
    Spdk(&'a str),
    /// A DPDK library, which must already be one of the scope's archives.
    Dpdk(&'a str),
    /// A static archive other than an SPDK or DPDK one, named by its
    /// absolute path.
    Bundled(&'a str),
    System(&'a str),
}

/// Classifies a token, refusing any the plan does not recognize.
///
/// Library search paths come from libdpdk's libdir, so the plan ignores
/// SPDK's `-L` entries, which also name its build tree. The Rust link supplies
/// `-lpthread` and `--as-needed`, and the binary resolves every DPDK symbol
/// statically, so the plan ignores `-pthread`, `--as-needed` and
/// `--export-dynamic`. Every other token names one library, as `-l<name>` or
/// as the absolute path of `lib<name>.a`, and the name passes
/// [`is_library_name`] in either spelling. An SPDK or DPDK library
/// classifies by its name alone, so one named by path links whole or meets
/// the second-copy refusal like the same library named by `-l`. Any other
/// library is a bundled archive when named by path and a system library
/// when named by `-l`. The plan checks a file in `libdir` for each archive
/// and for each bundled archive; a system library is a name alone, so an
/// archive of the install that the metadata names by `-l` gets no file
/// check here, and the build tracks and hashes no file for it.
fn classify(token: &str) -> Result<Token<'_>, String> {
    let (lib, by_path) = match token {
        "-pthread" | "-Wl,--as-needed" | "-Wl,--export-dynamic" => return Ok(Token::Ignored),
        _ if token.starts_with("-L") => return Ok(Token::Ignored),
        _ if token.starts_with('/') => (
            token
                .rsplit_once('/')
                .and_then(|(_, file)| file.strip_prefix("lib")?.strip_suffix(".a")),
            true,
        ),
        _ => (token.strip_prefix("-l"), false),
    };
    let lib = lib
        .filter(|lib| is_library_name(lib))
        .ok_or_else(|| std::format!("unrecognized pkg-config link token {token}"))?;
    Ok(if lib.starts_with("spdk_") {
        Token::Spdk(lib)
    } else if lib.starts_with("rte_") {
        Token::Dpdk(lib)
    } else if by_path {
        Token::Bundled(lib)
    } else {
        Token::System(lib)
    })
}

/// Whether `name` is a library name the plan places in a file name or a link
/// directive: ASCII letters, digits and underscores, at least one.
fn is_library_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Checks that `text`, the installed `spdk/version.h` at `header`, defines
/// the major, minor and patch fields of [`SPDK_VERSION`]. SPDK's pkg-config
/// versions are library ABI versions, so the release is read from the
/// header.
///
/// # Errors
///
/// Names the header and the fields it declares when any differs or is
/// absent.
pub fn check_spdk_version(header: &Path, text: &str) -> Result<(), String> {
    let field = |name: &str| {
        text.lines()
            .find_map(|line| {
                let mut words = line.strip_prefix("#define ")?.split_whitespace();
                // A longer identifier that begins with `name` is another macro.
                if words.next()? != name {
                    return None;
                }
                words.next()
            })
            .unwrap_or("")
    };
    let found = [
        field("SPDK_VERSION_MAJOR"),
        field("SPDK_VERSION_MINOR"),
        field("SPDK_VERSION_PATCH"),
    ];
    if found != SPDK_VERSION {
        return Err(std::format!(
            "{} declares SPDK {found:?}, expected {SPDK_VERSION:?}",
            header.display()
        ));
    }
    Ok(())
}

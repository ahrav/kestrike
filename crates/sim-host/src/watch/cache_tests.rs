use super::*;

fn listed(etag: Option<&str>) -> Objects {
    ["findings.json", "status.json", "suspects.jsonl"]
        .into_iter()
        .map(|name| {
            (
                name.to_owned(),
                (3, etag.map(|etag| format!("\"{etag}-{name}\""))),
            )
        })
        .collect()
}

fn raw() -> Raw {
    Raw {
        status: Object::Read(b"{\"format\": 1}".to_vec()),
        payload: Some((
            Object::Read(b"line\n".to_vec()),
            Object::Unreadable("holds 9 bytes, more than 8".into()),
        )),
    }
}

fn agreed(raw: Raw) -> Reading {
    Reading {
        raw,
        observed: 0,
        agreed: true,
        cacheable: true,
    }
}

fn cache(name: &str) -> (PathBuf, Cache) {
    let dir = file::scratch(name);
    let cache = Cache::new(&dir);
    (dir, cache)
}

#[test]
fn an_entry_reads_back_only_for_the_listing_it_was_stored_for() {
    let (dir, cache) = cache("cache-listing");
    let shown = listed(Some("a"));
    cache
        .put("sim.i-0000000a.aa", &shown, &agreed(raw()), 0)
        .expect("it stores");
    assert_eq!(cache.get("sim.i-0000000a.aa", &shown), Some(raw()));
    let bare = Raw {
        status: Object::Absent,
        payload: None,
    };
    cache
        .put("sim.i-0000000b.bb", &shown, &agreed(bare.clone()), 0)
        .expect("it stores");
    assert_eq!(cache.get("sim.i-0000000b.bb", &shown), Some(bare));
    let mut replaced = shown.clone();
    replaced.get_mut("suspects.jsonl").expect("listed").1 = Some("\"other\"".into());
    assert_eq!(
        cache.get("sim.i-0000000a.aa", &replaced),
        None,
        "another ETag"
    );
    let mut grown = shown.clone();
    grown.get_mut("status.json").expect("listed").0 = 4;
    assert_eq!(
        cache.get("sim.i-0000000a.aa", &grown),
        None,
        "another length"
    );
    let mut fewer = shown.clone();
    fewer.remove("findings.json");
    assert_eq!(
        cache.get("sim.i-0000000a.aa", &fewer),
        None,
        "another object set"
    );
    assert_eq!(cache.get("sim.i-0000000c.cc", &shown), None, "another root");
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn a_listing_without_etags_is_never_cached() {
    let (dir, cache) = cache("cache-etagless");
    let shown = listed(None);
    cache
        .put("sim.i-0000000a.aa", &shown, &agreed(raw()), 0)
        .expect("a no-op");
    assert!(!dir.join("cache").exists(), "nothing is stored");
    assert_eq!(cache.get("sim.i-0000000a.aa", &shown), None);
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn a_damaged_or_cut_entry_reads_as_none() {
    let (dir, cache) = cache("cache-damaged");
    let shown = listed(Some("a"));
    cache
        .put("sim.i-0000000a.aa", &shown, &agreed(raw()), 0)
        .expect("it stores");
    let path = cache.path("sim.i-0000000a.aa");
    let whole = std::fs::read(&path).expect("the entry");
    for cut in [0, 1, whole.len() / 2, whole.len() - 1] {
        std::fs::write(&path, &whole[..cut]).expect("a cut entry");
        assert_eq!(cache.get("sim.i-0000000a.aa", &shown), None, "cut at {cut}");
    }
    let mut flipped = whole.clone();
    *flipped.last_mut().expect("a byte") ^= 1;
    std::fs::write(&path, &flipped).expect("a damaged entry");
    assert_eq!(
        cache.get("sim.i-0000000a.aa", &shown),
        None,
        "a body that fails its digest"
    );
    let mut longer = whole.clone();
    longer.push(b'x');
    std::fs::write(&path, &longer).expect("a longer entry");
    assert_eq!(cache.get("sim.i-0000000a.aa", &shown), None);
    std::fs::write(&path, &whole).expect("the whole entry");
    assert_eq!(cache.get("sim.i-0000000a.aa", &shown), Some(raw()));
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn retain_removes_every_entry_of_an_unlisted_root() {
    let (dir, cache) = cache("cache-retain");
    let shown = listed(Some("a"));
    for campaign in ["sim.i-0000000a.aa", "sim.i-0000000b.bb"] {
        cache
            .put(campaign, &shown, &agreed(raw()), 0)
            .expect("it stores");
    }
    std::fs::write(dir.join("cache").join(".stray.staged"), b"x").expect("a stray file");
    cache.retain(["sim.i-0000000b.bb"]).expect("it retains");
    assert_eq!(cache.get("sim.i-0000000a.aa", &shown), None);
    assert_eq!(cache.get("sim.i-0000000b.bb", &shown), Some(raw()));
    let left: Vec<_> = std::fs::read_dir(dir.join("cache"))
        .expect("the cache")
        .map(|entry| entry.expect("an entry").file_name())
        .collect();
    assert_eq!(left.len(), 1, "{left:?}");
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

/// An entry of a header line and a body, sealed with a digest line that
/// matches them, so only the guard a test aims at can refuse it.
fn sealed(header: &[u8], body: &[u8]) -> Vec<u8> {
    let mut rest = header.to_vec();
    rest.push(b'\n');
    rest.extend_from_slice(body);
    let mut entry = file::sha256(&rest).into_bytes();
    entry.push(b'\n');
    entry.extend_from_slice(&rest);
    entry
}

/// The header line and the body of the entry at `path`.
fn opened(path: &Path) -> (Vec<u8>, Vec<u8>) {
    let whole = std::fs::read(path).expect("the entry");
    let rest = &whole[65..];
    let split = rest
        .iter()
        .position(|byte| *byte == b'\n')
        .expect("a header line");
    (rest[..split].to_vec(), rest[split + 1..].to_vec())
}

#[test]
fn a_damaged_header_or_another_format_reads_as_none() {
    let (dir, cache) = cache("cache-header");
    let shown = listed(Some("a"));
    cache
        .put("sim.i-0000000a.aa", &shown, &agreed(raw()), 0)
        .expect("it stores");
    let path = cache.path("sim.i-0000000a.aa");
    let whole = std::fs::read(&path).expect("the entry");
    let (header, body) = opened(&path);
    assert_eq!(
        sealed(&header, &body),
        whole,
        "the fixture seals as put does"
    );
    let text = String::from_utf8(whole.clone()).expect("a text entry");
    let damaged = text.replacen("more than 8", "more than 9", 1);
    assert_ne!(damaged, text, "the header names the unreadable reason");
    std::fs::write(&path, &damaged).expect("a damaged reason");
    assert_eq!(
        cache.get("sim.i-0000000a.aa", &shown),
        None,
        "the digest covers the header"
    );
    let header_text = String::from_utf8(header.clone()).expect("a text header");
    let other = header_text.replacen("\"format\":5", "\"format\":4", 1);
    assert_ne!(other, header_text, "the header names its format");
    std::fs::write(&path, sealed(other.as_bytes(), &body)).expect("another format");
    assert_eq!(
        cache.get("sim.i-0000000a.aa", &shown),
        None,
        "a sealed entry of another format"
    );
    let mut padded = header.clone();
    padded.resize(HEADER_BOUND as usize, b' ');
    std::fs::write(&path, sealed(&padded, &body)).expect("a header at its bound");
    assert_eq!(
        cache.get("sim.i-0000000a.aa", &shown),
        Some(raw()),
        "a header of exactly the bound reads"
    );
    padded.push(b' ');
    std::fs::write(&path, sealed(&padded, &body)).expect("a header past its bound");
    assert_eq!(cache.get("sim.i-0000000a.aa", &shown), None);
    std::fs::copy(&path, cache.path("sim.i-0000000b.bb")).expect("a copy");
    std::fs::write(&path, &whole).expect("the whole entry");
    std::fs::copy(&path, cache.path("sim.i-0000000b.bb")).expect("a copy at another root");
    assert_eq!(
        cache.get("sim.i-0000000b.bb", &shown),
        None,
        "an entry names its own root"
    );
    let huge = header_text.replacen("{\"read\":5}", "{\"read\":1000000000}", 1);
    assert_ne!(huge, header_text, "the header names the list's length");
    std::fs::write(&path, sealed(huge.as_bytes(), &body)).expect("a length past the file");
    assert_eq!(
        cache.get("sim.i-0000000a.aa", &shown),
        None,
        "a length past the entry's own length"
    );
    std::fs::write(&path, &whole).expect("the whole entry");
    assert_eq!(cache.get("sim.i-0000000a.aa", &shown), Some(raw()));
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn an_entry_past_the_reserve_is_refused_and_reclaim_gives_the_space_back() {
    let (dir, cache) = cache("cache-reserve");
    let shown = listed(Some("a"));
    assert!(
        cache
            .put("sim.i-0000000a.aa", &shown, &agreed(raw()), u64::MAX / 2)
            .is_err(),
        "no filesystem keeps that reserve"
    );
    assert!(
        !cache.path("sim.i-0000000a.aa").exists(),
        "nothing is written"
    );
    cache
        .put("sim.i-0000000a.aa", &shown, &agreed(raw()), 0)
        .expect("it stores");
    assert_eq!(cache.reclaim(&dir, 0), Ok(false), "room enough");
    assert!(cache.path("sim.i-0000000a.aa").exists());
    assert_eq!(cache.reclaim(&dir, u64::MAX / 2), Ok(true));
    assert!(
        !cache.path("sim.i-0000000a.aa").exists(),
        "every entry leaves"
    );
    assert!(dir.join("cache").is_dir(), "the cache directory stays");
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn a_refused_replacement_removes_the_entry_its_root_holds() {
    let (dir, cache) = cache("cache-refused");
    let shown = listed(Some("a"));
    let [format, listing, other] = [
        "sim.i-0000000a.aa",
        "sim.i-0000000b.bb",
        "sim.i-0000000c.cc",
    ];
    for campaign in [format, listing, other] {
        cache
            .put(campaign, &shown, &agreed(raw()), 0)
            .expect("it stores");
    }
    let path = cache.path(format);
    let (header, body) = opened(&path);
    let header = String::from_utf8(header).expect("a text header");
    let earlier = header.replacen("\"format\":5", "\"format\":4", 1);
    assert_ne!(earlier, header, "the header names its format");
    std::fs::write(&path, sealed(earlier.as_bytes(), &body)).expect("another format");
    assert_eq!(cache.get(format, &shown), None);
    assert!(
        cache
            .put(format, &shown, &agreed(raw()), u64::MAX / 2)
            .is_err(),
        "no filesystem keeps that reserve"
    );
    assert!(!path.exists(), "the entry of another format leaves");
    let replaced = listed(Some("b"));
    assert_eq!(cache.get(listing, &replaced), None);
    assert!(
        cache
            .put(listing, &replaced, &agreed(raw()), u64::MAX / 2)
            .is_err()
    );
    assert!(
        !cache.path(listing).exists(),
        "the entry of another listing leaves"
    );
    assert_eq!(
        cache.get(other, &shown),
        Some(raw()),
        "another root's entry stays"
    );
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn a_read_that_may_not_stand_for_its_root_is_never_cached() {
    let (dir, cache) = cache("cache-uncacheable");
    let reading = Reading {
        cacheable: false,
        ..agreed(raw())
    };
    cache
        .put("sim.i-0000000a.aa", &listed(Some("a")), &reading, 0)
        .expect("a no-op");
    assert!(!dir.join("cache").exists(), "nothing is stored");
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn a_read_that_disagreed_with_its_listing_is_never_cached() {
    let (dir, cache) = cache("cache-disagreed");
    let shown = listed(Some("a"));
    let reading = Reading {
        agreed: false,
        ..agreed(raw())
    };
    cache
        .put("sim.i-0000000a.aa", &shown, &reading, 0)
        .expect("a no-op");
    assert!(!dir.join("cache").exists(), "nothing is stored");
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn sweep_removes_only_staged_files_and_keeps_directories() {
    let (dir, cache) = cache("cache-sweep");
    let shown = listed(Some("a"));
    cache
        .put("sim.i-0000000a.aa", &shown, &agreed(raw()), 0)
        .expect("it stores");
    let staged = format!(".{}.staged", file::sha256(b"sim.i-0000000b.bb"));
    std::fs::write(dir.join("cache").join(&staged), b"part").expect("a staged leftover");
    std::fs::create_dir(dir.join("cache").join(".held")).expect("a directory");
    assert!(cache.sweep().is_err(), "a directory under cache/ is named");
    assert!(!dir.join("cache").join(&staged).exists());
    assert!(
        dir.join("cache").join(".held").is_dir(),
        "a directory stays"
    );
    assert_eq!(cache.get("sim.i-0000000a.aa", &shown), Some(raw()));
    assert!(cache.retain([]).is_err());
    assert!(
        dir.join("cache").join(".held").is_dir(),
        "a directory stays"
    );
    assert!(!cache.path("sim.i-0000000a.aa").exists());
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

#[test]
fn a_symlinked_cache_directory_is_refused_and_its_target_kept() {
    let (dir, cache) = cache("cache-symlink");
    let target = dir.join("elsewhere");
    std::fs::create_dir_all(target.join("subdirectory")).expect("a target directory");
    std::fs::write(target.join("sentinel"), b"kept").expect("a sentinel");
    std::fs::write(target.join(".sentinel.staged"), b"kept").expect("a dotted sentinel");
    let shown = listed(Some("a"));
    cache
        .put("sim.i-0000000a.aa", &shown, &agreed(raw()), 0)
        .expect("it stores");
    let entry = file::sha256(b"sim.i-0000000a.aa");
    std::fs::rename(dir.join("cache").join(&entry), target.join(&entry)).expect("a valid entry");
    std::fs::remove_dir(dir.join("cache")).expect("an empty cache");
    std::os::unix::fs::symlink(&target, dir.join("cache")).expect("a symlinked cache");
    assert_eq!(
        cache.get("sim.i-0000000a.aa", &shown),
        None,
        "a lookup through a symlinked cache is a miss"
    );
    assert!(cache.retain([]).is_err());
    assert!(cache.sweep().is_err());
    assert_eq!(
        std::fs::read(target.join("sentinel")).expect("kept"),
        b"kept"
    );
    assert!(target.join(".sentinel.staged").exists());
    assert!(target.join("subdirectory").is_dir());
    assert!(target.join(&entry).exists(), "the target's entry stays");
    std::fs::remove_file(dir.join("cache")).expect("the link");
    assert_eq!(cache.retain([]), Ok(()), "an absent cache holds nothing");
    assert!(!dir.join("cache").exists(), "retain creates no cache");
    assert_eq!(cache.get("sim.i-0000000a.aa", &shown), None);
    assert!(!dir.join("cache").exists(), "a lookup creates no cache");
    std::fs::create_dir(dir.join("cache")).expect("a real cache");
    std::os::unix::fs::symlink(target.join(&entry), dir.join("cache").join(&entry))
        .expect("a symlinked entry");
    assert_eq!(
        cache.get("sim.i-0000000a.aa", &shown),
        None,
        "a symlinked entry is a miss"
    );
    std::fs::remove_dir_all(&dir).expect("cleanup");
}

//! The runner emits libtest-compatible case listings and outcome lines.

use std::process::ExitCode;
use std::sync::Mutex;
use std::time::Instant;

use super::cases::CASES;

pub fn runner() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut filters = Vec::new();
    let mut skips = Vec::new();
    let (mut list, mut ignored, mut exact) = (false, false, false);
    let mut threads = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--list" => list = true,
            "--ignored" => ignored = true,
            "--exact" => exact = true,
            "--skip" => match rest.next() {
                Some(skip) => skips.push(skip.clone()),
                None => {
                    eprintln!("--skip requires a case name");
                    return ExitCode::from(2);
                }
            },
            flag if flag.starts_with("--skip=") => {
                skips.push(flag.trim_start_matches("--skip=").to_owned());
            }
            "--test-threads" => {
                threads = rest.next().and_then(|value| value.parse::<usize>().ok());
                if threads.is_none_or(|count| count == 0) {
                    eprintln!("--test-threads requires a positive count");
                    return ExitCode::from(2);
                }
            }
            flag if flag.starts_with("--test-threads=") => {
                threads = flag
                    .trim_start_matches("--test-threads=")
                    .parse::<usize>()
                    .ok();
                if threads.is_none_or(|count| count == 0) {
                    eprintln!("--test-threads requires a positive count");
                    return ExitCode::from(2);
                }
            }
            "--format" | "--color" => {
                rest.next();
            }
            flag if flag.starts_with('-') => {}
            filter => filters.push(filter.to_owned()),
        }
    }
    let matches = |name: &str, filter: &str| {
        if exact {
            name == filter
        } else {
            name.contains(filter)
        }
    };
    let chosen: Vec<&(&str, fn())> = CASES
        .iter()
        .filter(|(name, _)| {
            !ignored
                && !skips.iter().any(|skip| matches(name, skip))
                && (filters.is_empty() || filters.iter().any(|filter| matches(name, filter)))
        })
        .collect();
    let filtered = CASES.len() - chosen.len();
    if list {
        for (name, _) in &chosen {
            println!("{name}: test");
        }
        if !chosen.is_empty() {
            println!();
        }
        println!("{} tests, 0 benchmarks", chosen.len());
        return ExitCode::SUCCESS;
    }
    let started = Instant::now();
    println!("\nrunning {} tests", chosen.len());
    let threads = threads
        .or_else(|| {
            std::env::var("RUST_TEST_THREADS")
                .ok()
                .and_then(|count| count.parse().ok())
        })
        .unwrap_or(4usize)
        .max(1);
    let queue = Mutex::new(chosen.iter());
    let failed = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                loop {
                    let next = queue.lock().expect("the queue").next();
                    let Some((name, case)) = next else { return };
                    let passed = std::panic::catch_unwind(case).is_ok();
                    println!("test {name} ... {}", if passed { "ok" } else { "FAILED" });
                    if !passed {
                        failed.lock().expect("the failures").push(*name);
                    }
                }
            });
        }
    });
    let failed = failed.into_inner().expect("the failures");
    let passed = chosen.len() - failed.len();
    if !failed.is_empty() {
        println!("\nfailures:");
        for name in &failed {
            println!("    {name}");
        }
    }
    println!(
        "\ntest result: {}. {passed} passed; {} failed; 0 ignored; 0 measured; {filtered} filtered out; finished in {:.2}s\n",
        if failed.is_empty() { "ok" } else { "FAILED" },
        failed.len(),
        started.elapsed().as_secs_f64(),
    );
    if failed.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(101)
    }
}

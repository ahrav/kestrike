use std::fs;
use std::io;

use super::{package_path, transcription_drift};
use crate::genmc::case::tests::root;
use crate::genmc::refusal::Error;
use crate::json::parse;
use crate::paths::tests::Scratch;

#[test]
fn a_kernel_path_joins_the_package_as_a_path_join_does() {
    assert_eq!(package_path("", "src/k.rs"), "src/k.rs");
    assert_eq!(package_path("/", "src/k.rs"), "/src/k.rs");
    assert_eq!(
        package_path("verification/genmc/packages/kernels", "src/k.rs"),
        "verification/genmc/packages/kernels/src/k.rs"
    );
}

#[test]
fn an_empty_package_reads_kernel_files_under_the_root_and_a_root_package_reads_from_slash() {
    let scratch = Scratch::new("transcription-package");
    fs::create_dir_all(scratch.0.join("src")).expect("the directory is made");
    fs::copy(
        root().join("verification/genmc/packages/kernels/src/grace_kernel.rs"),
        scratch.0.join("src/grace_kernel.rs"),
    )
    .expect("the kernel copies");
    let declared = |package: &str| {
        parse(&format!(
            r#"{{"package": "{package}", "transcribed": [], "bindings": [],
                "strengths": [{{"file": "src/grace_kernel.rs", "impl": "impl ModelStrength for Sequential"}}]}}"#
        ))
        .expect("JSON")
    };
    let unbound: Vec<String> = ["BOUND_LOAD", "CLAIM_LOAD", "CLAIM_RAISE", "COMMIT", "OBSERVE"]
        .iter()
        .map(|constant| {
            format!(
                "src/grace_kernel.rs transcribes {constant} in its strength and no binding entry binds it"
            )
        })
        .collect();
    assert_eq!(
        transcription_drift(&declared(""), &scratch.0).expect("the kernel reads"),
        unbound
    );
    match transcription_drift(&declared("/"), &scratch.0) {
        Err(Error::Os(error)) => assert_eq!(error.kind(), io::ErrorKind::NotFound),
        other => panic!("the file /src/grace_kernel.rs is read, not {other:?}"),
    }
}

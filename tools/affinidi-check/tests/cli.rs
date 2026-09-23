//! Exercise the checker as a binary, including its file reads and printed document.

use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const CLI: &str = env!("CARGO_BIN_EXE_didwebs-affinidi-check");
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
const DID: &str = "did:webs:did-webs-service%3a7676:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";
const KEY: &str = "DHr0-I-mMN7h6cLMOTRJkkfPuMd0vgQPrOk4Y3edaHjr";

fn fixture(name: &str) -> String {
    format!("{FIXTURES}/{name}")
}

#[test]
fn cli_resolves_affinidis_reference_artifacts_and_prints_the_derived_document() {
    let output = Command::new(CLI)
        .args([
            DID,
            &fixture("ENro7uf0.keri.cesr"),
            &fixture("ENro7uf0.did.json"),
        ])
        .output()
        .expect("checker starts");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let document: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    assert_eq!(document["id"], DID);
    assert_eq!(
        document["verificationMethod"][0]["publicKeyJwk"]["kid"],
        KEY
    );
    assert_eq!(document["authentication"][0], format!("{DID}#{KEY}"));
}

#[test]
fn cli_refuses_oversized_stream_and_document_before_resolution() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let oversized = std::env::temp_dir().join(format!(
        "didwebs-affinidi-check-{}-{nonce}",
        std::process::id()
    ));
    let file = fs::File::create(&oversized).expect("temporary file");
    file.set_len(8 * 1024 * 1024 + 1)
        .expect("sparse oversized file");
    drop(file);
    let oversized_path = oversized.to_string_lossy().into_owned();
    let stream_fixture = fixture("ENro7uf0.keri.cesr");
    let document_fixture = fixture("ENro7uf0.did.json");

    for (stream, document) in [
        (&oversized_path, &document_fixture),
        (&stream_fixture, &oversized_path),
    ] {
        let output = Command::new(CLI)
            .args([DID, stream, document])
            .output()
            .expect("checker starts");
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("e.input.range.interop-artifact.f"),
            "{}",
            String::from_utf8_lossy(&output.stderr),
        );
    }

    fs::remove_file(oversized).expect("remove temporary file");
}

#[test]
fn cli_reports_open_and_read_failures_with_the_artifact_error() {
    let document = fixture("ENro7uf0.did.json");
    for path in ["/this/didwebs/artifact/does/not/exist", FIXTURES] {
        let output = Command::new(CLI)
            .args([DID, path, &document])
            .output()
            .expect("checker starts");
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("e.state.missing.interop-artifact.r"),
            "{}",
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

#[test]
fn cli_rejects_an_invalid_did_before_opening_artifacts() {
    let output = Command::new(CLI)
        .args([
            "did:web:example.com:Eabc",
            "/this/didwebs/artifact/does/not/exist",
            "/this/didwebs/document/does/not/exist",
        ])
        .output()
        .expect("checker starts");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("e.input.format.interop-check.f"),
        "{}",
        String::from_utf8_lossy(&output.stderr),
    );
}

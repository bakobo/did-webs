//! Cold-start checks against the two witnessed M7 publications.

use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

const CLI: &str = env!("CARGO_BIN_EXE_didwebs-affinidi-check-patched");
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");
const GUY: &str = "ELEGG02va7qWpBiTCQfTXFwbNTk-FVWJr7nWJX2DhHy7";

fn artifact(who: &str, name: &str) -> String {
    format!("{FIXTURES}/{who}/{name}")
}

fn check(did: &str, stream: &Path, document: &Path) -> Output {
    Command::new(CLI)
        .args([did, stream.to_str().unwrap(), document.to_str().unwrap()])
        .output()
        .expect("checker starts")
}

#[test]
fn both_m7_dids_resolve_from_their_published_artifacts() {
    for (who, aid, key) in [
        (
            "reissuer",
            "ELXGlco2cpv7qvt8xl4VyVydpVO0KksVObTEMX4O_5Wl",
            "DM25c3nmDayEGlzoap2cx4xLHRlyMM1TWH7m4ilsBD6K",
        ),
        (
            "guy-rotated",
            GUY,
            "DCComigjTwetk8AUE5Mugj0IZ8PhUwxX03cvCUvrRd8y",
        ),
    ] {
        let did = format!("did:webs:dids.bakobo.com:demo:{aid}");
        let stream = artifact(who, "keri.cesr");
        let document = artifact(who, "did.json");
        let output = check(&did, Path::new(&stream), Path::new(&document));
        assert!(
            output.status.success(),
            "{who}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let resolved: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(resolved["id"], did);
        assert_eq!(
            resolved["verificationMethod"][0]["publicKeyJwk"]["kid"],
            key
        );
    }
}

#[test]
fn changed_document_key_and_changed_kel_are_refused() {
    let temp = tempfile::tempdir().unwrap();
    let did = format!("did:webs:dids.bakobo.com:demo:{GUY}");
    let stream = artifact("guy-rotated", "keri.cesr");
    let document = artifact("guy-rotated", "did.json");

    let mut changed_document: serde_json::Value =
        serde_json::from_slice(&fs::read(&document).unwrap()).unwrap();
    changed_document["verificationMethod"][0]["id"] = "#DNotThePublishedKey".into();
    changed_document["verificationMethod"][0]["publicKeyJwk"]["kid"] = "DNotThePublishedKey".into();
    let changed_document_path = temp.path().join("changed-did.json");
    fs::write(
        &changed_document_path,
        serde_json::to_vec(&changed_document).unwrap(),
    )
    .unwrap();
    let document_result = check(&did, Path::new(&stream), &changed_document_path);
    assert!(!document_result.status.success());
    assert!(String::from_utf8_lossy(&document_result.stderr).contains("e.proof.stream.interop.f"));

    let mut changed_stream = fs::read(&stream).unwrap();
    let offset = changed_stream
        .windows(8)
        .position(|bytes| bytes == b"\"kt\":\"1\"")
        .unwrap();
    changed_stream[offset + 6] = b'2';
    let changed_stream_path = temp.path().join("changed-keri.cesr");
    fs::write(&changed_stream_path, changed_stream).unwrap();
    let stream_result = check(&did, &changed_stream_path, Path::new(&document));
    assert!(!stream_result.status.success());
    assert!(String::from_utf8_lossy(&stream_result.stderr).contains("e.proof.stream.interop.f"));
}

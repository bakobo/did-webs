//! Cold-start artifact check against the published affinidi-did-webs 0.7.0 crate.

use std::{env, fs::File, io::Read, process::ExitCode};

use affinidi_did_webs::{DidWebs, resolve_from_artifacts};

const INVOCATION_ERROR: &str = "e.input.format.interop-check.f";
const ARTIFACT_READ_ERROR: &str = "e.state.missing.interop-artifact.r";
const ARTIFACT_RANGE_ERROR: &str = "e.input.range.interop-artifact.f";
const RESOLUTION_ERROR: &str = "e.proof.stream.interop.f";
const MAX_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024;

fn read_artifact(path: &str) -> Result<Vec<u8>, String> {
    let file = File::open(path)
        .map_err(|error| format!("{ARTIFACT_READ_ERROR}: Cannot read {path}: {error}."))?;
    let mut bytes = Vec::new();
    file.take(MAX_ARTIFACT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{ARTIFACT_READ_ERROR}: Cannot read {path}: {error}."))?;
    if bytes.len() as u64 > MAX_ARTIFACT_BYTES {
        return Err(format!(
            "{ARTIFACT_RANGE_ERROR}: The artifact at {path} exceeds the {MAX_ARTIFACT_BYTES}-byte limit."
        ));
    }
    Ok(bytes)
}

fn resolve_artifacts(did: &str, stream: &[u8], document: &[u8]) -> Result<String, String> {
    let did = DidWebs::parse(did).map_err(|error| format!("{INVOCATION_ERROR}: {error}"))?;
    let resolved = resolve_from_artifacts(&did, stream, Some(document))
        .map_err(|error| format!("{RESOLUTION_ERROR}: {error}"))?;
    serde_json::to_string_pretty(&resolved).map_err(|error| format!("{RESOLUTION_ERROR}: {error}"))
}

fn run() -> Result<String, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let [did, stream_path, document_path] = args.as_slice() else {
        return Err(format!(
            "{INVOCATION_ERROR}: Supply DID, keri.cesr path, and did.json path."
        ));
    };
    let stream = read_artifact(stream_path)?;
    let document = read_artifact(document_path)?;
    resolve_artifacts(did, &stream, &document)
}

fn main() -> ExitCode {
    match run() {
        Ok(document) => {
            println!("{document}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_artifacts;

    const DID: &str = "did:webs:example.com:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";

    #[test]
    fn malformed_did_is_rejected_before_the_stream() {
        assert!(resolve_artifacts("did:web:example.com:Eabc", b"", b"{}").is_err());
    }

    #[test]
    fn empty_stream_is_rejected() {
        assert!(resolve_artifacts(DID, b"", b"{}").is_err());
    }
}

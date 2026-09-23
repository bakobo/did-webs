//! Cold-start artifact check against the published affinidi-did-webs 0.7.0 crate.

use std::{env, fs, process::ExitCode};

use affinidi_did_webs::{DidWebs, resolve_from_artifacts};

const INVOCATION_ERROR: &str = "e.input.format.interop-check.f";
const ARTIFACT_READ_ERROR: &str = "e.state.missing.interop-artifact.r";
const RESOLUTION_ERROR: &str = "e.proof.stream.interop.f";

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
    let stream = fs::read(stream_path)
        .map_err(|error| format!("{ARTIFACT_READ_ERROR}: Cannot read {stream_path}: {error}."))?;
    let document = fs::read(document_path)
        .map_err(|error| format!("{ARTIFACT_READ_ERROR}: Cannot read {document_path}: {error}."))?;
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

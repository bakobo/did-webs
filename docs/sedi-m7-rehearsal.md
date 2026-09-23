# SEDI M7 witnessed DID rehearsal

This recipe creates two local, witnessed KERI v1 Ed25519 AIDs, issues each AID's designated-aliases ACDC, and runs `didwebs publish`. The host and DID path prefix are parameters; the defaults are `dids.bakobo.com` and `demo`. These DIDs are provisional while the shared trust-anchor hostname decision remains open. Changing either value requires new alias ACDCs and publication.

From this repo's worktree, install its pinned dependencies with `uv sync`, then run the three demo witnesses in another terminal:

```sh
nice -n 19 ionice -c 3 uv run kli witness demo --base m7-witness-demo --version 1.0
```

In the first terminal, choose a fresh KLI base name, then create and publish both controllers. Keep the witness process running throughout. The final two arguments are the output directory and path prefix:

```sh
nice -n 19 ionice -c 3 bash scripts/sedi_m7.sh create m7-controller-demo dids.bakobo.com .ignored/m7/demo demo
```

The script prints the artifact paths. A second `create` with the same base is not a cold start: choose another base to repeat the exercise. To rotate Guy and republish his DID in place:

```sh
nice -n 19 ionice -c 3 bash scripts/sedi_m7.sh rotate m7-controller-demo dids.bakobo.com .ignored/m7/demo demo
```

To serve the generated files locally over TLS without changing DNS, make a short-lived certificate for the DID host and start the loopback server and CONNECT proxy:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout .ignored/m7/localhost.key -out .ignored/m7/localhost.crt -subj /CN=dids.bakobo.com -addext subjectAltName=DNS:dids.bakobo.com -days 2
nice -n 19 ionice -c 3 uv run python scripts/sedi_m7_https.py --root .ignored/m7/demo/artifacts --cert .ignored/m7/localhost.crt --key .ignored/m7/localhost.key
```

The proxy binds `127.0.0.1:8444` and tunnels only `dids.bakobo.com:443` to the TLS listener at `127.0.0.1:8443`. Use `HTTPS_PROXY=http://127.0.0.1:8444`, `REQUESTS_CA_BUNDLE=$PWD/.ignored/m7/localhost.crt`, and an empty `NO_PROXY` when invoking GLEIF's resolver. This preserves the DID's real host and standard HTTPS port. It does not change DNS or `/etc/hosts`.

GLEIF `dws` 0.3.7 and Affinidi `affinidi-did-webs` 0.7.0 both refuse the published artifacts in the 2026-09-23 rehearsal. GLEIF parses the stream and derives the correct current key, but its DID document comparison rejects spec-required `controller`, `authentication`, and `assertionMethod` fields, the optional `@context`, and the different `alsoKnownAs` value. Affinidi rejects the v1 ACDC `-I` source seal triple attachment; when the ACDC is removed for diagnosis, it does not count the stream's indexed witness signatures as receipts. See `docs/scope.md` and `.ignored/m7-report.md` in the rehearsal worktree for the commands and evidence. These are open interop issues; the independent-resolver acceptance criterion has not been met.

## Static hosting contract for `dids.bakobo.com`

An OpenTofu-managed server or static object store needs a public DNS record for `dids.bakobo.com`, a publicly trusted TLS certificate, and HTTPS on port 443. It must serve `GET /demo/<AID>/did.json` as JSON and `GET /demo/<AID>/keri.cesr` as `application/cesr`, without authentication or an HTTP downgrade. Those are the paths encoded by `did:webs:dids.bakobo.com:demo:<AID>`. The host stores only the published artifacts; the controllers' signing keys and keystores stay with the controllers.

The deployment must accept verified artifact updates after KEL or TEL changes, preserve the DID path, and publish each `did.json`/`keri.cesr` pair as one coherent snapshot. Stage both files, then switch the served directory or object version atomically; a resolver that reads one old and one new file will reject the DID. A short cache lifetime or explicit cache purge is needed so rotation becomes visible promptly. Keep the old publication available until its replacement is ready, and monitor both routes and TLS. This is a description of the server contract; this rehearsal did not deploy or alter infrastructure.

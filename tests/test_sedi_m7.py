"""The demo adapter's v1 stream and the localhost TLS tunnel."""

from __future__ import annotations

import contextlib
import runpy
import socket
import socketserver
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from bakobo.errors import BakoboError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import keri_api

from didwebs import document, ingest
from didwebs.did import parse as parse_did
from scripts import sedi_m7_https, sedi_m7_keri


class _OpenRegery:
    def __init__(self, regery):
        self.regery = regery
        self.closed = False

    def __getattr__(self, name):
        return getattr(self.regery, name)

    def close(self):
        self.closed = True


def _borrow(monkeypatch, hby, regery):
    @contextlib.contextmanager
    def opening(**_):
        yield hby

    borrowed = _OpenRegery(regery)
    monkeypatch.setattr(sedi_m7_keri, "openHby", opening)
    monkeypatch.setattr(sedi_m7_keri, "Regery", lambda **_: borrowed)
    return borrowed


def test_demo_issues_and_exports_a_verified_v1_publication(tmp_path, monkeypatch):
    with keri_api.scratch("m7", tmp_path) as (hby, regery):
        hab = keri_api.make_hab(hby, "guy")
        borrowed = _borrow(monkeypatch, hby, regery)
        said = sedi_m7_keri.issue("guy", "unused", "dids.example.test", "demo")
        stream_path = tmp_path / "stream" / "guy.cesr"
        aid = sedi_m7_keri.export("guy", "unused", stream_path)

        assert aid == hab.pre
        assert said in stream_path.read_bytes().decode()
        assert borrowed.closed
        did = parse_did(f"did:webs:dids.example.test:demo:{aid}")
        with ingest.ingest(stream_path.read_bytes(), did) as verified:
            doc = document.derive_document(verified, did)
        assert doc["id"] == did.raw
        assert keri_api.v1_genus_violation(stream_path.read_bytes()) is None


def test_demo_refuses_an_unverified_witness_and_missing_credential(
    tmp_path, monkeypatch
):
    with keri_api.scratch("m7-empty", tmp_path) as (hby, regery):
        hab = keri_api.make_hab(hby, "guy")
        borrowed = _borrow(monkeypatch, hby, regery)
        monkeypatch.setattr(sedi_m7_keri, "WITNESSES", ((hab.pre, 5642),))
        sedi_m7_keri.seed_locations("guy", "unused")
        assert hab.fetchUrl(eid=hab.pre) == "http://127.0.0.1:5642/"
        monkeypatch.setattr(sedi_m7_keri, "WITNESSES", (("unknown-witness", 5643),))
        with pytest.raises(BakoboError, match="e.state.missing.witness-oobi.r"):
            sedi_m7_keri.seed_locations("guy", "unused")
        with pytest.raises(BakoboError, match="e.state.missing.alias-acdc.r"):
            sedi_m7_keri.export("guy", "unused", tmp_path / "empty.cesr")
        duplicate = SimpleNamespace(
            reger=SimpleNamespace(
                creds=SimpleNamespace(
                    getTopItemIter=lambda: iter([(("one",), None), (("two",), None)])
                )
            ),
            close=lambda: None,
        )
        monkeypatch.setattr(sedi_m7_keri, "Regery", lambda **_: duplicate)
        with pytest.raises(BakoboError, match="e.state.conflict.alias-acdc.f"):
            sedi_m7_keri.export("guy", "unused", tmp_path / "ambiguous.cesr")
        assert borrowed.closed
        assert not (tmp_path / "empty.cesr").exists()
        assert not (tmp_path / "ambiguous.cesr").exists()


def test_demo_cli_commands_and_required_export_path(monkeypatch, capsys, tmp_path):
    seen = []
    monkeypatch.setattr(
        sedi_m7_keri, "seed_locations", lambda *a: seen.append(("seed", a))
    )
    monkeypatch.setattr(
        sedi_m7_keri, "issue", lambda *a: seen.append(("issue", a)) or "said"
    )
    monkeypatch.setattr(
        sedi_m7_keri, "export", lambda *a: seen.append(("export", a)) or "aid"
    )
    for command in ("seed", "issue", "export"):
        args = ["sedi_m7_keri.py", command, "--name", "guy", "--base", "m7"]
        if command == "export":
            args.extend(("--stream", str(tmp_path / "stream.cesr")))
        monkeypatch.setattr(sys, "argv", args)
        sedi_m7_keri.main()
    assert [call[0] for call in seen] == ["seed", "issue", "export"]
    assert "said" in capsys.readouterr().out
    monkeypatch.setattr(
        sys, "argv", ["sedi_m7_keri.py", "export", "--name", "guy", "--base", "m7"]
    )
    with pytest.raises(SystemExit) as error:
        sedi_m7_keri.main()
    assert error.value.code == 2
    assert "e.input.format.demo-invocation.f" in capsys.readouterr().err


def test_demo_module_entrypoint_shows_help(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["sedi_m7_keri.py", "--help"])
    with pytest.raises(SystemExit) as error:
        runpy.run_module("scripts.sedi_m7_keri", run_name="__main__")
    assert error.value.code == 0
    assert "seed" in capsys.readouterr().out


class _Echo(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(1024)
        self.request.sendall(data)


@contextlib.contextmanager
def _server(handler):
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            server.shutdown()
            thread.join()


def test_https_tunnel_forwards_only_the_configured_host():
    with _server(_Echo) as upstream:
        sedi_m7_https.Tunnel.target_host = "dids.example.test"
        sedi_m7_https.Tunnel.target_port = upstream
        with _server(sedi_m7_https.Tunnel) as proxy:
            with socket.create_connection(("127.0.0.1", proxy)) as client:
                client.sendall(b"GET / HTTP/1.1\r\n\r\n")
                response = client.recv(1024)
                assert b"403 Forbidden" in response
                assert b"e.input.format.proxy-target.f" in response
            with socket.create_connection(("127.0.0.1", proxy)) as client:
                client.sendall(b"CONNECT dids.example.test:443 HTTP/1.1\r\n\r\n")
                assert b"200 Connection Established" in client.recv(1024)
                client.sendall(b"ping")
                assert client.recv(1024) == b"ping"
            with socket.create_connection(("127.0.0.1", proxy)) as client:
                client.sendall(b"CONNECT dids.example.test:443 HTTP/1.0\r\n")
            with socket.create_connection(("127.0.0.1", proxy)) as client:
                client.sendall(
                    b"CONNECT dids.example.test:443 HTTP/1.1\r\n"
                    + b"X: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n"
                    * 300
                )
                assert b"e.input.range.proxy-headers.f" in client.recv(1024)


def test_https_main_binds_loopback_and_closes_servers(monkeypatch, tmp_path):
    events = []

    class FakeTLS:
        def __init__(self, protocol):
            events.append(("tls", protocol))

        def load_cert_chain(self, cert, key):
            events.append(("cert", cert, key))

        def wrap_socket(self, sock, server_side):
            assert server_side
            return sock

    class FakeServer:
        def __init__(self, address, handler):
            events.append(("bind", address))
            self.socket = object()

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def serve_forever(self):
            events.append(("serve",))

        def shutdown(self):
            events.append(("shutdown",))

        def server_close(self):
            events.append(("close",))

    class FakeThread:
        def __init__(self, target, daemon):
            assert daemon
            self.target = target

        def start(self):
            self.target()

    monkeypatch.setattr(sedi_m7_https.ssl, "SSLContext", FakeTLS)
    monkeypatch.setattr(sedi_m7_https, "ThreadingHTTPServer", FakeServer)
    monkeypatch.setattr(sedi_m7_https.socketserver, "ThreadingTCPServer", FakeServer)
    monkeypatch.setattr(sedi_m7_https.threading, "Thread", FakeThread)
    monkeypatch.setattr(
        sys,
        "argv",
        ["sedi_m7_https.py", "--root", str(tmp_path), "--cert", "cert", "--key", "key"],
    )
    sedi_m7_https.main()
    assert events.count(("serve",)) == 2
    assert ("bind", ("127.0.0.1", 8443)) in events
    assert ("bind", ("127.0.0.1", 8444)) in events
    assert events[-2:] == [("shutdown",), ("close",)]


def test_https_module_entrypoint_shows_help(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["sedi_m7_https.py", "--help"])
    with pytest.raises(SystemExit) as error:
        runpy.run_module("scripts.sedi_m7_https", run_name="__main__")
    assert error.value.code == 0
    assert "--proxy-port" in capsys.readouterr().out

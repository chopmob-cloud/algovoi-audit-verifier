"""Tests for the algovoi_verify_server HTTP wrapper."""
from __future__ import annotations

import json

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

import algovoi_verify_server
import demo_audit_bundle


@pytest.fixture()
def client() -> TestClient:
    return TestClient(algovoi_verify_server.app)


@pytest.fixture()
def good_bundle() -> dict:
    """A well-formed bundle that verify_bundle accepts."""
    return demo_audit_bundle.build_demo_bundle()


class TestRoot:
    def test_index(self, client: TestClient) -> None:
        r = client.get("/")
        assert r.status_code == 200
        body = r.json()
        assert body["name"] == "algovoi-audit-verifier"
        assert "POST /verify" in body["endpoints"]

    def test_health(self, client: TestClient) -> None:
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}


class TestVerify:
    def test_good_bundle_returns_200(
        self, client: TestClient, good_bundle: dict
    ) -> None:
        r = client.post("/verify", content=json.dumps(good_bundle))
        assert r.status_code == 200
        body = r.json()
        assert body["all_passed"] is True
        assert body["fatal"] == []
        assert isinstance(body["checks"], list)
        assert len(body["checks"]) > 0

    def test_empty_body_returns_400(self, client: TestClient) -> None:
        r = client.post("/verify", content="")
        assert r.status_code == 400
        assert "empty" in r.json()["detail"].lower()

    def test_invalid_json_returns_400(self, client: TestClient) -> None:
        r = client.post("/verify", content="not json")
        assert r.status_code == 400
        assert "valid json" in r.json()["detail"].lower()

    def test_oversized_body_returns_413(self, client: TestClient) -> None:
        # Build a payload over 5 MiB.
        big = "x" * (algovoi_verify_server.MAX_BUNDLE_BYTES + 1)
        r = client.post("/verify", content=big)
        assert r.status_code == 413

    def test_malformed_bundle_returns_422(
        self, client: TestClient, good_bundle: dict
    ) -> None:
        # Strip required field -> verify_bundle adds fatal -> all_passed = False
        malformed = dict(good_bundle)
        del malformed["chain_format_version"]
        r = client.post("/verify", content=json.dumps(malformed))
        assert r.status_code == 422
        body = r.json()
        assert body["all_passed"] is False
        assert any("chain_format_version" in f for f in body["fatal"])

    def test_tampered_bundle_returns_422(
        self, client: TestClient, good_bundle: dict
    ) -> None:
        # Tamper with a row -> per-row content_hash check fails.
        tampered = dict(good_bundle)
        tampered["rows"] = list(tampered["rows"])
        if tampered["rows"]:
            row0 = dict(tampered["rows"][0])
            row0["content_hash"] = "0" * 64
            tampered["rows"][0] = row0
        r = client.post("/verify", content=json.dumps(tampered))
        assert r.status_code == 422
        body = r.json()
        assert body["all_passed"] is False

    def test_signing_key_header_is_consumed(
        self, client: TestClient, good_bundle: dict
    ) -> None:
        # Without the header, the signature check is skipped.
        # With a wrong key, the signature check fails.
        r_no_key = client.post("/verify", content=json.dumps(good_bundle))
        assert r_no_key.status_code == 200
        # If the bundle isn't signed, providing a key shouldn't break it.
        # If it IS signed and the key is wrong, we'd get 422; either way the
        # server should not 500.
        r_wrong_key = client.post(
            "/verify",
            content=json.dumps(good_bundle),
            headers={"X-Audit-Bundle-Key": "definitely-not-the-key"},
        )
        assert r_wrong_key.status_code in (200, 422)

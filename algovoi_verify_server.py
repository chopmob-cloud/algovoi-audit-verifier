"""
HTTP server wrapper around verify_audit_bundle.

Single endpoint:
  POST /verify -- accepts an audit-bundle JSON body, returns a structured
                  verification report.

Bundles up to 5 MiB are accepted; larger bodies are rejected with 413.
The server is stateless: no bundle is persisted, no log is kept beyond
standard access logs. Designed to run behind nginx with strict body-size
limits and rate limiting.

Run locally:
    uvicorn algovoi_verify_server:app --host 0.0.0.0 --port 8000

Or via the CLI shim:
    python -m algovoi_verify_server
"""
from __future__ import annotations

import io
import json
import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

# Re-use the existing verifier without modification.
import verify_audit_bundle as _verifier  # noqa: E402

logger = logging.getLogger("algovoi-verify")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

MAX_BUNDLE_BYTES = 5 * 1024 * 1024  # 5 MiB

app = FastAPI(
    title="AlgoVoi Audit Verifier",
    description=(
        "Standalone reference verifier for AlgoVoi selective-disclosure audit "
        "bundles. The server is stateless and does not retain submitted bundles."
    ),
    version="0.1.0",
)


@app.get("/")
def root() -> dict[str, Any]:
    return {
        "name": "algovoi-audit-verifier",
        "version": "0.1.0",
        "endpoints": {
            "GET /": "this index",
            "GET /health": "liveness probe",
            "POST /verify": "verify an audit bundle (JSON body)",
        },
        "docs": "https://verify.algovoi.co.uk/docs",
        "source": "https://github.com/chopmob-cloud/algovoi-audit-verifier",
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/verify")
async def verify(request: Request) -> JSONResponse:
    """Verify an audit bundle.

    The request body MUST be JSON. The bundle is verified in-memory and the
    result is returned; nothing is persisted. If the bundle is signed and
    you want bundle_signature verified, pass the signing key in the
    `X-Audit-Bundle-Key` header; otherwise the signature step is skipped
    (the structural checks 1 and 2 still run).
    """
    raw = await request.body()
    if len(raw) == 0:
        raise HTTPException(status_code=400, detail="request body is empty")
    if len(raw) > MAX_BUNDLE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"request body exceeds {MAX_BUNDLE_BYTES} bytes",
        )

    try:
        bundle = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"request body is not valid JSON: {exc.msg} at line {exc.lineno} col {exc.colno}",
        )

    signing_key = request.headers.get("x-audit-bundle-key")

    try:
        report = _verifier.verify_bundle(bundle, signing_key=signing_key)
    except Exception as exc:  # pragma: no cover -- defensive
        logger.exception("verifier raised unexpectedly")
        raise HTTPException(status_code=500, detail=f"verifier raised: {exc}")

    # Status code mirrors the CLI exit-code semantics:
    #   200 OK -> all checks passed (or optional checks skipped)
    #   422 Unprocessable Entity -> one or more checks failed (or fatal)
    body = report.to_dict()
    status = 200 if report.all_passed else 422
    return JSONResponse(content=body, status_code=status)


def main() -> int:  # pragma: no cover -- CLI shim
    """Run uvicorn directly via `python -m algovoi_verify_server`."""
    import uvicorn

    uvicorn.run(
        "algovoi_verify_server:app",
        host="0.0.0.0",
        port=8000,
        proxy_headers=True,
        forwarded_allow_ips="*",
        access_log=True,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

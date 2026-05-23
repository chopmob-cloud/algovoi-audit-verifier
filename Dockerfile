# AlgoVoi Audit Verifier -- standalone offline verifier as a hosted service.
# Stateless; no persistence; bounded body size.

FROM python:3.12-slim AS build

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY verify_audit_bundle.py demo_audit_bundle.py algovoi_verify_server.py ./

RUN pip install --no-cache-dir --upgrade pip \
 && pip wheel --no-cache-dir --wheel-dir /wheels ".[server]"

# -----------------------------------------------------------------------------

FROM python:3.12-slim AS runtime

# Run as non-root for defence in depth.
RUN groupadd --system algovoi && useradd --system --gid algovoi --home /home/algovoi --shell /sbin/nologin algovoi
WORKDIR /app

# Install only the runtime deps + the package.
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links /wheels algovoi-audit-verifier[server] \
 && rm -rf /wheels

USER algovoi
EXPOSE 8000

# Run uvicorn with proxy-headers so the nginx X-Forwarded-* are honoured.
ENTRYPOINT ["uvicorn", "algovoi_verify_server:app", \
    "--host", "0.0.0.0", \
    "--port", "8000", \
    "--proxy-headers", \
    "--forwarded-allow-ips", "*", \
    "--access-log"]

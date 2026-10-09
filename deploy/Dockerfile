# Shared image for every federation service process (P4-3, ARCHITECTURE.md
# §7 Path B). Which service a container runs is selected entirely by the
# SERVICE_ROLE environment variable at `docker run`/compose time -- see
# deploy/entrypoint.py. One image, one Dockerfile, five roles: this keeps
# with "keep it easy to install and run" (ARCHITECTURE.md §1) rather than
# maintaining five near-identical images.
#
# Build context is the repository root (see docker-compose.yml's
# `build.context: ..`), so paths below are relative to the repo root.

FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml ./
COPY src/ ./src/
RUN pip install --no-cache-dir -e .

COPY deploy/ ./deploy/
# The synthetic dataset the bootstrap step seeds (P4-5).
COPY demo/ ./demo/
COPY portal/ ./portal/
COPY wire/ ./wire/

ENV PYTHONUNBUFFERED=1
ENV HOST=0.0.0.0
ENV TLS_CERT_DIR=/tls

ENTRYPOINT ["python", "-m", "deploy.entrypoint"]

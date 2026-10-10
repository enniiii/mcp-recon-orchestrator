# syntax=docker/dockerfile:1

# ---- build the ProjectDiscovery Go tools from source (reliable paths) ----
FROM golang:1.23-bookworm AS gotools
ENV CGO_ENABLED=0
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# ---- runtime image: scanners + the recon toolkit ----
FROM python:3.12-slim-bookworm

# nmap + whois from Debian; the Go tools copied from the build stage.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap whois ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=gotools /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=gotools /go/bin/subfinder /usr/local/bin/subfinder

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY tests ./tests

# Install the package plus pytest so integration tests can run in-container.
RUN pip install --no-cache-dir . pytest

# Idle by default; exec in to run scans or `pytest -m integration`.
CMD ["sleep", "infinity"]

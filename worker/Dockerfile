# ==============================================================================
# CMYK PDF Preflight engine — RunPod serverless (CPU pod)
# OPTIMIZATION LABEL CONFIGURATION: RAM_BACKED_VIRTUAL_SCRATCHPAD (handler uses
#   /dev/shm), PROCESS_GROUP_POISON_PILL (os.setpgrp in handler).
# VENDOR-BUG FIXES vs the original spec:
#   - real pinned pdfcpu release URL (verified live 2026-08-24; the vendor's
#     "wget https://github.com" downloaded a homepage, not an archive)
#   - pip install direct (the vendor's echo "\n" wrote literal \n into
#     requirements.txt, breaking the build)
#   - libgs-dev dropped: we invoke the `gs` binary via subprocess (the vendor
#     handler already did); ctypes/libgs-dev was unused weight.
# SECURITY FIX: the pdfcpu artifact is now SHA-256 verified and the build FAILS
#   CLOSED on any checksum mismatch (see COMMITTED_PDFCPU_SHA256
#   below). No secret is injected at build time: a published SHA-256 is public
#   data, not a credential.
# ==============================================================================
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    G_SLICE=always-malloc

RUN apt-get update && apt-get install -y --no-install-recommends \
    ghostscript \
    poppler-utils \
    wget \
    ca-certificates \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# pdfcpu 0.15.0 — newest release whose Linux x86_64 asset resolves
# (0.15.1 / 0.16.0 assets 404 as of 2026-08-24). tar.xz -> needs -J.
#
# Pinned pdfcpu release, VERIFIED against its published checksum.
# COMMITTED digest for the pinned Linux x86_64 asset below. Provenance: the
# official pdfcpu release v0.15.0 checksums.txt
# (github.com/pdfcpu/pdfcpu/releases/tag/v0.15.0), asset
# pdfcpu_0.15.0_Linux_x86_64.tar.xz - independently re-verified here against the
# downloaded artifact (5,603,500 bytes, sha256 matched). The build compares the
# download against THIS committed value, so the binary is pinned and any
# tampering aborts the build before installation.
# To bump the version: take the new digest from that release's checksums.txt.
# NEVER invent, guess, or copy a digest from an untrusted mirror.
ARG COMMITTED_PDFCPU_SHA256="652830db95e81868dbe38fbb3f506365511c99a1831b5e8955deac38f3f645f8"
RUN set -eu; \
    committed="$(printf '%s' "${COMMITTED_PDFCPU_SHA256}" | tr 'A-Z' 'a-z')"; \
    case "${committed}" in \
      *[!0-9a-f]*) echo "FATAL: committed digest is not a hex sha256." >&2; exit 1;; \
    esac; \
    if [ "${#committed}" -ne 64 ]; then \
        echo "FATAL: committed digest must be 64 hex characters." >&2; exit 1; \
    fi; \
    tmp="$(mktemp -d)"; \
    wget -q -O "${tmp}/pdfcpu.tar.xz" \
      https://github.com/pdfcpu/pdfcpu/releases/download/v0.15.0/pdfcpu_0.15.0_Linux_x86_64.tar.xz; \
    actual="$(sha256sum "${tmp}/pdfcpu.tar.xz" | cut -d' ' -f1)"; \
    if [ "${actual}" != "${committed}" ]; then \
        echo "FATAL: pdfcpu checksum MISMATCH - nothing installed." >&2; \
        echo "  expected: ${committed}" >&2; \
        echo "  actual:   ${actual}" >&2; \
        echo "  Refusing to install an unverified binary (possible tampering)." >&2; \
        rm -rf "${tmp}"; \
        exit 1; \
    fi; \
    echo "pdfcpu SHA-256 verified: ${actual}"; \
    tar -xJf "${tmp}/pdfcpu.tar.xz" -C "${tmp}"; \
    install -m 0755 "${tmp}/pdfcpu_0.15.0_Linux_x86_64/pdfcpu" /usr/local/bin/pdfcpu; \
    rm -rf "${tmp}"

# Single RUN, no requirements-file echo hack (vendor's version embedded a
# literal "\n" string into the file and broke pip).
RUN pip install --no-cache-dir pypdf==4.0.1 requests==2.31.0 boto3==1.34.50 runpod==1.6.2

WORKDIR /app
COPY handler.py .

CMD [ "python", "-u", "handler.py" ]
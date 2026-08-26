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
RUN wget -q https://github.com/pdfcpu/pdfcpu/releases/download/v0.15.0/pdfcpu_0.15.0_Linux_x86_64.tar.xz \
    && tar -xJf pdfcpu_0.15.0_Linux_x86_64.tar.xz \
    && mv pdfcpu_0.15.0_Linux_x86_64/pdfcpu /usr/local/bin/pdfcpu \
    && chmod +x /usr/local/bin/pdfcpu \
    && rm -rf pdfcpu_0.15.0_Linux_x86_64*

# Single RUN, no requirements-file echo hack (vendor's version embedded a
# literal "\n" string into the file and broke pip).
RUN pip install --no-cache-dir pypdf==4.0.1 requests==2.31.0 boto3==1.34.50 runpod==1.6.2

WORKDIR /app
COPY handler.py .

CMD [ "python", "-u", "handler.py" ]

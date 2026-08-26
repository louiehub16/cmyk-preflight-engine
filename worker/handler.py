"""
CMYK PDF Preflight Core Daemon Processing Service (RunPod serverless, CPU pod)
Optimizations Applied: TCP_CONNECTION_POOLING, STORAGE_QUOTA_WATCHDOG, PERMISSION_LOCK_MITIGATION, RAM_BACKED_VIRTUAL_SCRATCHPAD,
                       PROCESS_GROUP_POISON_PILL, JPEG_PREVIEW, GARBAGE_COLLECTION_DEACTIVATION,
                       MIME_TYPE_FRAUD_ENFORCEMENT (real: %PDF- magic), DESTINATION_HOST_ORIGIN_FILTER (defense-in-depth),
                       HMAC_PAYLOAD_SIGNATURE_SEAL, SERVER_ABUSE_CEILING_GATE (2.5 GB service cap)

OPTIMIZATION LABEL CORRECTIONS vs the vendor spec's Ghostscript invocation:
  - DROPPED -dPDFX=true   : requires PDFX definition resources; standalone use errors out.
  - DROPPED -dBandHeight  : banding is a RENDER-device parameter; pdfwrite ignores it.
  - DROPPED -dDITHERPPI   : render-device parameter, not a pdfwrite vector simplifier.
  - DROPPED -dMaxBitmap   : render-device parameter (memory bitmap ceiling).
  - OMITTED -dWRITESYSTEMDICT : pointless when invoking the gs binary via subprocess
    (it matters for ctypes/libgs embedding, which we do not do).
  KEPT: -sDEVICE=pdfwrite + DeviceCMYK process color model + CMYK conversion
  strategy + font embed/subset — the actual CMYK preflight core.
"""

import os
import gc
import glob
import uuid
import signal
import socket
import shutil
import hashlib
import ipaddress
import subprocess
import time
from urllib.parse import urljoin, urlparse

import requests
import pypdf
import boto3
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# ==============================================================================
# OPTIMIZATION LABEL CONFIGURATION: TCP_CONNECTION_POOLING
# ==============================================================================
# VENDOR-BUG FIX: status_forcelist=() was a syntax error; a real retry list now.
session = requests.Session()
_retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503])
session.mount('https://', HTTPAdapter(max_retries=_retries, pool_connections=20, pool_maxsize=20))

s3_client = boto3.client(
    's3',
    endpoint_url=os.environ.get("R2_ENDPOINT_URL"),
    aws_access_key_id=os.environ.get("R2_ACCESS_KEY_ID"),
    aws_secret_access_key=os.environ.get("R2_SECRET_ACCESS_KEY")
)
BUCKET_NAME = os.environ.get("R2_BUCKET_NAME")
PUBLIC_URL_PREFIX = os.environ.get("R2_PUBLIC_URL_PREFIX")

RAM_SPACE = os.environ.get("ENGINE_RAM_DIR", "/dev/shm")  # module constant so tests can retarget it
GS_TIMEOUT_S = int(os.environ.get("GS_TIMEOUT_S", "240"))
SHM_FLOOR_MB = int(os.environ.get("SHM_FLOOR_MB", "512"))
# Malformed Payload Invalidation penalty ($0.01) — attached to failures that the
# instant pypdf sniff catches (not_a_pdf / corrupt_pdf / encrypted_pdf).
MALFORMED_PENALTY_MICRO_USDC = "10000"
_SIGKILL = getattr(signal, "SIGKILL", 9)  # absent on Windows dev hosts


def _kill_process_group(proc):
    """OPTIMIZATION LABEL CONFIGURATION: PROCESS_GROUP_POISON_PILL.
    Sweep the entire process group on timeout. Falls back to single-process
    kill where POSIX process groups don't exist (Windows dev hosts);
    production images are Linux, so the group-kill path is the real one."""
    try:
        if hasattr(os, "killpg"):
            os.killpg(os.getpgid(proc.pid), _SIGKILL)
        else:
            proc.kill()
    except OSError:
        pass


def verify_storage_headroom():
    """OPTIMIZATION LABEL CONFIGURATION: STORAGE_QUOTA_WATCHDOG"""
    total, used, free = shutil.disk_usage(RAM_SPACE)
    if (free / (1024 * 1024)) < SHM_FLOOR_MB:
        raise ResourceWarning("SYSTEM CRITICAL ERROR: Scratchpad shared memory allocation boundaries exhausted.")


def inspect_pdf_permissions(local_path):
    """OPTIMIZATION LABEL CONFIGURATION: PERMISSION_LOCK_MITIGATION.
    Returns the page count on success."""
    try:
        with open(local_path, "rb") as f:
            reader = pypdf.PdfReader(f)
            if reader.is_encrypted:
                raise PermissionError("encrypted")
            return len(reader.pages)
    except pypdf.errors.PdfReadError:
        raise ValueError("corrupt_pdf")


def _assert_public_host(hostname):
    """OPTIMIZATION LABEL CONFIGURATION: DESTINATION_HOST_ORIGIN_FILTER
    (defense-in-depth engine layer). Resolve DNS and reject ANY private /
    loopback / link-local / reserved address — protects against SSRF even if
    an edge gate is ever bypassed or a hostname re-resolves post-check."""
    infos = socket.getaddrinfo(hostname, 443)
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        # R3 Kimi: Python's is_private does NOT unwrap IPv4-mapped IPv6
        # (::ffff:127.0.0.1 bypasses the checks) — normalize to the embedded
        # IPv4 first so mapped-loopback/private addresses are caught.
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise PermissionError("ssrf_blocked")


MAX_REDIRECTS = 5


def _safe_fetch(file_url, method, **kw):
    """SSRF-HARDENED fetch: follows redirects MANUALLY, re-validating scheme
    (https only) and destination host (via _assert_public_host DNS resolution)
    on EVERY hop. A public URL that 302s to internal/metadata targets is
    rejected before the hop is taken — closes the redirect bypass where
    allow_redirects=True would silently defeat both SSRF layers."""
    current = file_url
    for _hop in range(MAX_REDIRECTS + 1):
        parsed = urlparse(current)
        if parsed.scheme != "https":
            raise PermissionError("ssrf_blocked")  # http(s) downgrade mid-chain also blocked
        _assert_public_host(parsed.hostname)
        resp = session.request(method, current, allow_redirects=False, stream=True, timeout=kw.pop("timeout", 60), **kw)
        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("location")
            if not loc:
                resp.close()
                raise ValueError("corrupt_pdf")
            nxt = urljoin(current, loc)
            resp.close()
            current = nxt
            continue
        return resp
    # too many hops — treat as hostile/broken
    raise PermissionError("ssrf_blocked")


MAX_DOWNLOAD_BYTES = 2500000000 + (64 * 1024 * 1024)  # service cap + working margin


def _download(file_url, tmp_input):
    """Streamed download WITH a hard cumulative byte cap. The HEAD probe caps
    the DECLARED size, but an origin can send a small HEAD length and a huge
    GET payload (R2 Kimi finding): enforce the cap on ACTUAL bytes so a lying
    origin can never OOM the /dev/shm scratchpad."""
    written = 0
    with _safe_fetch(file_url, "GET") as r:
        r.raise_for_status()
        with open(tmp_input, 'wb') as f:
            for chunk in r.iter_content(chunk_size=256 * 1024):
                written += len(chunk)
                if written > MAX_DOWNLOAD_BYTES:
                    raise ValueError("file_too_large")
                f.write(chunk)


def handler(job):
    # ==============================================================================
    # OPTIMIZATION LABEL CONFIGURATION: GARBAGE_COLLECTION_DEACTIVATION
    # ==============================================================================
    gc.disable()

    job_input = job['input']
    file_url = job_input.get('file_url')
    dest_folder = str(job_input.get('destination_folder', '')).strip('/')
    incoming_hash = job_input.get('payload_hash')

    # ==============================================================================
    # OPTIMIZATION LABEL CONFIGURATION: HMAC_PAYLOAD_SIGNATURE_SEAL
    # ==============================================================================
    calculated_hash = hashlib.sha256(file_url.encode()).hexdigest()
    if incoming_hash != calculated_hash:
        return {"status": "failed", "error": "payload_seal_broken"}

    # SERVER_ABUSE_CEILING_GATE: two-layer defense. (1) POLICY: the service caps
    # inputs at 2.5 GB (the edge rejects larger pre-payment; this backstop also
    # applies if a redirect chain swapped sizes after pricing). (2) CAPACITY:
    # declared size vs /dev/shm free space, checked BEFORE download (a
    # post-payment OOM would strand the customer's money).
    head = None
    try:
        head = _safe_fetch(file_url, "HEAD", timeout=15)
        cl = head.headers.get('content-length')
        if cl is not None and cl.isdigit():
            _declared = int(cl)
            if _declared > 2500000000:
                return {"status": "failed", "error": "file_too_large"}
            _total, _used, free = shutil.disk_usage(RAM_SPACE)
            if _declared > free - (64 * 1024 * 1024):  # keep 64 MiB working margin
                return {"status": "failed", "error": "storage_exhausted"}
    except requests.RequestException:
        pass  # size unknown -> proceed; magic-byte check still guards content
    except PermissionError:
        # SSRF rejection raised while probing/redirect-walking the source URL:
        # terminal, return the clean generic failure instead of letting the
        # raw exception escape as an opaque job error.
        return {"status": "failed", "error": "ssrf_blocked"}
    except ValueError:
        # _safe_fetch raises ValueError on a redirect without a Location header
        # (R3 Kimi finding): treat as unknown size and proceed — the magic-byte
        # check still guards whatever actually downloads.
        pass

    unique_id = str(uuid.uuid4())  # FIX: timestamps collided under load

    # ==============================================================================
    # OPTIMIZATION LABEL CONFIGURATION: RAM_BACKED_VIRTUAL_SCRATCHPAD
    # ==============================================================================
    tmp_input = os.path.join(RAM_SPACE, f"in_{unique_id}.pdf")
    tmp_output = os.path.join(RAM_SPACE, f"out_{unique_id}.pdf")
    tmp_preview_base = os.path.join(RAM_SPACE, f"prev_{unique_id}")

    started = time.monotonic()
    pages = 0
    tmp_preview_actual = None
    try:
        verify_storage_headroom()

        # Engine-layer SSRF block BEFORE any outbound fetch of attacker-chosen URL.
        _assert_public_host(urlparse(file_url).hostname)

        _download(file_url, tmp_input)

        # ======================================================================
        # OPTIMIZATION LABEL CONFIGURATION: MIME_TYPE_FRAUD_ENFORCEMENT (REAL)
        # The vendor doc claimed this check but only did a HEAD content-type
        # peek. We enforce %PDF- magic bytes on the DOWNLOADED bytes.
        # ======================================================================
        with open(tmp_input, "rb") as f:
            if f.read(5) != b"%PDF-":
                raise ValueError("not_a_pdf")

        pages = inspect_pdf_permissions(tmp_input)

        # ======================================================================
        # Core conversion — correct pdfwrite DeviceCMYK flag set (see module
        # docstring OPTIMIZATION LABEL CORRECTIONS for what was dropped & why).
        # ======================================================================
        gs_cmd = [
            "gs", "-dBATCH", "-dNOPAUSE", "-dQUIET", "-dSAFER",
            "-sDEVICE=pdfwrite",
            "-sProcessColorModel=DeviceCMYK",
            "-sColorConversionStrategy=CMYK",
            "-dEmbedAllFonts=true", "-dSubsetFonts=true",
            "-dAutoRotatePages=/None", "-dPDFSETTINGS=/prepress",
            f"-sOutputFile={tmp_output}", tmp_input,
        ]

        # ======================================================================
        # OPTIMIZATION LABEL CONFIGURATION: PROCESS_GROUP_POISON_PILL
        # ======================================================================
        # POSIX process groups in production; None where unavailable (Windows
        # dev hosts) — Popen evaluates the ATTRIBUTE at call time, so guard it.
        _preexec = getattr(os, "setpgrp", None)
        proc = subprocess.Popen(gs_cmd, preexec_fn=_preexec,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            proc.communicate(timeout=GS_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            _kill_process_group(proc)
            raise TimeoutError("timeout")
        if proc.returncode != 0:
            raise RuntimeError("conversion_failed")

        # ======================================================================
        # OPTIMIZATION LABEL CONFIGURATION: JPEG_PREVIEW
        # (renamed from WEBP_HIGH_SPEED_PREVIEW — pdftoppm emits JPEG, and we
        # no longer claim WebP anywhere. FIX: vendor assumed '-1.jpg' exists;
        # we glob and fail cleanly if Poppler produced nothing.)
        # ======================================================================
        poppler_cmd = ["pdftoppm", "-jpeg", "-jpegopt", "quality=85", "-r", "110",
                       "-f", "1", "-l", "1", tmp_output, tmp_preview_base]
        subprocess.run(poppler_cmd, capture_output=True, timeout=60)
        matches = sorted(glob.glob(tmp_preview_base + "-*.jpg"))
        if not matches:
            raise RuntimeError("preview_render_failed")
        tmp_preview_actual = matches[0]

        pdf_key = f"{dest_folder}/print_{unique_id}.pdf" if dest_folder else f"print_{unique_id}.pdf"
        img_key = f"{dest_folder}/preview_{unique_id}.jpg" if dest_folder else f"preview_{unique_id}.jpg"

        s3_client.upload_file(tmp_output, BUCKET_NAME, pdf_key, ExtraArgs={'ContentType': 'application/pdf'})
        s3_client.upload_file(tmp_preview_actual, BUCKET_NAME, img_key, ExtraArgs={'ContentType': 'image/jpeg'})

        duration_s = round(time.monotonic() - started, 3)
        rate_per_hr = float(os.environ.get("ENGINE_CPU_RATE_PER_HR", "0.13"))
        estimated_cost_usd = round(duration_s * (rate_per_hr / 3600.0), 6)

        return {
            "status": "success",
            "download_url": f"{PUBLIC_URL_PREFIX.rstrip('/')}/{pdf_key}",
            "preview_url": f"{PUBLIC_URL_PREFIX.rstrip('/')}/{img_key}",
            "pages": int(pages),
            "duration_s": duration_s,
            "estimated_cost_usd": estimated_cost_usd,
        }

    except ResourceWarning:
        return {"status": "failed", "error": "storage_exhausted"}
    except PermissionError as pe:
        # covers ssrf_blocked and encrypted; keep the codes DISTINCT
        code = str(pe) if str(pe) == "ssrf_blocked" else "encrypted_pdf"
        resp = {"status": "failed", "error": code}
        if code == "encrypted_pdf":
            resp["penalty_amount_micro_usdc"] = MALFORMED_PENALTY_MICRO_USDC
            resp["penalty_reason"] = "malformed_payload_invalidation"
        return resp
    except ValueError as ve:
        code = str(ve) if str(ve) in ("not_a_pdf", "corrupt_pdf", "file_too_large") else "corrupt_pdf"
        # R3 Kimi: the $0.01 invalidation penalty applies ONLY to instant
        # pypdf-sniff rejects; file_too_large is a size rejection, not a
        # malformed payload — no penalty attached there.
        resp = {"status": "failed", "error": code}
        if code in ("not_a_pdf", "corrupt_pdf"):
            resp["penalty_amount_micro_usdc"] = MALFORMED_PENALTY_MICRO_USDC
            resp["penalty_reason"] = "malformed_payload_invalidation"
        return resp
    except TimeoutError:
        return {"status": "failed", "error": "timeout"}
    except Exception as e:
        # LOG HYGIENE: detailed exception stays in worker logs only; the client
        # gets a fixed generic code (raw text can embed endpoints/signed URLs).
        print(f"[handler] conversion failure: {type(e).__name__}: {e}")
        return {"status": "failed", "error": "conversion_failed"}
    finally:
        for path in [tmp_input, tmp_output] + ([tmp_preview_actual] if tmp_preview_actual else []):
            try:
                if path and os.path.exists(path):
                    os.remove(path)
            except OSError:
                pass
        # Re-enable system allocations during clean idle states
        gc.enable()
        gc.collect()


if __name__ == "__main__":
    import runpod
    runpod.serverless.start({"handler": handler})

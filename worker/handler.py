"""
CMYK PDF Preflight Core Daemon Processing Service (RunPod serverless, CPU pod)
Optimizations Applied: TCP_CONNECTION_POOLING, STORAGE_QUOTA_WATCHDOG, PERMISSION_LOCK_MITIGATION, RAM_BACKED_VIRTUAL_SCRATCHPAD,
                       PROCESS_GROUP_POISON_PILL, JPEG_PREVIEW, GARBAGE_COLLECTION_DEACTIVATION,
                       MIME_TYPE_FRAUD_ENFORCEMENT (real: %PDF- magic), DESTINATION_HOST_ORIGIN_FILTER (defense-in-depth),
                       PAYLOAD_INTEGRITY_SEAL, SERVER_ABUSE_CEILING_GATE (2.5 GB service cap)

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

import re
import os
import gc
import glob
import uuid
import signal
import socket
import ssl
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


def _new_session():
    """Per-request Session factory.

    The SSRF-hardened fetch mounts a pinned TLS adapter per request, so it MUST NOT
    mutate the shared module-level `session`: concurrent handler invocations would
    clobber each other's pinning and one request could be routed through another
    request's adapter. Each fetch therefore gets its own Session. Exposed as a
    function so tests can substitute a fake transport.
    """
    s = requests.Session()
    s.mount('https://', HTTPAdapter(max_retries=_retries, pool_connections=20, pool_maxsize=20))
    return s

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
DEST_FOLDER_MAX = 200   # matches the gateway-side limit for destination_folder
_SIGKILL = getattr(signal, "SIGKILL", 9)  # absent on Windows dev hosts


def _log_failure(stage, exc, correlation_id):
    """OPTIMIZATION LABEL CONFIGURATION: LOG_HYGIENE / SECRET-SAFE DIAGNOSTICS.
    Exception text can carry credentials, signed query parameters, bearer
    tokens or upstream URLs, so it is NEVER logged. Emit the exception TYPE
    plus an internal correlation id (RunPod job id / request trace id) and
    nothing else -- the caller still returns a fixed generic error code."""
    if exc is None:
        print(f"[handler] stage={stage} correlation_id={correlation_id}")
    else:
        print(f"[handler] stage={stage} exc_type={type(exc).__name__} "
              f"correlation_id={correlation_id}")


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


class EncryptedPdfError(PermissionError):
    """R109: an ENCRYPTED document - the ONE PermissionError that is the CUSTOMER's
    fault and may carry the $0.01 malformed-payload penalty.

    PermissionError is far too broad a type to classify on: an OS/filesystem
    read fault raises the same type, and the handler below used to map every
    non-'ssrf_blocked' PermissionError to encrypted_pdf, so a scratch-file we
    could not read billed the customer for a malformed document. Only this
    dedicated subclass is billable; every other PermissionError is our fault.
    """


class SsrfBlockedError(PermissionError):
    """R109: a refused fetch target. Subclasses PermissionError so existing
    `except PermissionError` sites keep working, but it is never billable."""


def inspect_pdf_permissions(local_path):
    """OPTIMIZATION LABEL CONFIGURATION: PERMISSION_LOCK_MITIGATION.
    Returns the page count on success."""
    try:
        with open(local_path, "rb") as f:
            reader = pypdf.PdfReader(f)
            if reader.is_encrypted:
                raise EncryptedPdfError("encrypted")
            return len(reader.pages)
    except pypdf.errors.PdfReadError:
        raise ValueError("corrupt_pdf")
    except EncryptedPdfError:
        raise
    # R96: MemoryError is deliberately ABSENT. It is resource exhaustion in the RUNTIME,
    # not a malformed document, so mapping it to corrupt_pdf would bill the customer the
    # $0.01 penalty for OUR failure. It falls through to the generic conversion_failed.
    except (RecursionError, ValueError, TypeError, KeyError, IndexError, AttributeError, EOFError,
            ArithmeticError) as e:
        # R105 (narrowed by R86): these are pypdf PARSER faults (recursion on a
        # malformed xref, a bad token stream, an empty file, ...), so they map to
        # corrupt_pdf and carry the documented $0.01 invalidation. Deliberately NOT a
        # blanket `except Exception`: an operational fault (disk, memory, permissions)
        # is the SERVER's problem and must never be billed to the customer.
        _log_failure("pdf_parse_exception", e, None)
        raise ValueError("corrupt_pdf")


def _assert_public_host(hostname):
    """OPTIMIZATION LABEL CONFIGURATION: DESTINATION_HOST_ORIGIN_FILTER
    (defense-in-depth engine layer). Resolve DNS ONCE and reject ANY private /
    loopback / link-local / reserved address — protects against SSRF even if
    an edge gate is ever bypassed.

    RETURNS the validated address list so the caller can PIN the connection to
    the very IP that was validated. Previously this function validated and
    threw the result away, then handed the HOSTNAME to requests, which ran its
    OWN resolution — a DNS-rebinding TOCTOU window where validation saw a public
    address and the connection reached a private one.
    """
    infos = socket.getaddrinfo(hostname, 443)
    validated = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        # R3 Kimi: Python's is_private does NOT unwrap IPv4-mapped IPv6
        # (::ffff:127.0.0.1 bypasses the checks) — normalize to the embedded
        # IPv4 first so mapped-loopback/private addresses are caught.
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise SsrfBlockedError("ssrf_blocked")
        validated.append(str(ip))
    if not validated:
        raise SsrfBlockedError("ssrf_blocked")
    return validated


class _PinnedTLS(requests.adapters.HTTPAdapter):
    """Connect to a pre-validated IP while verifying TLS for the ORIGINAL HOSTNAME.

    R84: handing requests an IP-bearing URL makes urllib3 send SNI for, and verify the
    certificate against, that IP. Proven live against raw.githubusercontent.com: it fails
    with "IP address mismatch, certificate is not valid for <ip>", so EVERY real
    download would break. A Host header cannot fix it, because TLS completes before any
    HTTP header is sent.

    So the socket is driven directly: the TCP connection targets the pinned IP while
    `server_hostname`/`assert_hostname` carry the hostname that was validated. The
    certificate is verified against the real name, and the connection can only reach
    the address that passed validation - which is the entire point of pinning.
    """

    def __init__(self, pinned_ip, hostname, *args, **kwargs):
        self._pinned_ip = pinned_ip
        self._hostname = hostname
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        from urllib.parse import urlparse
        import urllib3
        from urllib3.util.ssl_ import create_urllib3_context

        parsed = urlparse(request.url)
        port = parsed.port or 443

        ctx = create_urllib3_context()
        ca = _ca_bundle_path()
        if ca:
            ctx.load_verify_locations(cafile=ca)
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        raw_timeout = kwargs.get("timeout") or 60
        connect_timeout = raw_timeout.total if hasattr(raw_timeout, "total") else raw_timeout
        if not isinstance(connect_timeout, (int, float)):
            connect_timeout = 60

        # HTTPSConnection(host=<pinned ip>) dials that address, while
        # server_hostname/assert_hostname bind the TLS handshake to the hostname.
        conn = urllib3.connection.HTTPSConnection(
            host=self._pinned_ip,
            port=port,
            timeout=connect_timeout,
            ssl_context=ctx,
            server_hostname=self._hostname,
            assert_hostname=self._hostname,
            cert_reqs=ssl.CERT_REQUIRED,
        )
        body = request.body
        if hasattr(body, "read"):
            body = body.read()
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        try:
            conn.request(request.method or "GET", path, body=body,
                          headers=dict(request.headers))
            raw = conn.getresponse()
            # requests' cookie jar reads response._original_response.msg, so expose a
            # minimal shim carrying the underlying response under `.msg`.
            if getattr(raw, "_original_response", None) is None:
                class _RespShim:
                    def __init__(self, r):
                        self.msg = r
                raw._original_response = _RespShim(raw)
        except Exception:
            conn.close()
            raise

        resp = requests.Response()
        resp.status_code = raw.status
        resp.headers = requests.structures.CaseInsensitiveDict(dict(raw.headers))
        resp.raw = raw
        resp.url = request.url
        resp.request = request
        resp.reason = getattr(raw, "reason", None)
        resp.encoding = None
        return resp


def _ca_bundle_path():
    """CA bundle used for TLS verification (certifi when available)."""
    try:
        import certifi
        return certifi.where()
    except Exception:
        return None


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
            raise SsrfBlockedError("ssrf_blocked")
        # R75: reject URL credentials. `https://user:pass@host/x` resolves to a PUBLIC
        # host and so passed the DNS check, while the credentials leak upstream and make
        # the effective origin ambiguous. Never dial a URL that carries userinfo.
        if parsed.username or parsed.password:
            raise SsrfBlockedError("ssrf_blocked")  # http(s) downgrade mid-chain also blocked
        # Resolve + validate ONCE, then PIN: connect to the exact IP that was
        # validated while keeping TLS SNI and certificate verification bound to
        # the original hostname. This closes the DNS-rebinding TOCTOU window where
        # a second, independent resolution inside requests could reach a private
        # address that validation never saw.
        validated_ips = _assert_public_host(parsed.hostname)
        pinned_ip = validated_ips[0]
        # R71: carry the AUTHORITY's port and the fragment through. Rebuilding the URL
        # from scheme+host+path silently converted an explicit port (https://h:8443/...)
        # to the default 443, so a legitimately declared service port was dropped and the
        # request went somewhere the caller never named.
        port_suffix = ":" + parsed.port if parsed.port else ""
        target = "https://[%s]%s%s" % (pinned_ip, port_suffix, parsed.path or "/") \
            if ":" in pinned_ip else "https://%s%s%s" % (pinned_ip, port_suffix, parsed.path or "/")
        if parsed.query:
            target += "?" + parsed.query
        if parsed.fragment:
            target += "#" + parsed.fragment
        pinned_headers = dict(kw.pop("headers", None) or {})
        # SNI/cert are verified against the hostname; the Host header carries the
        # original authority (hostname[:port]) so the origin sees the named port.
        pinned_headers["Host"] = parsed.netloc
        # Pin via a per-host TLS adapter mounted on the session: urllib3 then
        # connects to the IP we validated (it is the URL host) while the adapter's
        # SSLContext keeps check_hostname + SNI bound to the ORIGINAL hostname, so a
        # mismatched certificate still fails.
        # PER-REQUEST Session. The module-level `session` is shared by concurrent
        # handler invocations, so mounting an adapter on it let one job's pinning be
        # clobbered by another's mid-flight. A fresh Session per fetch keeps the
        # adapter selection strictly request-scoped; connection reuse across jobs is
        # deliberately traded for isolation here.
        own = _new_session()
        own.mount("https://", _PinnedTLS(str(pinned_ip), parsed.hostname))
        try:
            resp = own.request(
                method, target, allow_redirects=False, stream=True,
                timeout=kw.pop("timeout", 60),
                headers=pinned_headers, verify=True,
                **kw)
        except (requests.exceptions.SSLError, requests.exceptions.ConnectionError):
            try:
                own.close()
            except Exception:
                pass
            # Never fall back to an unpinned connection on a TLS/connection failure.
            raise SsrfBlockedError("ssrf_blocked")
        # R70: the Session must stay OPEN - it owns the connection the STREAMED body is
        # read from. Closing it in a finally block here shut the pool before _download
        # could consume the response, which can fail or truncate a legitimate download.
        #
        # R188: but response.close() does NOT close the Session, so on the success path
        # (and on the HEAD path) the adapter, connection pool, sockets and TLS state
        # leaked for the life of a REUSED RunPod process until jobs failed under load.
        # Bind the Session's lifetime to the response the caller actually closes: record
        # the owner on the response and close it there. The session is only closed once,
        # and never before the streamed body has been read.
        # R188: give the response ownership of the Session so the caller's close() (or
        # its `with` block) also releases the pool. Wrapped so a close failure can never
        # mask the real error.
        try:
            resp._own_session = own
            resp.close = (lambda _orig=resp.close, _sess=own: (lambda: (_orig(), _sess.close())))()
        except Exception:
            pass

        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("location")
            if not loc:
                resp.close()
                try:
                    own.close()
                except Exception:
                    pass
                # R108: a redirect we cannot FOLLOW is an ORIGIN fault, not a bad PDF.
                # This raised ValueError("corrupt_pdf"), which the billing handler maps to
                # the $0.01 malformed-payload penalty - so a server replying 302 with no
                # Location billed the customer for a document we never even inspected.
                # That is exactly the "our own fault, never the customer's" class the R97
                # allowlist exists to prevent. Fail closed with a neutral, un-billable code.
                _log_failure("redirect_missing_location", None, None)  # no correlation id in this scope
                raise SsrfBlockedError("ssrf_blocked")
            nxt = urljoin(current, loc)
            resp.close()
            try:
                own.close()
            except Exception:
                pass
            current = nxt
            continue
        return resp
    # too many hops — treat as hostile/broken
    raise SsrfBlockedError("ssrf_blocked")


# SERVER_ABUSE_CEILING_GATE (input side). The INPUT allowance is EXACTLY the
# documented 2.5 GB service cap. Working/scratch space is accounted for
# SEPARATELY (WORKING_MARGIN_BYTES below) so the margin can never silently
# inflate the input allowance -- an origin that lies on HEAD may deliver at
# most MAX_INPUT_BYTES of actual bytes, no more.
MAX_INPUT_BYTES = 2500000000
WORKING_MARGIN_BYTES = 64 * 1024 * 1024  # scratch/headroom reserve (NOT input)
# R183: a job needs MORE than the downloaded input on the scratchpad. Ghostscript writes a
# CMYK OUTPUT of comparable size to the input, plus a page-1 JPEG preview, plus working
# files - all while the input is still present. Reserving only WORKING_MARGIN_BYTES meant a
# job admitted near the cap could exhaust /dev/shm AFTER the customer had paid. Reserve
# the input AND its output artifacts.
OUTPUT_ARTIFACT_FACTOR = 2   # input + Ghostscript output + preview, bounded overhead
# Effective hard ceiling on ACTUAL streamed input bytes, enforced mid-stream.
MAX_DOWNLOAD_BYTES = MAX_INPUT_BYTES


# R199: an injectable Durable-Object handle. The engine runs on RunPod with no Cloudflare
# binding, so this is None in production and the read-only capacity check is used; the
# offline suite injects a stub to exercise the atomic path.
SCRATCH_STORE = None
# R221: scratch bytes currently reserved by other jobs (from the DO's inUse).
SCRATCH_IN_USE = 0


def _scratch_call(env, path, payload):
    """R199: reserve/release scratch space through the replay DO (one partition).

    The engine has no Cloudflare binding, so this is only reachable when a DO stub is
    injected (as the test suite does); otherwise it returns None and the caller falls
    back to the read-only check.
    """
    store = env.get("CONSUMED_TX_STORE") if isinstance(env, dict) else None
    if not store:
        return None                      # no DO available: read-only fallback
    try:
        import json as _json
        import urllib.request as _rq
        stub = store.get(store.idFromName("singleton"))
        req = _rq.Request("https://internal/" + path, method="POST",
                          headers={"Content-Type": "application/json"},
                          data=_json.dumps(payload).encode())
        with stub.urlopen(req, timeout=10) as resp:
            return _json.loads(resp.read().decode())
    except Exception:
        return None


def reserve_scratch(env, key, need, free):
    """R199: ATOMIC admission - True when the space is reserved.

    A plain free-space READ is not a reservation: two concurrent paid jobs each see
    the same headroom, each pass the input x2 check, and together exhaust /dev/shm
    AFTER the customer has paid. With the DO present the reservation is serialised under
    its single storage partition; without one, fall back to the read-only comparison
    so a standalone container behaves as before.
    """
    global SCRATCH_IN_USE
    r = _scratch_call(env, "reserve-scratch", {"key": key, "need": need, "free": free})
    if r is None:
        # No DO: keep the previous read-only behaviour (no concurrency tracking).
        return need <= free
    SCRATCH_IN_USE = int(r.get("inUse") or 0)
    return bool(r.get("ok"))


def release_scratch(env, key):
    _scratch_call(env, "release-scratch", {"key": key})


def _stream_byte_budget(free_bytes, reserved_bytes=0):
    """The REMAINING byte budget for a streamed input.

    R221: admission reserves `declared*2 + margin` per job against `free - inUse`,
    but this budget only subtracted the flat margin, so N CONCURRENTLY admitted jobs
    each downloaded against the SAME un-reserved headroom and together could still
    fill /dev/shm. Subtract what other jobs already hold, matching admission.
    """
    capacity = free_bytes - int(reserved_bytes or 0) - WORKING_MARGIN_BYTES
    if capacity < 0:
        capacity = 0
    return min(MAX_DOWNLOAD_BYTES, capacity)


def _download(file_url, tmp_input, max_bytes=MAX_DOWNLOAD_BYTES,
              expected_bytes=None):
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
                # The PAID size is the tighter bound: abort the moment the body
                # exceeds what the customer was charged for, before the generic
                # cap or the disk can be overrun.
                if expected_bytes is not None and written > expected_bytes:
                    raise ValueError("file_size_mismatch")
                if written > max_bytes:
                    raise ValueError("file_too_large")
                f.write(chunk)
        # R86: the delivered body must EQUAL the paid size. An upper bound alone let an
        # origin advertise a large HEAD and then deliver a much smaller valid PDF and
        # still succeed - the customer paid the larger tier for a fraction of the work.
        if expected_bytes is not None and written != expected_bytes:
            raise ValueError("file_size_mismatch")


def handler(job):
    # ==============================================================================
    # OPTIMIZATION LABEL CONFIGURATION: GARBAGE_COLLECTION_DEACTIVATION
    # ==============================================================================

    job_input = job['input']
    file_url = job_input.get('file_url')
    # R108: assign the correlation id FIRST. The destination_folder validation below
    # logs it, and reading it before assignment raised NameError (an uncaught error
    # escaping the handler) instead of the intended clean rejection.
    correlation_id = str(job.get('id') or uuid.uuid4())
    # R104: validate destination_folder IN THE ENGINE too. The gateway sanitizes it,
    # but the engine must not trust that: it only stripped slashes, so a job invoked
    # directly could write to an arbitrary S3 prefix or use '../' traversal. Apply the
    # same grammar as the gateway and fail closed.
    # OMITTED means "root prefix"; SUPPLIED means it must be a valid string. An explicit
    # null is a malformed value, not an absent one, so it fails closed (R77) - while
    # `str(None)` would otherwise become the literal S3 key "None/".
    _dest_present = 'destination_folder' in job_input
    _dest_raw = job_input.get('destination_folder')
    if not _dest_present or _dest_raw == '':
        dest_folder = ''
    elif isinstance(_dest_raw, str):
        dest_folder = _dest_raw.strip('/')
    else:
        _log_failure("destination_folder_invalid_type", None, correlation_id)
        return {"status": "failed", "error": "invalid_destination_folder"}
    if len(dest_folder) > DEST_FOLDER_MAX:
        _log_failure("destination_folder_too_long", None, correlation_id)
        return {"status": "failed", "error": "invalid_destination_folder"}
    if dest_folder:
        allowed = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-/')
        if any(ch not in allowed for ch in dest_folder):
            _log_failure("destination_folder_invalid_chars", None, correlation_id)
            return {"status": "failed", "error": "invalid_destination_folder"}
        for seg in dest_folder.split('/'):
            if seg == '' or seg == '.' or seg == '..':
                _log_failure("destination_folder_traversal", None, correlation_id)
                return {"status": "failed", "error": "invalid_destination_folder"}
    incoming_hash = job_input.get('payload_hash')

    # Internal correlation id for logs ONLY (never returned to the client):
    # the RunPod job id when present, else a locally generated trace id.
    correlation_id = str(job.get('id') or uuid.uuid4())
    # R199: scratch-space reservation state, released in the cleanup finally.
    scratch_reserved = False
    scratch_key = str(uuid.uuid4())

    # PAYMENT-PRICED DECLARED SIZE (R26): the gateway priced this job from the
    # origin's HEAD content-length and sealed the URL. Carrying that number here
    # lets the engine enforce the SAME bound while streaming - an origin that
    # advertises a small HEAD and then streams a huge body is refused instead of
    # filling /dev/shm. A missing/malformed value is UNVERIFIABLE, so we fail
    # closed before requesting a single byte.
    expected_bytes = job_input.get('expected_bytes')
    if isinstance(expected_bytes, bool) or not isinstance(expected_bytes, int):
        _log_failure("expected_bytes_missing_or_invalid", None, correlation_id)
        return {"status": "failed", "error": "file_size_unverifiable"}
    if expected_bytes <= 0:
        # A zero/negative declared size can never be a payable PDF. Report it in the
        # SIZE-UNVERIFIABLE class (matching a missing value) rather than
        # file_too_large, so the gateway and engine agree on one size contract.
        return {"status": "failed", "error": "file_size_unverifiable"}
    if expected_bytes > MAX_INPUT_BYTES:
        return {"status": "failed", "error": "file_too_large"}

    # ==============================================================================
    # OPTIMIZATION LABEL CONFIGURATION: PAYLOAD_INTEGRITY_SEAL
    # ==============================================================================
    # R98: this is an UNKEYED SHA-256 binding of the exact file_url the gateway priced,
    # not an HMAC. The old label claimed keyed authentication, which overstates it: the
    # seal stops a job body from being swapped to a different target between pricing and
    # execution. It is not a client-facing secret - the value travels in the job input.
    # R94: validate file_url BEFORE any use. It was hashed at line 468 and parsed for
    # DNS at 550 with no shape check, so a direct malformed job (null / number / empty)
    # raised an uncaught AttributeError instead of a clean generic rejection.
    if not isinstance(file_url, str) or not file_url.strip():
        _log_failure("file_url_invalid", None, correlation_id)
        return {"status": "failed", "error": "invalid_file_url"}
    file_url = file_url.strip()
    try:
        _parsed_fu = urlparse(file_url)
    except ValueError:
        _log_failure("file_url_unparsable", None, correlation_id)
        return {"status": "failed", "error": "invalid_file_url"}
    if _parsed_fu.scheme != "https" or not _parsed_fu.hostname:
        _log_failure("file_url_not_https", None, correlation_id)
        return {"status": "failed", "error": "invalid_file_url"}
    calculated_hash = hashlib.sha256(file_url.encode()).hexdigest()
    if incoming_hash != calculated_hash:
        return {"status": "failed", "error": "payload_seal_broken"}

    # SERVER_ABUSE_CEILING_GATE: two layers, and BOTH fail closed.
    # (1) VERIFIED SIZE: the HEAD probe must positively establish a usable
    # Content-Length on a 2xx status. A probe failure, an error status, or a
    # missing/unparseable Content-Length is NOT tolerated -- we never guess a
    # size and never proceed to GET with an unknown input size.
    # (2) POLICY + CAPACITY: the service caps inputs at 2500000000 bytes (the
    # edge rejects larger pre-payment; this backstop also applies if a
    # redirect chain swapped sizes after pricing), and the VERIFIED size must
    # fit /dev/shm free space minus the SEPARATE working margin before a single
    # download byte is requested (a post-payment OOM would strand the
    # customer's money).
    try:
        head = _safe_fetch(file_url, "HEAD", timeout=15)
    except PermissionError:
        # SSRF rejection raised while probing/redirect-walking the source URL:
        # terminal, return the clean generic failure instead of letting the
        # raw exception escape as an opaque job error.
        return {"status": "failed", "error": "ssrf_blocked"}
    except Exception as probe_exc:
        # Engine HEAD failure (connection reset, timeout, TLS error, a
        # redirect without a Location header, ...) -- size unknown, and an
        # unknown size is NOT a licence to download. Log the exception TYPE
        # and correlation id only; the raw text can embed credentials, signed
        # query parameters or upstream URLs.
        _log_failure("head_probe_failed", probe_exc, correlation_id)
        return {"status": "failed", "error": "file_size_unverifiable"}

    try:
        if not (200 <= head.status_code < 300):
            _log_failure("head_probe_bad_status", None, correlation_id)
            return {"status": "failed", "error": "file_size_unverifiable"}

        # R172: close the HEAD response as soon as we have what we need. _safe_fetch
        # returns the live response but the per-request Session that owns its adapter,
        # pool, sockets and TLS state stays open until the response is closed, and the
        # GET path already relies on `with`. Leaving the HEAD response unclosed leaks
        # those resources in a REUSED RunPod process until jobs fail under load.
        try:
            head.close()
        except Exception:
            pass
        cl = head.headers.get('content-length')
        # R180: require a CANONICAL non-negative integer string, then convert inside a
        # try. str.isdigit() alone accepts unicode digits and, more importantly, int() on a
        # pathologically long digit string can raise ValueError under CPython's integer
        # conversion limit - which escaped this handler as an opaque job error instead of
        # the fail-closed file_size_unverifiable response the contract promises.
        cl_s = str(cl).strip() if cl is not None else ""
        if not re.fullmatch(r"(?:0|[1-9][0-9]*)", cl_s):
            _log_failure("head_probe_no_content_length", None, correlation_id)
            return {"status": "failed", "error": "file_size_unverifiable"}
        try:
            declared_size = int(cl_s)
        except (ValueError, MemoryError, OverflowError):
            _log_failure("head_probe_content_length_unconvertible", None, correlation_id)
            return {"status": "failed", "error": "file_size_unverifiable"}
        if declared_size > MAX_INPUT_BYTES:
            return {"status": "failed", "error": "file_too_large"}
        # The HEAD size must MATCH the paid size. A smaller HEAD is not trusted
        # (it would let the origin under-deliver and hide a size swap); a larger
        # one means the target changed after pricing.
        if declared_size != expected_bytes:
            _log_failure("declared_size_mismatch", None, correlation_id)
            return {"status": "failed", "error": "file_size_unverifiable"}

        # CAPACITY RESERVATION against the VERIFIED size, before GET. The
        # working margin is subtracted from free space, never from the input
        # allowance, so the 2500000000-byte cap stays intact.
        _total, _used, free = shutil.disk_usage(RAM_SPACE)
        # R183: reserve the input AND the output artifacts, not a flat margin.
        required = declared_size * OUTPUT_ARTIFACT_FACTOR + WORKING_MARGIN_BYTES
        if not reserve_scratch(SCRATCH_STORE, scratch_key, required, free):
            return {"status": "failed", "error": "storage_exhausted"}
        scratch_reserved = True
        scratch_in_use = SCRATCH_IN_USE
        # Budget enforced on ACTUAL streamed bytes for the remainder of the
        # transfer, so an origin that under-reported on HEAD cannot overrun.
        # R221: bound the stream by the capacity remaining AFTER every other
        # job's reservation, so concurrent jobs cannot collectively overrun.
        byte_budget = _stream_byte_budget(free, scratch_in_use)
    finally:
        try:
            head.close()
        except Exception:
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
    tmp_preview_extras = []
    try:
        # R207: disable GC ONLY now, INSIDE the try whose finally re-enables it. It
        # previously sat ~100 lines earlier, so the 9 preflight early returns in between
        # (ssrf_blocked, file_size_unverifiable, file_too_large, storage_exhausted) returned
        # while GC was still disabled - permanently, in a REUSED RunPod process. Earlier
        # reviews of this claim were refuted against the wrong `finally` block; the real
        # gc.enable()/collect() lives in the conversion cleanup finally, not the HEAD-probe one.
        gc.disable()
        verify_storage_headroom()

        # Engine-layer SSRF block BEFORE any outbound fetch of attacker-chosen URL.
        _assert_public_host(urlparse(file_url).hostname)

        _download(file_url, tmp_input, byte_budget, expected_bytes=expected_bytes)

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
        # R107: check pdftoppm's OUTCOME. Ignoring the return code let a failed
        # renderer that happened to leave a file be treated as a good preview, and a
        # timeout fell through to the generic handler and reported conversion_failed.
        # Both are preview-specific and must say so.
        # R91: the preview renderer gets the SAME process-group poison pill as
        # Ghostscript. subprocess.run()'s timeout kills only the direct child, so a
        # renderer descendant could survive holding /dev/shm scratch.
        try:
            proc = subprocess.Popen(poppler_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    start_new_session=True)
        except OSError:
            _log_failure("preview_render_spawn_failed", None, correlation_id)
            raise RuntimeError("preview_render_failed")
        try:
            out_b, err_b = proc.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            _kill_process_group(proc)
            try:
                proc.communicate(timeout=5)   # reap
            except Exception:
                pass
            _log_failure("preview_render_timeout", None, correlation_id)
            raise RuntimeError("preview_render_failed")
        if proc.returncode != 0:
            _log_failure("preview_render_exit_nonzero", None, correlation_id)
            raise RuntimeError("preview_render_failed")
        matches = sorted(glob.glob(tmp_preview_base + "-*.jpg"))
        if not matches:
            raise RuntimeError("preview_render_failed")
        # R63: keep EVERY matched preview. The command asks for page 1 only, but a
        # Poppler build that emits more than one file would previously leave the extras
        # behind: only matches[0] was uploaded and only it was removed, so each such
        # job leaked the remainder into /dev/shm until the container filled.
        tmp_preview_actual = matches[0]
        tmp_preview_extras = [m for m in matches[1:] if m != tmp_preview_actual]

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
    except RuntimeError as re_:
        # R107: a preview-specific fault must keep its own code instead of collapsing
        # into the generic conversion_failed, so the caller can distinguish a failed
        # RENDER from a failed conversion. Never attaches the malformed-payload penalty:
        # the PDF parsed fine, the previewer did not.
        code = str(re_) if str(re_) in ("preview_render_failed", "preview_render_timeout") else "conversion_failed"
        return {"status": "failed", "error": code}
    except PermissionError as pe:
        # R109: classify on the EXCEPTION TYPE, not on the message string. This used
        # to map every non-'ssrf_blocked' PermissionError to encrypted_pdf, so a plain
        # OS read fault - OUR fault - was reported as an encrypted document and charged
        # the $0.01 malformed-payload penalty. Only the dedicated EncryptedPdfError
        # subclass (an actual encrypted document) is the customer's fault; everything
        # else fails closed as an un-billable operational error.
        if isinstance(pe, SsrfBlockedError):
            return {"status": "failed", "error": "ssrf_blocked"}
        if isinstance(pe, EncryptedPdfError):
            return {"status": "failed", "error": "encrypted_pdf",
                    "penalty_amount_micro_usdc": MALFORMED_PENALTY_MICRO_USDC,
                    "penalty_reason": "malformed_payload_invalidation"}
        _log_failure("operational_permission_fault", type(pe).__name__, correlation_id)
        return {"status": "failed", "error": "conversion_failed"}
    except ValueError as ve:
        raw = str(ve)
        # R68: a SIZE failure is not a malformed payload. `file_size_mismatch` used to
        # fall through to the "corrupt_pdf" default and therefore attached the $0.01
        # invalidation penalty, so an origin that under-reported its HEAD size and then
        # streamed a different body charged the customer for the server's own lie.
        # Map size faults to their own codes and never attach a penalty to them.
        if raw == "file_size_mismatch":
            return {"status": "failed", "error": "file_size_unverifiable"}
        # R97: an UNRECOGNISED ValueError is an internal fault, not a bad PDF. It
        # previously defaulted to corrupt_pdf and so attached the $0.01 penalty to
        # our own bug. Only the codes we raise deliberately may be billed.
        code = raw if raw in ("not_a_pdf", "corrupt_pdf", "file_too_large") else "conversion_failed"
        # R3 Kimi + R93: the $0.01 invalidation penalty is scoped to the INSTANT PYPDF
        # SNIFF rejects (corrupt_pdf / encrypted). `not_a_pdf` comes from the %PDF- magic
        # byte check, which is MIME fraud rather than a malformed document, and
        # file_too_large is a size rejection - neither is a malformed payload, so
        # neither may carry the penalty.
        resp = {"status": "failed", "error": code}
        if code == "corrupt_pdf":
            resp["penalty_amount_micro_usdc"] = MALFORMED_PENALTY_MICRO_USDC
            resp["penalty_reason"] = "malformed_payload_invalidation"
        return resp
    except TimeoutError:
        return {"status": "failed", "error": "timeout"}
    except Exception as e:
        # LOG HYGIENE: exception TYPE + internal correlation id only. The raw
        # message can embed credentials, signed query parameters or upstream
        # URLs, so it is never logged; the client gets a fixed generic code.
        _log_failure("conversion_failed", e, correlation_id)
        return {"status": "failed", "error": "conversion_failed"}
    finally:
        # R199: release the scratch reservation on EVERY exit path (success, failure or
        # exception) so a rejected job cannot hold its reservation forever.
        if scratch_reserved:
            try:
                release_scratch(SCRATCH_STORE, scratch_key)
            except Exception:
                pass
        # R63: remove EVERY globbed preview artifact, not just the uploaded one.
        # R106: sweep the preview GLOB, not only the files we happened to track. A
        # pdftoppm timeout (or a non-zero exit) raised BEFORE the glob ran, so any
        # partial preview it had already written stayed outside tmp_preview_extras and
        # leaked from /dev/shm on every such job.
        leaked_previews = [p for p in glob.glob(tmp_preview_base + "-*.jpg")]
        preview_paths = [p for p in (list(leaked_previews) + list(tmp_preview_extras or []) + ([tmp_preview_actual] if tmp_preview_actual else [])) if p]
        for path in [tmp_input, tmp_output] + preview_paths:
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

"""
fetcher.py — Layer 1: Raw HTTP Fetcher
Handles synchronous HTTP requests with redirect tracking, TLS inspection,
timeout/retry logic, and thread-safe rate limiting.

NOTE: Migrated from `requests` to `httpx` for HTTP/2 support and to make
future async migration easier if needed. Cookie parsing and TLS inspection
logic are unchanged since they didn't depend on `requests` internals.
"""

import ssl
import socket
import time
import threading
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

import httpx

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import FETCH_TIMEOUT, MAX_REDIRECTS, USER_AGENT, MAX_BODY_SIZE, DEFAULT_RPS_LIMIT

logger = logging.getLogger(__name__)


class RateLimiter:
    """Thread-safe token-bucket rate limiter for controlling requests per second."""

    def __init__(self, rps: float = 10):
        self.rps = max(0.1, rps) if rps and rps > 0 else 0
        self._interval = 1.0 / self.rps if self.rps else 0
        self._last_request = 0.0
        self._lock = threading.Lock()

    def acquire(self):
        """Block until a request slot is available."""
        if not self._interval:
            return  # unlimited
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request
            if elapsed < self._interval:
                time.sleep(self._interval - elapsed)
            self._last_request = time.monotonic()


@dataclass
class TLSInfo:
    """TLS/SSL certificate information."""
    protocol: str = ""
    cipher: str = ""
    cert_subject: dict = field(default_factory=dict)
    cert_issuer: dict = field(default_factory=dict)
    cert_expiry: str = ""
    cert_not_before: str = ""
    serial_number: str = ""
    has_valid_cert: bool = False
    error: str = ""


@dataclass
class FetchResult:
    """Complete result of fetching a URL."""
    url: str
    final_url: str = ""
    status_code: int = 0
    headers: dict = field(default_factory=dict)
    body: str = ""
    redirect_chain: list = field(default_factory=list)
    tls_info: Optional[TLSInfo] = None
    response_time_ms: float = 0.0
    cookies: dict = field(default_factory=dict)
    error: Optional[str] = None
    content_type: str = ""
    server: str = ""


class Fetcher:
    """
    Synchronous HTTP fetcher with redirect tracking, TLS inspection,
    and thread-safe rate limiting. Designed to be called concurrently
    from multiple worker threads (see ThreadPoolExecutor usage in
    orchestrator.py and active_checks.py).
    """

    def __init__(self, concurrency=10, timeout=FETCH_TIMEOUT,
                 max_redirects=MAX_REDIRECTS, user_agent=USER_AGENT,
                 extra_cookies=None, extra_headers=None, rate_limit=0):
        self.concurrency = concurrency
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.user_agent = user_agent
        self.extra_cookies = extra_cookies or {}
        self.extra_headers = extra_headers or {}
        self.rate_limiter = RateLimiter(rate_limit) if rate_limit else None
        self._local = threading.local()

    def _get_session(self):
        if not hasattr(self._local, "session"):
            headers = {"User-Agent": self.user_agent}
            headers.update(self.extra_headers)
            client = httpx.Client(
                headers=headers,
                cookies=self.extra_cookies if self.extra_cookies else None,
                verify=False,
                max_redirects=self.max_redirects,
            )
            self._local.session = client
        return self._local.session

    def fetch(self, url: str, method: str = "GET",
              follow_redirects: bool = True, timeout: float = None,
              data: dict = None) -> FetchResult:
        if self.rate_limiter:
            self.rate_limiter.acquire()
        return self._do_fetch(url, method, follow_redirects, timeout=timeout, data=data)

    def fetch_post(self, url: str, data: dict,
                   timeout: float = None) -> FetchResult:
        return self.fetch(url, method="POST", data=data, timeout=timeout)

    def _do_fetch(self, url: str, method: str,
                  follow_redirects: bool, timeout: float = None,
                  data: dict = None) -> FetchResult:
        result = FetchResult(url=url)
        start_time = time.monotonic()
        effective_timeout = timeout if timeout is not None else self.timeout
        session = self._get_session()

        try:
            req_kwargs = {
                "timeout": effective_timeout,
                "follow_redirects": follow_redirects,
            }
            if data and method.upper() == "POST":
                req_kwargs["data"] = data

            resp = session.request(method, url, **req_kwargs)
            elapsed = (time.monotonic() - start_time) * 1000

            headers = {k.lower(): v for k, v in resp.headers.items()}

            content_type = headers.get("content-type", "")
            body = ""
            if ("text" in content_type or "json" in content_type or
                    "xml" in content_type or "html" in content_type or not content_type):
                raw = resp.content
                if len(raw) <= MAX_BODY_SIZE:
                    body = raw.decode("utf-8", errors="replace")
                else:
                    body = raw[:MAX_BODY_SIZE].decode("utf-8", errors="replace")

            cookies = {}
            jar = resp.cookies.jar
            for c in jar:
                cookies[c.name] = {
                    "value": c.value,
                    "domain": c.domain or "",
                    "path": c.path or "",
                    "secure": bool(c.secure),
                    "httponly": bool(getattr(c, "_rest", {}).get("HttpOnly", False)),
                    "samesite": getattr(c, "_rest", {}).get("SameSite", ""),
                }

            redirect_chain = []
            if follow_redirects and resp.history:
                for r in resp.history:
                    redirect_chain.append({
                        "url": str(r.url),
                        "status": r.status_code,
                        "location": r.headers.get("location", "")
                    })

            result.final_url = str(resp.url)
            result.status_code = resp.status_code
            result.headers = headers
            result.body = body
            result.redirect_chain = redirect_chain
            result.response_time_ms = round(elapsed, 2)
            result.cookies = cookies
            result.content_type = content_type
            result.server = headers.get("server", "")

            if url.startswith("https://"):
                result.tls_info = self._get_tls_info(url)

        except httpx.TimeoutException:
            result.error = f"Timeout after {effective_timeout}s"
            result.final_url = url
        except httpx.HTTPError as e:
            result.error = f"HTTP error: {str(e)}"
            result.final_url = url
        except Exception as e:
            result.error = f"Fetch error: {str(e)}"
            result.final_url = url

        return result

    def _get_tls_info(self, url: str) -> TLSInfo:
        tls = TLSInfo()
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443

        if not host:
            tls.error = "No hostname to inspect"
            return tls

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    tls.protocol = ssock.version() or ""
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        tls.cipher = cipher_info[0]

                    cert = ssock.getpeercert()
                    if cert:
                        tls.has_valid_cert = True
                        tls.cert_subject = dict(
                            x[0] for x in cert.get("subject", ())
                        ) if cert.get("subject") else {}
                        tls.cert_issuer = dict(
                            x[0] for x in cert.get("issuer", ())
                        ) if cert.get("issuer") else {}
                        tls.cert_expiry = cert.get("notAfter", "")
                        tls.cert_not_before = cert.get("notBefore", "")
                        tls.serial_number = cert.get("serialNumber", "")
                    else:
                        tls.has_valid_cert = False

        except ssl.SSLCertVerificationError as e:
            tls.error = f"Certificate verification failed: {e}"
            tls.has_valid_cert = False
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
            tls.error = f"TLS connection error: {e}"
        except Exception as e:
            tls.error = f"TLS inspection error: {e}"

        return tls

    def fetch_multiple(self, urls: list, method: str = "GET") -> list:
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = [executor.submit(self.fetch, url, method) for url in urls]
            return [f.result() for f in futures]


def fetch_url(url: str, **kwargs) -> FetchResult:
    fetcher = Fetcher(**kwargs)
    return fetcher.fetch(url)

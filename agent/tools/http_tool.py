"""Tool handler for http_fetch tasks.

Makes a safe, bounded HTTP GET request using Python's built-in urllib.
No third-party HTTP library is needed and we deliberately avoid one --
fewer dependencies means a smaller attack surface.
"""

import urllib.request
import urllib.error
from urllib.parse import urlparse


# Hard limits to prevent resource exhaustion attacks.
_TIMEOUT_SECONDS = 10
_MAX_RESPONSE_BYTES = 64 * 1024  # 64 KB -- plenty for a status feed or weather string


# Allowlist of URL schemes we will actually connect to.
# Why exclude 'file://' and 'ftp://'?
# 1. 'file://': Python's urllib natively resolves file URIs by reading local
#    disk files (e.g. file:///etc/passwd or local SQLite DBs). Permitting it allows
#    arbitrary Local File Inclusion (LFI) via SSRF.
# 2. 'ftp://': Can trigger protocol smuggling, cleartext credential leakage, or hanging
#    connections on internal ports.
# We restrict exclusively to http and https.
_ALLOWED_SCHEMES = {"http", "https"}


def run(url: str, output_key: str) -> dict:
    """Fetch `url` via HTTP GET and return the response body.

    Args:
        url:        The URL to fetch (already sanitised and validated).
        output_key: The key to store the result under in the return dict.

    Returns:
        A result dict with the response body stored under `output_key`.

    Raises:
        ValueError:          If the URL scheme is not http/https (defence-in-depth).
        urllib.error.URLError: If the request fails (DNS, timeout, etc.).
        RuntimeError:        If the response exceeds the size limit.
    """
    # Defence-in-depth: re-check the URL scheme even though the sanitiser
    # already validated it. Belt and braces -- if someone refactors the
    # sanitiser and removes the URL check, this still blocks file:// etc.
    scheme = urlparse(url).scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ValueError(
            f"Blocked URL scheme '{scheme}': only http/https are permitted."
        )

    request = urllib.request.Request(
        url,
        headers={
            # Identify ourselves honestly. Never spoof a browser UA --
            # that would be deceptive and could violate site terms.
            "User-Agent": "lec-ai-agent/0.1",
        },
        method="GET",
    )

    with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
        # Read up to the limit. If the server sends more, we truncate and
        # raise rather than silently consuming an unbounded response body.
        raw = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise RuntimeError(
                f"Response from {url} exceeded {_MAX_RESPONSE_BYTES} bytes limit. "
                f"Aborting to prevent resource exhaustion."
            )

        body = raw.decode("utf-8", errors="replace")
        status_code = response.status

    return {
        output_key: body.strip(),
        "status_code": status_code,
        "url": url,
    }

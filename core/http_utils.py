# ── core/http_utils.py ───────────────────────────────────────────────────────
"""
Shared HTTP helper that caps response body size.

`requests` downloads the entire response body into memory when
``response.text`` or ``response.content`` is accessed. A malicious or
broken target that returns a multi-gigabyte body can therefore exhaust
the scanner's memory. ``bounded_request`` streams the response and
reads at most ``config.MAX_RESPONSE_BYTES`` bytes (default 2 MiB),
then returns a normal ``requests.Response`` object whose ``.text``,
``.content``, ``.url``, ``.status_code`` and ``.headers`` attributes
behave exactly as callers expect.
"""

import requests

import config

DEFAULT_MAX_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MiB


def bounded_request(method, url, *, session=None, max_bytes=None, **kwargs):
    """
    Make an HTTP request with a hard body-size cap.

    Parameters
    ----------
    method : str
        HTTP method (GET, POST, ...).
    url : str
        Request URL.
    session : requests.Session, optional
        Session to use (for cookies/auth). If omitted, a bare
        ``requests.request`` call is made.
    max_bytes : int, optional
        Maximum bytes to read. Defaults to ``config.MAX_RESPONSE_BYTES``
        or 2 MiB.
    **kwargs
        Passed through to ``session.request`` / ``requests.request``.

    Returns
    -------
    requests.Response
        Response object with ``_content`` populated from the capped read.
    """
    if max_bytes is None:
        max_bytes = getattr(
            config, 'MAX_RESPONSE_BYTES', DEFAULT_MAX_RESPONSE_BYTES
        )

    kwargs.setdefault('stream', True)

    if session is not None:
        resp = session.request(method, url, **kwargs)
    else:
        resp = requests.request(method, url, **kwargs)

    content = bytearray()
    try:
        for chunk in resp.iter_content(chunk_size=65536):
            content.extend(chunk)
            if len(content) >= max_bytes:
                break
    finally:
        resp.close()

    resp._content = bytes(content[:max_bytes])
    return resp

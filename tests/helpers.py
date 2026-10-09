"""Test helpers: a fake fetcher standing in for PoliteFetcher."""

from siteseal.fetch import RateLimited


class FakeResponse:
    def __init__(self, url, status=200, headers=None, body=b"", truncated=False):
        self.url = url
        self.status = status
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.body = body if isinstance(body, bytes) else body.encode("utf-8")
        self.truncated = truncated

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")


class FakeFetcher:
    """Maps URL prefixes to FakeResponse (or an exception instance to raise)."""

    def __init__(self):
        self.routes = []  # (prefix, response-or-exception), first match wins
        self.request_count = 0
        self.requested = []

    def add(self, prefix, response):
        self.routes.append((prefix, response))
        return self

    def get(self, url):
        self.request_count += 1
        self.requested.append(url)
        for prefix, resp in self.routes:
            if url.startswith(prefix):
                if isinstance(resp, Exception):
                    raise resp
                return resp
        return FakeResponse(url, status=404, body=b"not found")


def html_page(scripts=(), body_extra=""):
    tags = "".join('<script src="%s"></script>' % s for s in scripts)
    return ("<html><head>%s</head><body><h1>hi</h1>%s</body></html>"
            % (tags, body_extra)).encode()

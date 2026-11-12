"""Streaming output masker for `secreds run`.

Replaces each secret, and the common ways a program re-prints one, with ***. It works on the whole byte stream, not
line by line, so a multi-line secret (a PEM or SSH key) is caught, and it holds back only the few trailing bytes that
could still turn out to be the start of a secret.
"""
import base64, json, urllib.parse

MASK = b"***"
MIN_LEN = 4        # shorter values would shred ordinary output; they are still never logged


def variants(secrets):
    """Every byte string that should be hidden for these secret values, longest first."""
    out = set()
    for s in secrets:
        if not s or len(s) < MIN_LEN:
            continue
        raw = s.encode()
        out.add(raw)
        out.add(base64.b64encode(raw)); out.add(base64.b64encode(raw).rstrip(b"="))
        out.add(base64.urlsafe_b64encode(raw)); out.add(base64.urlsafe_b64encode(raw).rstrip(b"="))
        out.add(urllib.parse.quote(s, safe="").encode()); out.add(urllib.parse.quote_plus(s).encode())
        out.add(json.dumps(s)[1:-1].encode())                      # JSON-escaped (newlines as \n)
        out.add(s.replace("\r\n", "\n").replace("\n", "\\n").encode())
        if "\n" in s:
            out.add(s.replace("\n", "\r\n").encode())
        for part in s.splitlines():                               # each long line of a multi-line secret on its own
            if len(part.strip()) >= 12:
                out.add(part.strip().encode())
    return sorted((v for v in out if len(v) >= MIN_LEN), key=len, reverse=True)


class Masker:
    def __init__(self, secrets):
        self.vs = variants(secrets)
        self.buf = b""

    def _replace(self, data):
        for v in self.vs:
            if v in data:
                data = data.replace(v, MASK)
        return data

    def _hold(self, data):
        """How many trailing bytes might still be the beginning of a secret."""
        keep = 0
        for v in self.vs:
            for n in range(min(len(v) - 1, len(data)), keep, -1):
                if v.startswith(data[-n:]):
                    keep = n
                    break
        return keep

    def feed(self, chunk):
        data = self._replace(self.buf + chunk)
        keep = self._hold(data)
        self.buf = data[len(data) - keep:] if keep else b""
        return data[:len(data) - keep] if keep else data

    def flush(self):
        data, self.buf = self._replace(self.buf), b""
        return data

"""
Job51Client — request scaffold for the 51job cgate/cupid API.

The request shape (host + common params + headers) is recovered from the unpacked app; the
`sign` / `appsign` parameter is computed by a method the s.h.e.l.l shell extracted (nop'd in the
static dump), so `sign()` is a TODO to be filled from an ART-method-level dump. Until then this
scaffold assembles everything EXCEPT the signature and will raise on send.
"""
from __future__ import annotations
import json as _json
import time
import requests

from . import api


class SignNotImplemented(NotImplementedError):
    pass


def sign(params: dict, key: str | None = None) -> str:
    """51job request signature (params 'sign'/'appsign').

    TODO: recover the algorithm from an ArtMethod-level dump of jobs.android.retrofitnetwork
    .BasicParamsInterceptor (the shell extracted the method body). The common params carry
    partner / guid / uuid / device / version / timestamp; the legacy .php API historically
    signs a sorted param string with an app key. Fill this in once the dump yields the bytecode.
    """
    raise SignNotImplemented(
        "51job sign() not recovered — the s.h.e.l.l shell extracted BasicParamsInterceptor's "
        "method body; needs an ArtMethod dump. See docs/unpacking.md.")


class Job51Client:
    def __init__(self, session: dict):
        self.s = session
        self.http = requests.Session()

    def _common_params(self) -> dict:
        """Common params observed on the request (names recovered; values from the session)."""
        return {
            "partner": self.s.get("partner", ""),
            "guid": self.s.get("guid", ""),
            "uuid": self.s.get("uuid", ""),
            "device": self.s.get("device", ""),
            "version": self.s.get("version", "16.15.0"),
            "timestamp": str(int(time.time())),
        }

    def get(self, path: str, host: str = "cupid", params: dict | None = None) -> dict:
        q = self._common_params()
        if params:
            q.update(params)
        q["sign"] = sign(q, self.s.get("sign_key"))          # raises until recovered
        r = self.http.get(api.url(path, host), params=q,
                          headers={"Authorization": self.s.get("access_token", "")}, timeout=30)
        r.raise_for_status()
        return _json.loads(r.content.decode("utf-8", "replace"))

    def job_search(self, keyword: str, page: int = 1) -> dict:
        return self.get(api.ENDPOINTS["job_search"], "cupid",
                        {"keyword": keyword, "pageNum": page, "pageSize": 30})

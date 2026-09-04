"""
Job51Client — 51job cupid/young API client with the RECOVERED, LIVE-VERIFIED request signature.

The `sign` algorithm was recovered from a root /proc/<pid>/mem memory dump of the 爱加密/Ijiami-packed
app (lazy extraction: the invoked EncryptAndSignUtil / SignFor51 are full bytecode in the dump, so no
FART is needed for the sign — see docs/unpacking.md), then verified against the live cupid.51job.com
gateway: a correct sign reaches the business layer (HTTP 200) while a corrupted sign is rejected with
`{"status":"110011","message":"鉴权失败，签名错误"}`. Source classes:

  com.jobs.network.EncryptAndSignUtil / $SignKey                 -- sign interceptor + per-host keys
  com.jobs.network.digest.SignFor51                             -- hmacSha256 / getSHA256 / md5
  com.jobs.network.interceptor.CommonParamInterceptor           -- common QUERY params (below)
  com.jobs.network.interceptor.CommonHeaderInterceptor          -- Client-Time header
  com.job.android.network.MyNetWorkConfig.getCommonQueryParams  -- the common query param set

Request (modern cupid / youngapi hosts):
  CommonParamInterceptor first appends the common QUERY params (below) to the URL; THEN the sign is
  computed over the whole URL after the host:
    after_host = url.substring(url.indexOf(host) + host.length())   # "/path?key=&api_key=51job&..."
    message    = after_host + gsonJson(bodyParams)                  # getSignJsonDataFromMap
    sign       = HMAC_SHA256(getSignKeyForHost(host, api_key, clientid), message).hex()  # lower hex
  headers: "sign" = sign, "Client-Time" = client_time() (a separate GATEWAY header, NOT in the HMAC).

Common query params (MyNetWorkConfig.getCommonQueryParams): key, api_key=51job, format=json,
productname=51job, partner, uuid, version=16.15.0, accountid, clientid=000007, privacy, distinct_id,
huihuaId, timestamp=currentTimeMillis()/1000 (the GATEWAY-validated timestamp), frompageUrl, pageUrl.
`key`/`accountid` are login values (empty when anonymous); `partner`/`uuid` are device/app config.

Legacy path (EncryptAndSignUtil.signData, older appapi/vapi): sign = MD5(SHA256(x + data + key)).
"""
from __future__ import annotations
import hashlib
import hmac
import json as _json
import time
import urllib.parse
from datetime import datetime, timezone, timedelta
import requests

from . import api

# EncryptAndSignUtil$SignKey enum values (recovered from the enum <clinit> smali; all confirmed).
# App-EMBEDDED constants — same for every install, not tied to any account, extractable from the APK
# (the sign is an anti-tamper HMAC, not auth) — so included directly.
SIGN_KEYS = {
    "V_API": "8a9f1f198af70a41aec9fc7cf34b3456",
    "V_API_FOR_CAMPUS": "9hnrejixqt4k4jt60rrl7w6ajyfv0t1k",
    "V_API_FOR_YJS": "1960a9b25d8d4e16bcff6d5d7d82c2cb",
    "IM": "w$mm0nIukwebctvH",
    "APP_API": "44kC5ppqtNc8",
    "SIGH_KEY_XY": "lhs3ayggr7fc00sjgskaupe6nrrlxod9tl1ct7hhdivvzdd2kj6hurj3fukhnt3r",
    "SIGN_KEY_51JOB": "abfc8f9dcf8c3f3d8aa294ac5f2cf2cc7767e5592590f39c3f503271dd68562b",
}


def sign_key_for(host: str, api_key: str = "51job", clientid: str = "000007") -> str:
    """EncryptAndSignUtil$SignKey.getSignKeyForHost — pick the key by host (+ api_key/clientid query
    params). cupid/youngapi default to SIGN_KEY_51JOB (SIGH_KEY_XY only when api_key=='xy')."""
    if host in ("appapi.51job.com", "appapi.51jobapp.com"):
        return SIGN_KEYS["APP_API"]
    if host in ("vapi.51job.com", "vapi.51jobapp.com"):
        if clientid == "000013":
            return SIGN_KEYS["V_API_FOR_CAMPUS"]
        return SIGN_KEYS["V_API_FOR_YJS"] if clientid == "000004" else SIGN_KEYS["V_API"]
    if host in ("cupid.51job.com", "cupid.51jobapp.com",
                "youngapi.yingjiesheng.com", "youngapi.51job.com"):
        return SIGN_KEYS["SIGH_KEY_XY"] if api_key == "xy" else SIGN_KEYS["SIGN_KEY_51JOB"]
    if host in ("im.51job.com", "im.51jobapp.com"):
        return SIGN_KEYS["IM"]
    return SIGN_KEYS["V_API"]


def gson_json(params: dict) -> str:
    """Mirror EncryptAndSignUtil.getSignJsonDataFromMap: a Gson JsonObject of the param map, values
    as strings, insertion order preserved, compact separators."""
    return _json.dumps({k: str(v) for k, v in params.items()}, separators=(",", ":"),
                       ensure_ascii=False)


def hmac_sha256(key: str, message: str) -> str:
    """SignFor51.hmacSha256(key, message) -> lower-case hex."""
    return hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def client_time() -> str:
    """CommonHeaderInterceptor.getCurrentTime(): GMT+8, minute/second/millis zeroed (top of hour),
    getTimeInMillis()/1000 -> epoch SECONDS. A gateway header, NOT part of the cupid HMAC."""
    tz8 = timezone(timedelta(hours=8))
    hs = datetime.now(tz8).replace(minute=0, second=0, microsecond=0)
    return str(int(hs.timestamp()))


def sign_cupid(after_host: str, params: dict, host: str = "cupid.51job.com",
               api_key: str = "51job", clientid: str = "000007") -> str:
    """Modern cupid/young sign: HMAC_SHA256(signKey, after_host + gsonJson(params)). `after_host` is
    url.substring(after host) — path WITH leading '/' AND the query string (common params), exactly
    as sent."""
    key = sign_key_for(host, api_key, clientid)
    message = "/" + after_host.lstrip("/") + gson_json(params)
    return hmac_sha256(key, message)


def sign_legacy(data: str, key: str, prefix: str = "") -> str:
    """Legacy appapi signData: MD5(SHA256(prefix + data + key).getBytes())."""
    inner = hashlib.sha256((prefix + data + key).encode("utf-8")).hexdigest()
    return hashlib.md5(inner.encode("utf-8")).hexdigest()


class Job51Client:
    def __init__(self, session: dict | None = None):
        self.s = session or {}
        self.http = requests.Session()

    def common_query_params(self) -> list[tuple[str, str]]:
        """MyNetWorkConfig.getCommonQueryParams — the common query params. `timestamp` is the
        gateway-validated epoch-seconds; `partner`/`uuid` come from the session (device/app config),
        `key`/`accountid` from login (empty when anonymous)."""
        return [
            ("key", self.s.get("key", "")),
            ("api_key", "51job"),
            ("format", "json"),
            ("productname", "51job"),
            ("partner", self.s.get("partner", "")),
            ("uuid", self.s.get("uuid", "")),
            ("version", "16.15.0"),
            ("accountid", self.s.get("accountid", "")),
            ("clientid", "000007"),
            ("privacy", "1"),
            ("distinct_id", self.s.get("distinct_id", "")),
            ("huihuaId", self.s.get("huihuaId", "")),
            ("timestamp", str(int(time.time()))),
            ("frompageUrl", ""),
            ("pageUrl", ""),
        ]

    def call(self, host: str, path: str, params: dict | None = None,
             extra_query: list[tuple[str, str]] | None = None) -> dict:
        """POST a signed cupid/young request. Builds the common query params (+ any `extra_query`),
        signs over "/path?query" + gsonJson(params), and sends with the `sign` + `Client-Time`
        headers. Verified live against cupid.51job.com."""
        params = params or {}
        q = self.common_query_params() + (extra_query or [])
        qs = urllib.parse.urlencode(q)
        after_host = "/" + path.lstrip("/") + "?" + qs
        body = gson_json(params)
        sign = sign_cupid(after_host, params, host)
        headers = {
            "Content-Type": "application/json;charset=utf-8",
            "sign": sign,
            "Client-Time": client_time(),
            "UUID": self.s.get("uuid", ""),
            "User-Agent": self.s.get("ua", "okhttp/4.9.0"),
        }
        if self.s.get("access_token"):
            headers["user-token"] = self.s["access_token"]
        url = f"https://{host}/{path.lstrip('/')}?{qs}"
        r = self.http.post(url, data=body.encode("utf-8"), headers=headers, timeout=30)
        r.raise_for_status()
        return _json.loads(r.content.decode("utf-8", "replace"))

    def job_search(self, keyword: str, page: int = 1) -> dict:
        """Job search (needs a logged-in user-token in session['access_token'])."""
        return self.call("cupid.51job.com", api.ENDPOINTS["job_search"],
                         {"keyword": keyword, "pageNum": page, "pageSize": 30})

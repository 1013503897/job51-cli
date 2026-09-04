"""
Job51Client — 51job cupid/young API client with the RECOVERED request signature.

The `sign` algorithm was recovered from a root /proc/<pid>/mem memory dump of the 爱加密/Ijiami-packed
app. The packer's method extraction is lazy: methods that have been invoked at runtime are restored
in-memory, so EncryptAndSignUtil / SignFor51 (exercised while the app runs) appear as full method
bodies in the dump (insns_size 31–439) and disassemble directly — no ArtMethod-level FART is needed
for the sign. (FART / the Vector unpacker is the general path for methods that are never invoked and
stay nop'd; see docs/unpacking.md.) Source classes:

  com.jobs.network.EncryptAndSignUtil            -- the OkHttp sign/encrypt interceptor
  com.jobs.network.EncryptAndSignUtil$SignKey    -- per-host secret keys (enum)
  com.jobs.network.digest.SignFor51              -- hmacSha256 / getSHA256 / md5 primitives

Algorithm (modern cupid / youngapi hosts, EncryptAndSignUtil.getRequestBodyAfter):
  message = <url path after host> + gsonJson(params)          # getSignJsonDataFromMap: Gson obj
  sign    = HMAC_SHA256(key=SignKey.getSignKey(), msg=message).hex()   # lower-case, SignFor51
  request:  header "sign" = sign,  header "Client-Time" = <epoch ms>,  body = gsonJson(params)

Legacy path (EncryptAndSignUtil.signData, older appapi/vapi): sign = MD5(SHA256(x + data + key)).
"""
from __future__ import annotations
import hashlib
import hmac
import json as _json
import time
import requests

from . import api

# EncryptAndSignUtil$SignKey enum values, from the class's <clinit>. These are APP-EMBEDDED constants
# (the same for every install, not tied to any account, extractable from the APK) — the sign is an
# anti-tamper HMAC, not authentication — so they are included directly. getSignKeyForHost(url) picks
# one by host (see docs/sign.md for the host->key switch).
SIGN_KEYS = {
    "V_API": "8a9f1f198af70a41aec9fc7cf34b3456",
    "V_API_FOR_CAMPUS": "9hnrejixqt4k4jt60rrl7w6ajyfv0t1k",
    "V_API_FOR_YJS": "1960a9b25d8d4e16bcff6d5d7d82c2cb",
    "IM": "w$mm0nIukwebctvH",
    "APP_API": "44kC5ppqtNc8",
    "SIGH_KEY_XY": "lhs3ayggr7fc00sjgskaupe6nrrlxod9tl1ct7hhdivvzdd2kj6hurj3fukhnt3r",
}

# Hosts that sign via getRequestBodyAfter (HMAC-SHA256). getSignKeyForHost maps each to a SignKey;
# cupid/vapi/appapi.51job* use V_API, campus (yingjiesheng young) uses V_API_FOR_YJS, etc.
SIGNED_HOSTS = {
    "cupid.51job.com": "V_API", "cupid.51jobapp.com": "V_API",
    "vapi.51job.com": "V_API", "vapi.51jobapp.com": "V_API",
    "appapi.51job.com": "APP_API", "appapi.51jobapp.com": "APP_API",
    "youngapi.51job.com": "V_API", "youngapi.yingjiesheng.com": "V_API_FOR_YJS",
    "im.51job.com": "IM", "im.51jobapp.com": "IM",
}


def gson_json(params: dict) -> str:
    """Mirror EncryptAndSignUtil.getSignJsonDataFromMap: a Gson JsonObject of the param map, values
    as strings, insertion order preserved, compact separators."""
    return _json.dumps({k: str(v) for k, v in params.items()}, separators=(",", ":"),
                       ensure_ascii=False)


def hmac_sha256(key: str, message: str) -> str:
    """SignFor51.hmacSha256(key, message) -> lower-case hex."""
    return hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def sign_cupid(url_path: str, params: dict, host: str = "cupid.51job.com") -> str:
    """Modern cupid/young sign: HMAC_SHA256(signKey, url_path + gsonJson(params))."""
    keyname = SIGNED_HOSTS.get(host, "V_API")
    key = SIGN_KEYS[keyname]
    message = url_path + gson_json(params)
    return hmac_sha256(key, message)


def sign_legacy(data: str, key: str, prefix: str = "") -> str:
    """Legacy appapi signData: MD5(SHA256(prefix + data + key).getBytes())."""
    inner = hashlib.sha256((prefix + data + key).encode("utf-8")).hexdigest()
    return hashlib.md5(inner.encode("utf-8")).hexdigest()


class Job51Client:
    def __init__(self, session: dict | None = None):
        self.s = session or {}
        self.http = requests.Session()

    def call(self, host: str, path: str, params: dict | None = None) -> dict:
        """POST a signed cupid/young request. `host` is the API host (e.g. cupid.51job.com);
        `path` is the URL path (used in the sign message)."""
        params = params or {}
        body = gson_json(params)
        sign = sign_cupid(path, params, host)
        headers = {
            "Content-Type": "application/json;charset=utf-8",
            "sign": sign,
            "Client-Time": str(int(time.time() * 1000)),
            "User-Agent": self.s.get("ua", "okhttp/4.9.0"),
        }
        if self.s.get("access_token"):
            headers["Authorization"] = self.s["access_token"]
        url = f"https://{host}/{path.lstrip('/')}"
        r = self.http.post(url, data=body.encode("utf-8"), headers=headers, timeout=30)
        r.raise_for_status()
        return _json.loads(r.content.decode("utf-8", "replace"))

    def job_search(self, keyword: str, page: int = 1) -> dict:
        return self.call("cupid.51job.com", api.ENDPOINTS["job_search"],
                         {"keyword": keyword, "pageNum": page, "pageSize": 30})

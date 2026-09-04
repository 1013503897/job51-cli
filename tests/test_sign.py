"""51job sign primitives (recovered from a /proc/mem memory dump; see docs/sign.md).

These are offline unit tests of the algorithm shape — they do NOT need the real per-host keys.
Where a key is required they use an arbitrary literal or the (possibly-empty) SIGN_KEYS entry, so
they pass with or without a populated .env.
"""
import os, sys, hmac, hashlib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from job51cli.client import hmac_sha256, gson_json, sign_cupid, sign_legacy, SIGN_KEYS


def test_hmac_sha256_matches_stdlib():
    k, m = "test-key", "hello"          # arbitrary key — this only checks hmac_sha256 == stdlib
    assert hmac_sha256(k, m) == hmac.new(k.encode(), m.encode(), hashlib.sha256).hexdigest()
    assert len(hmac_sha256(k, m)) == 64          # lower-case hex, SHA-256


def test_gson_json_order_and_strings():
    j = gson_json({"keyword": "python", "pageNum": 1, "pageSize": 30})
    assert j == '{"keyword":"python","pageNum":"1","pageSize":"30"}'   # values as strings, insertion order


def test_sign_cupid_shape():
    s = sign_cupid("open/good-job-tab/search-new-job-list",
                   {"keyword": "python", "pageNum": 1}, host="cupid.51job.com")
    # deterministic HMAC over path+json with whatever V_API key is configured (may be "")
    msg = "open/good-job-tab/search-new-job-list" + gson_json({"keyword": "python", "pageNum": 1})
    assert s == hmac.new(SIGN_KEYS["V_API"].encode(), msg.encode(), hashlib.sha256).hexdigest()


def test_sign_legacy():
    key = "test-key"                    # arbitrary key — sign_legacy is a pure fn of (data, key)
    inner = hashlib.sha256(("abc" + key).encode()).hexdigest()
    assert sign_legacy("abc", key) == hashlib.md5(inner.encode()).hexdigest()


if __name__ == "__main__":
    n = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print(f"  ok  {name}"); n += 1
    print(f"all {n} tests passed")

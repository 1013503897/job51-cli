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
    # cupid default key = SIGN_KEY_51JOB (api_key='51job' != 'xy'); sign_cupid ensures the leading '/'
    msg = "/open/good-job-tab/search-new-job-list" + gson_json({"keyword": "python", "pageNum": 1})
    assert s == hmac.new(SIGN_KEYS["SIGN_KEY_51JOB"].encode(), msg.encode(), hashlib.sha256).hexdigest()


def test_sign_key_for_host():
    from job51cli.client import sign_key_for
    assert sign_key_for("cupid.51job.com") == SIGN_KEYS["SIGN_KEY_51JOB"]
    assert sign_key_for("cupid.51job.com", api_key="xy") == SIGN_KEYS["SIGH_KEY_XY"]
    assert sign_key_for("appapi.51job.com") == SIGN_KEYS["APP_API"]
    assert sign_key_for("vapi.51job.com", clientid="000004") == SIGN_KEYS["V_API_FOR_YJS"]
    assert sign_key_for("im.51job.com") == SIGN_KEYS["IM"]


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

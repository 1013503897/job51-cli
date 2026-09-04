# job51-cli

A reverse-engineering study client for the **前程无忧 51job (com.job.android)** API, with the
request signature (`sign`) recovered and reproduced in pure Python.

> Research / study project. The app is packed by an 爱加密 (Ijiami) code-extraction shell. It was
> unpacked from memory (root `/proc/<pid>/mem` dump → 16 DEX / 55054 classes), which recovered the
> API map **and** the signing algorithm. The sign is **verified live**: recomputing it over a real
> captured request reproduces the app's `sign` header byte-for-byte, and `python -m job51cli java`
> fetches real 51job listings from the public API with no login. See
> [`docs/unpacking.md`](docs/unpacking.md) and [`docs/sign.md`](docs/sign.md).

## What's recovered

- **Sign** — `sign = HMAC_SHA256(perHostKey, afterHost + gsonJson(bodyParams))`, lower-case hex, in a
  `sign` header. `afterHost` is the URL substring after the host — path **and** query string, since
  the common query params are appended before signing. `Client-Time` is a separate gateway header
  (GMT+8 epoch **seconds**, truncated to the hour), not part of the HMAC. Two more paths exist
  (`signData = MD5(SHA256(...))` and `CQEncrypt` for appapi). Source:
  `EncryptAndSignUtil` / `EncryptAndSignUtil$SignKey` / `SignFor51` / `CommonParamInterceptor`.
  Implemented in [`job51cli/client.py`](job51cli/client.py) (`sign_cupid` / `sign_legacy`).
- **Hosts** — legacy `https://appapi.51job.com/api/2|3/*.php` and the modern REST
  `https://cupid.51job.com/open/*`, plus `aceapi` / `51gpt` / `app`.
- **554 endpoints** — [`docs/endpoints_full.txt`](docs/endpoints_full.txt). E.g. job search
  `open/good-job-tab/search-new-job-list`, SMS `open/noauth/sms/send-sms-verification-code`.
- **Common params / auth** — `partner` / `guid` / `uuid` / `device` / `version` / `timestamp` +
  `sign`, plus an Authorization / access-token header.

## Why no FART was needed for the sign

The packer's extraction is lazy: methods **invoked at runtime** are restored in memory, methods that
are never invoked stay nop'd. `EncryptAndSignUtil` / `SignFor51` are exercised whenever the app
signs a request, so their bodies are full in the `/proc/mem` dump (`insns_size` 31–439) and
disassemble directly. ArtMethod-level FART (the Vector unpacker's `dexfind`+`trigger`) is the general
path for the methods that stay nop'd; it is not required for the sign. Details in `docs/`.

## Sign keys

All 7 per-host `EncryptAndSignUtil$SignKey` values (incl. `SIGN_KEY_51JOB`, the cupid/young default)
are **app-embedded HMAC constants** — the same for every install, not tied to any account, and
extractable from the APK. The sign is an anti-tamper HMAC, not authentication, so the keys are
included directly in [`job51cli/client.py`](job51cli/client.py); `sign_key_for(host, api_key,
clientid)` mirrors `getSignKeyForHost`.

## Run

```bash
pip install requests
python tests/test_sign.py                # offline: primitives + sign shape (5/5)
python -m job51cli java 010000           # LIVE: real 51job listings, no login
python -m job51cli detail 173534695      # LIVE: full job detail (desc/company/salary/HR)
```

`python -m job51cli <keyword> [jobarea]` signs a request to the public (noauth) job search and
prints real listings from `resultbody.job.items` — e.g. for `java`:

```
[173534695] Java开发工程师  |  深圳·龙华区  |  2年及以上 / 本科 / 周末双休 / 全勤奖
[173499249] Java后端开发工程师  |  宁波·慈溪市  |  5年及以上 / 本科 / 交通补贴 / 餐饮补贴
[173521861] Java开发(中原银行账务类项目)  |  郑州·金水区  |  5年及以上 / 本科 / java / mysql
...
```

No login or device values needed — the noauth endpoints validate the sign, and a random `uuid` /
`partner` work. Programmatic: `Job51Client().search_jobs(keyword, jobarea)` and
`Job51Client().job_detail(job_id)` (returns `detailJobInfo` — description, company, salary, HR,
address). A lot of data is reachable without an account this way.

### Login (out of scope here)

The logged-in surface (`job_search`'s personalized results, applications, resume, etc.) needs a
`user-token`. Login is `POST open/noauth/login/loginbyphone` (form `nationCode`/`mobile`/`phoneCode`
→ `LoginInfo.token`), and the SMS code comes from `sendPhoneCodeWithGeetest` — i.e. it is gated by a
**Geetest CAPTCHA + an SMS OTP**, and first login **auto-registers an account**. This client stays on
the noauth endpoints (which already expose search + full detail); to use the logged-in surface, put
your own `user-token` in `session['access_token']`.

## Layout

```
job51cli/api.py       hosts + key endpoints
job51cli/client.py    sign (sign_cupid / sign_legacy) + signed request client
docs/sign.md          the sign algorithm + how it was recovered
docs/unpacking.md     how the s.h.e.l.l shell was unpacked from /proc/<pid>/mem
docs/endpoints_full.txt   the 554 endpoints recovered from the unpacked DEX
```

Reverse-engineered from `com.job.android` v16.15.0.

## Disclaimer

For security research and study only. Do not use in any way that violates 51job's Terms of Service
or applicable law; you bear all consequences of use.

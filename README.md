# job51-cli

A reverse-engineering study client for the **前程无忧 51job (com.job.android)** API, with the
request signature (`sign`) recovered and reproduced in pure Python.

> Research / study project. The app is packed by an 爱加密 (Ijiami) code-extraction shell. It was
> unpacked from memory (root `/proc/<pid>/mem` dump → 16 DEX / 55054 classes), which recovered the
> API map **and** the signing algorithm. See [`docs/unpacking.md`](docs/unpacking.md) and
> [`docs/sign.md`](docs/sign.md).

## What's recovered

- **Sign** — `sign = HMAC_SHA256(perHostKey, urlPathAfterHost + gsonJson(params))`, lower-case hex,
  in a `sign` header alongside a `Client-Time` (epoch-ms) header; body is the same `gsonJson(params)`.
  Two more paths exist (`signData = MD5(SHA256(...))` and `CQEncrypt` for appapi). Source classes:
  `com.jobs.network.EncryptAndSignUtil` / `EncryptAndSignUtil$SignKey` / `com.jobs.network.digest.SignFor51`.
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

The per-host `EncryptAndSignUtil$SignKey` values are **app-embedded HMAC constants** — the same for
every install, not tied to any account, and extractable from the APK. The sign is an anti-tamper
HMAC, not authentication, so the keys are included directly in
[`job51cli/client.py`](job51cli/client.py).

## Run

```bash
pip install requests
python tests/test_sign.py                # offline: primitives + sign shape
# then use job51cli.client.Job51Client for signed requests
```

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

# job51-cli

A reverse-engineering scaffold for the **前程无忧 51job (com.job.android)** API.

> Research / study project. **Status: scaffold, not runnable yet.** The app is packed by an
> `s.h.e.l.l` code-extraction shell; it was unpacked from memory (16 DEX / 55054 classes), which
> recovered the API map (hosts / endpoints / param names) but **not** the request-signing
> algorithm — that lives in a method body the shell extracted, so it needs an ART-method-level
> dump. See [`docs/unpacking.md`](docs/unpacking.md).

## What's recovered

- **Hosts** — legacy `https://appapi.51job.com/api/2|3/*.php` (partner/guid/sign) and the modern
  REST `https://cupid.51job.com/open/*`, plus `aceapi` / `51gpt` / `app`.
- **554 endpoints** — [`docs/endpoints_full.txt`](docs/endpoints_full.txt). Notably:
  - job search: `open/good-job-tab/search-new-job-list`
  - login/SMS: `open/noauth/sms/send-sms-verification-code`, `open/noauth/sms/geetest-first-register`
- **Common params** — `partner` / `guid` / `uuid` / `device` / `version` / `timestamp` + `sign`/`appsign`.
- **Auth** — an Authorization/access-token header + the signed params.

## What's missing

- **`sign()` / `appsign`** — the signing method (`jobs.android.retrofitnetwork.BasicParamsInterceptor`)
  is nop'd in the static dump (抽取壳). `job51cli/client.py::sign()` raises `SignNotImplemented`
  until it's recovered via an ArtMethod dump. So the client assembles everything except the
  signature and can't send valid requests yet.

## Layout

```
job51cli/api.py       hosts + key endpoints
job51cli/client.py    request scaffold (common params + headers) + sign() TODO
docs/unpacking.md     how the s.h.e.l.l shell was unpacked from /proc/pid/mem
docs/endpoints_full.txt   the 554 endpoints recovered from the unpacked DEX
```

Reverse-engineered from `com.job.android` v16.15.0.

## Disclaimer

For security research and study only. Do not use in any way that violates 51job's Terms of Service
or applicable law; you bear all consequences of use.

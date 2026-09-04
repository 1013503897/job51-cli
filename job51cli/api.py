"""51job API hosts + key endpoints (recovered from the unpacked DEX strings)."""
from __future__ import annotations

# Hosts seen in the unpacked app
HOSTS = {
    "appapi": "https://appapi.51job.com",   # legacy .php API: /api/2/*, /api/3/*  (partner/guid/sign)
    "cupid": "https://cupid.51job.com",      # modern REST API: /open/*
    "ace": "https://aceapi.51job.com",
    "gpt": "https://51gpt.51job.com",
    "app": "https://app.51job.com",
}

# A few concrete endpoints (554 total extracted — see docs/endpoints.md / job51_endpoints.txt)
ENDPOINTS = {
    # cupid REST (/open/*)
    "job_search": "open/good-job-tab/search-new-job-list",   # 职位搜索（需登录 user-token）
    "job_search_noauth": "open/noauth/gold-two-silver-three/search-job-list",  # 公开职位搜索（免登录）
    "job_search_v0": "open/good-job-tab/search-job-list",
    "send_sms": "open/noauth/sms/send-sms-verification-code",
    "geetest_register": "open/noauth/sms/geetest-first-register",
    "dict_single": "open/noauth/dictionary/single-dictionary",
    "last_version": "open/noauth/index/last-version",
    # legacy appapi (.php)
    "auto_login": "api/2/user/auto_login.php",
    "apply_job": "api/2/user/apply_job.php",
    "dd_search": "api/2/datadict/get_dd_search.php",
}


def url(path: str, host: str = "cupid") -> str:
    if path.startswith("http://") or path.startswith("https://"):
        return path
    base = HOSTS.get(host, HOSTS["cupid"])
    return base.rstrip("/") + "/" + path.lstrip("/")

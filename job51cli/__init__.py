"""job51-cli — off-device client scaffold for the 前程无忧 51job (com.job.android) API.

Reverse-engineered from com.job.android v16.15.0, which ships packed by an s.h.e.l.l shell. The
app was unpacked by dumping the decrypted DEX regions from /proc/pid/mem (root, bypassing page
perms) and reassembling 16 DEX / 55054 classes — see docs/unpacking.md. That yielded the full API
map (hosts, endpoints, param names) but the shell is a *code-extraction* (抽取壳) shell: method
bodies are nop'd in the static image, so the request-signing algorithm (sign/appsign) is not in
the dump and needs an ART-method-level dump. Hence this is a **scaffold**, not a runnable client:
the request assembly is here, `sign()` is a documented TODO.
"""
__version__ = "0.1.0"

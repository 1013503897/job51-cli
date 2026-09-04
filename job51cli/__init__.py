"""job51-cli — off-device study client for the 前程无忧 51job (com.job.android) API.

Reverse-engineered from com.job.android v16.15.0, which ships packed by 爱加密 (Ijiami). The app
was unpacked by dumping the decrypted DEX regions from /proc/pid/mem (root, bypassing page perms)
and reassembling 16 DEX / 55054 classes — see docs/unpacking.md. The shell is a *code-extraction*
(抽取壳) shell, but extraction is lazy: methods invoked at runtime are restored in memory, so the
signing chain (EncryptAndSignUtil / SignFor51) is full in the dump and the request signature was
recovered directly — see docs/sign.md and job51cli.client.
"""
__version__ = "0.1.0"

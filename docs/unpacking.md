# 前程无忧 51job (com.job.android v16.15.0) — unpacking notes

The app is packed by an **`s.h.e.l.l`** shell (Application `s.h.e.l.l.S`, appComponentFactory
`s.h.e.l.l.A`). jadx on the base APK shows only 143 classes (ARouter routes); the business code is
encrypted and loaded at runtime.

## Anti-frida

frida is defeated by the shell + `libzxprotect.so` (RASP):

```
attach -> target terminated with signal 9        # process SIGKILL'd on frida agent injection
spawn  -> unexpectedly timed out while waiting for app to launch
```

Both a Morphida anti-detect frida-server and a vanilla 32/64-bit frida-server get killed.

## Memory dump (no frida)

The process is **not self-ptraced** (`TracerPid: 0`), so root can read `/proc/<pid>/mem` — and
that read **bypasses page permissions**, so even the shell's `-wxp` (no-read) DEX pages dump fine.

1. `cat /proc/<pid>/maps | grep 'DEX data'` → 496 `[anon:dalvik-DEX data]` regions.
2. Dump each DEX's full span from `/proc/<pid>/mem`. Two traps:
   - **Android shell is 32-bit arithmetic** — `$((0x6f8a65d000))` overflows to negative. Compute
     `skip`/`count` on the PC (64-bit) and emit `dd bs=4096 skip=<literal>` commands.
   - **A DEX spans multiple regions** — `file_size` (header @0x20) > a single region. The DEX
     offset is page-aligned, so read `file_size` bytes from the DEX's virtual address (region
     start + magic offset); adjacent regions read contiguously through `/proc/mem`.
3. Trim each dump to `file_size`, recompute the SHA-1 signature (`data[0x20:]`) and Adler32
   checksum (`data[0x0c:]`), pack the 16 DEX as `classes.dex`/`classes2.dex`… into a zip → jadx
   loads **55054 classes**.

## It's a code-extraction (抽取壳) shell

Method bodies in the dump are `return null` + a run of `nop`:

```
.method public intercept(Lokhttp3/Interceptor$Chain;)Lokhttp3/Response;
    const/4 v0, 0x0
    return-object v0
    nop nop nop …
.end method
```

So this is not a whole-DEX encryption shell (where the memory dump gives complete bytecode) — it
**extracts** each method's `code_item`, restoring it to a separate buffer at runtime (the ArtMethod
entry points there; the DEX's inline `code_item` stays nop'd). The dump therefore yields **class
structure + method signatures + fields + string constants** (enough for hosts / endpoints / param
names) but **not method bytecode** — the signing algorithm included.

Recovering the bytecode needs an **ArtMethod-level dump** (FART/Youpk-style: hook `ArtMethod`
invoke, dump each `code_item` from the ArtMethod), which requires running in-process — i.e. first
defeating `libzxprotect`'s anti-frida (e.g. via a KPM-stealth ART-hook framework). That is the
next step; `client.sign()` stays a TODO until then.

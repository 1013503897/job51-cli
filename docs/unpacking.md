# 前程无忧 51job (com.job.android v16.15.0) — unpacking notes

The app is packed by **爱加密 (Ijiami)** — the entry shell classes are `s.h.e.l.l.S` (Application)
/ `s.h.e.l.l.A` (appComponentFactory), but the vendor fingerprint is unmistakable in the packed
APK:

```
assets/ijiami.dat            (~36 MB)  encrypted business DEX payload
assets/ijiami.ajm
assets/ijm_lib/<abi>/libexec.so, libexecmain.so   Ijiami shell natives ("ijm")
assets/libijmDataEncryption_<abi>.so
assets/IJMDal.Data
lib/<abi>/libijm-emulator.so     Ijiami VMP / instruction emulator
lib/<abi>/libzxprotect.so        Ijiami RASP (anti-frida / anti-debug)
```

So it's Ijiami in **extraction + VMP** dual mode: most business methods are *extracted* (nop'd body,
runtime-restored → recoverable as standard CodeItems, which is what FART below does), but some may be
VM-protected by `libijm-emulator` (no standard CodeItem → out of FART scope). jadx on the base APK
shows only 143 classes (ARouter routes); the business code is encrypted (`ijiami.dat`) and loaded at
runtime. The self-libart-patching anti-hook (below) is `libexec` / `libzxprotect`'s doing.

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

## It's a code-extraction (抽取壳) shell — and extraction is lazy

The shell **extracts** each method's `code_item`, restoring it to a separate buffer at runtime (the
ArtMethod entry points there; the DEX's inline `code_item` stays nop'd). Extraction is **lazy**: a
method is restored the first time it is invoked; methods never invoked stay nop stubs. So in the
memory dump, invoked methods are complete bytecode, while un-invoked ones are `return null` + a run
of `nop`:

```
.method public intercept(Lokhttp3/Interceptor$Chain;)Lokhttp3/Response;
    const/4 v0, 0x0
    return-object v0
    nop nop nop …
.end method
```

The dump yields **class structure + method signatures + fields + string constants** (hosts /
endpoints / param names) for everything, and **full bytecode for every method that ran**.

## ✅ Sign recovered — straight from the memory dump

The signing chain (`EncryptAndSignUtil` / `SignFor51`) runs whenever the app signs a request, so its
method bodies are full in the dump (`insns_size` 31–439) and disassemble directly — **no FART
needed**. **The sign algorithm + all secret keys are recovered** — see [sign.md](sign.md) and
`job51cli/client.py`. TL;DR: cupid/young sign = `HMAC_SHA256(perHostKey, urlPath + gsonJson(params))`,
key from `EncryptAndSignUtil$SignKey`.

## FART — for methods that never ran (general capability)

To recover methods still nop'd in the dump (the various `intercept`s, etc.) you need an
**ArtMethod-level dump**: enumerate `ArtMethod`, force-restore each via `GetCodeItem`. Vector's
built-in unpacker (`persist.kpmhook.unpack.dexfind=1 trigger=1`) captured 364k+ CodeItems this way.
Getting FART to run on this shell needed three fixes to Vector's unpacker (all upstreamed to the
working tree): (1) a `worker_delay_ms` pre-attach settle delay — the shell maps a private libart and
inline-hooks it at startup, and that routine SEGVs if any concurrent JNI-thread-attach / ART access
happens while it runs; (2) gate KPM engagement off for pure-Dobby runs (the shpte KPM PTE-managing
the target's libart collides with the shell's own libart patching); (3) read multi-region dexes by
`file_size` (the app's dexes exceed a single VMA).

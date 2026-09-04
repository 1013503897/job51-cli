# 51job 请求签名 —— 从爱加密(Ijiami)抽取壳的内存脱壳恢复

目标是 `sign` 参数。App 被**爱加密(Ijiami)抽取壳**加固（入口类 `s.h.e.l.l.S`；指纹 `assets/ijiami.dat`、
`assets/ijm_lib/*/libexec.so`、`lib/*/libijm-emulator.so`、`libzxprotect.so`）。抽取壳把方法体从静态
DEX 里 nop 掉，但**抽取是惰性的**：被调用过的方法在运行期恢复进内存。签名链在 App 签任何请求时都会走到，
所以它们在内存里是完整方法体——root 读 `/proc/<pid>/mem` dump 出来即得，无需 ArtMethod 级 FART。

## 恢复路径（内存脱壳）

1. `su -c "grep 'dalvik-DEX data' /proc/<pid>/maps"` 列出全部 `[anon:dalvik-DEX data]` 区域（本例 496 个）。
2. 逐份从 `/proc/<pid>/mem` 按 header `file_size`（偏移 0x20）读全（多区域 dex 跨区连续读），裁尾、重算
   `signature`(data[0x20:]) 与 `checksum`(data[0x0c:])，打包成 zip → jadx 加载 **55054 个类**。
3. 签名类落在其中一份 dump dex（`full_6f9d1b1000.dex`），方法体完整：`EncryptAndSignUtil.doEncryptOrSign`
   439 条指令、`getRequestBodyAfter` 202 条、`getSignJsonDataFromMap` 52 条、`SignFor51.hmacSha256` 42 条，
   `insns_size` 都是实打实的方法体，没有一条是 nop 抽取桩。

> 没被调用过、仍是 nop 桩的方法（各种 `intercept` 等），要拿得靠 ArtMethod 级 FART（Vector 内建脱壳器的
> `dexfind`+`trigger`）——那是通用手段，签名不需要。见 [unpacking.md](unpacking.md)。

## 签名类

| 类 | 作用 |
|---|---|
| `com.jobs.network.EncryptAndSignUtil` | OkHttp 签名/加密拦截器（`doEncryptOrSign` / `getRequestBodyAfter`） |
| `com.jobs.network.EncryptAndSignUtil$SignKey` | per-host 密钥（enum） |
| `com.jobs.network.digest.SignFor51` | `hmacSha256` / `getSHA256` / `md5` 原语 |

## 算法（现代 cupid / young 站）

`EncryptAndSignUtil.getRequestBodyAfter`。注意拦截器顺序：`CommonParamInterceptor` **先**把公共 query
参数（partner / guid / uuid / clientid / apiversion …，来自 `NetWorkConfig.getCommonQueryParams()`）拼进
URL，`doEncryptOrSign` 在其**之后**跑，`url.substring(indexOf(host)+host.length())` 因此**连 query 串一起签**：

```
after_host = url.substring(url.indexOf(host) + host.length())   # "/path?partner=..&guid=..&.." 带前导 / 和 query
message    = after_host + getSignJsonDataFromMap(params)         # Gson JsonObject of body params
sign       = SignFor51.hmacSha256(key = signKey.getSignKey(), msg = message)  # HMAC-SHA256, 小写 hex
请求:       header "sign" = sign
            body = getSignJsonDataFromMap(params)（JSON）
```

`SignFor51.hmacSha256(p0, p1)`：`SecretKeySpec(p0.getBytes(UTF_8), "HmacSHA256")` = **key=p0**，
`mac.doFinal(p1.getBytes(UTF_8))` = **message=p1**，`toHexString` = `Formatter("%02x")` 小写 hex。
`getSignJsonDataFromMap` 遍历参数 `Map`（`LinkedHashMap` 保序），值 `String.valueOf` 转字符串，出紧凑 JSON。

`Client-Time` 是**另一个网关 header**（`CommonHeaderInterceptor.getCurrentTime`）：GMT+8 时区、分/秒/毫秒清零
（截到整点），`getTimeInMillis()/1000` → **秒级** epoch。它**不进 cupid 的 HMAC**。

> 实测边界：服务器会对收到的 URL（含 query）重算签名，所以真发一个被接受的请求，还需要设备侧真实的公共 query
> 参数（partner/guid/uuid/clientid/apiversion…，`getCommonQueryParams()` 是运行时配置，未离线捕获）；这些也在
> 签名范围内。算法本身已从源码核实。

### per-host 密钥（`SignKey.<clinit>`，App 内明文常量）

这些是 App 里写死的 HMAC 常量：每个安装一样、与账号无关、反编译 APK 即得，签名必需，直接列出。

| enum | 密钥 | 选站 |
|---|---|---|
| `V_API` | `8a9f1f198af70a41aec9fc7cf34b3456` | vapi / cupid / 默认 |
| `V_API_FOR_CAMPUS` | `9hnrejixqt4k4jt60rrl7w6ajyfv0t1k` | vapi 且 clientid=000013（校园） |
| `V_API_FOR_YJS` | `1960a9b25d8d4e16bcff6d5d7d82c2cb` | vapi 且 clientid=000004（yingjiesheng 应届） |
| `IM` | `w$mm0nIukwebctvH` | im.51job(app).com |
| `APP_API` | `44kC5ppqtNc8` | appapi.51job(app).com |
| `SIGH_KEY_XY` | `lhs3ayggr7fc00sjgskaupe6nrrlxod9tl1ct7hhdivvzdd2kj6hurj3fukhnt3r` | cupid/young 且 api_key==XY |
| `SIGN_KEY_51JOB` | （cupid / young 默认，值未捕获） | cupid / young 默认 |

`getSignKeyForHost(url)` 用 `host.hashCode()` 的 sparse-switch 选 key。签名 host（`isHostYoungOrCupidApi`
+ `isNeedSign` → VAPI/IM/AppApiV3/Young/Cupid）：`cupid.51job.com`、`cupid.51jobapp.com`、`vapi.51job.com`、
`vapi.51jobapp.com`、`appapi.51job.com`、`appapi.51jobapp.com`、`youngapi.51job.com`、
`youngapi.yingjiesheng.com`、`im.51job.com`、`im.51jobapp.com`。

## 遗留 appapi 路径（`signData`）

`sign = MD5( SHA256(prefix + data + signKey.getSignKey()).hex().getBytes() )`（老 .php / URLBuilder.appendRSign
一路；首页 cupid 不走这条）。

实现见 [`job51cli/client.py`](../job51cli/client.py)（`sign_cupid` / `sign_legacy`）。

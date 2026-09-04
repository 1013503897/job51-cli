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

### 公共 query 参数（`MyNetWorkConfig.getCommonQueryParams`）

`CommonParamInterceptor` 把这套参数拼进 URL（在签名之前），所以它们都在签名范围内。网关校验的**时间戳就是
其中的 `timestamp` query 参数**（不是 `Client-Time` header）：

```
key=<登录token，匿名为空>  api_key=51job  format=json  productname=51job
partner=<渠道>  uuid=<设备uuid>  version=16.15.0  accountid=<登录，匿名为空>
clientid=000007  privacy=1  distinct_id=<神策>  huihuaId=<统计>
timestamp=currentTimeMillis()/1000   ← 网关校的时间戳，当前秒级 epoch
frompageUrl=<...>  pageUrl=<...>
```

### per-host 密钥（`SignKey.<clinit>`，App 内明文常量）

App 里写死的 HMAC 常量：每个安装一样、与账号无关、反编译即得，直接列出。

| enum | 密钥 | 选站（`getSignKeyForHost`） |
|---|---|---|
| `V_API` | `8a9f1f198af70a41aec9fc7cf34b3456` | vapi 默认 / 其它未列 host |
| `V_API_FOR_CAMPUS` | `9hnrejixqt4k4jt60rrl7w6ajyfv0t1k` | vapi 且 clientid=000013 |
| `V_API_FOR_YJS` | `1960a9b25d8d4e16bcff6d5d7d82c2cb` | vapi 且 clientid=000004 |
| `IM` | `w$mm0nIukwebctvH` | im.51job(app).com |
| `APP_API` | `44kC5ppqtNc8` | appapi.51job(app).com |
| `SIGH_KEY_XY` | `lhs3ayggr7fc00sjgskaupe6nrrlxod9tl1ct7hhdivvzdd2kj6hurj3fukhnt3r` | cupid/young 且 `api_key=="xy"` |
| `SIGN_KEY_51JOB` | `abfc8f9dcf8c3f3d8aa294ac5f2cf2cc7767e5592590f39c3f503271dd68562b` | **cupid / young 默认** |

`getSignKeyForHost(url)` 按 host 的 switch 选 key，读 URL 的 `api_key` / `clientid` query 参数：cupid/youngapi →
`api_key=="xy" ? SIGH_KEY_XY : SIGN_KEY_51JOB`；vapi → clientid `000013`→CAMPUS、`000004`→YJS、否则 V_API；
appapi→APP_API；im→IM；其它→V_API。App 的 `api_key = BuildConfig.productName = "51job"`，故首页 cupid 走 **SIGN_KEY_51JOB**。

### 实测验证（cupid.51job.com，2026-09-04）

用上述算法 + `SIGN_KEY_51JOB` + 全套公共 query 参数，对线上打真请求：

- **逐字节匹配抓包**：mitmproxy 抓到 App 一条真实 `open/index/notice-infos` 请求（`sign` 头
  `89333aa6…f3e5`）。对它的 `url.substring(after host)`（GET 无 body）用 `SIGN_KEY_51JOB` 重算 HMAC，
  **结果 == App 发出的 sign，逐字节相同**。GET 的 message 就是 `after_host`；POST 再接 body JSON。
- **差分**：正确签名 → 过网关+签名到业务层（`common-switch` 返 HTTP 200）；**故意改一位签名 →
  `{"status":"110011","message":"鉴权失败，签名错误"}`**。
- **取到真实职位**：用签名打免登录 `open/noauth/gold-two-silver-three/search-job-list`，返回
  `{"status":"1","message":"成功"}`，`resultbody.job.items` 是真实岗位（职位名/城市/标签）。随机 `uuid`/`partner`
  也返回——该接口只校签名。`python -m job51cli java` 即可复现。
- `job-search`（登录版）→ `110104 user-token 不能为空`（签名过，仅差登录态）。

签名/密钥/请求构造已被服务器接受、端到端验证通过。（部分端点回 `100000/100012 网络超时`，是抓包代理链路到后端的超时，与请求无关。）

## 遗留 appapi 路径（`signData`）

`sign = MD5( SHA256(prefix + data + signKey.getSignKey()).hex().getBytes() )`（老 .php / URLBuilder.appendRSign
一路；首页 cupid 不走这条）。

实现见 [`job51cli/client.py`](../job51cli/client.py)（`sign_cupid` / `sign_legacy`）。

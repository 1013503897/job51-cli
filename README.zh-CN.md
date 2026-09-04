# job51-cli

[English](README.md) | **中文**

**前程无忧 51job（com.job.android）** API 的逆向研究客户端：把请求签名 `sign` 逆向恢复，并用纯 Python 复现。

> 研究 / 学习项目。该 App 用**爱加密（Ijiami）抽取壳**加固。通过 root 读 `/proc/<pid>/mem` 从内存脱壳
> （重组出 16 个 DEX / 55054 个类），恢复出 **API 结构** 与 **签名算法**。签名已**线上实测验证**：对一条真实
> 抓包请求重算，结果与 App 发出的 `sign` 头**逐字节相同**；`python -m job51cli java` 免登录即可从公开接口拉取
> 真实岗位。详见 [`docs/unpacking.md`](docs/unpacking.md) 与 [`docs/sign.md`](docs/sign.md)。

## 恢复了什么

- **签名** —— `sign = HMAC_SHA256(perHostKey, afterHost + gsonJson(bodyParams))`，小写 hex，放 `sign`
  请求头。`afterHost` 是 URL 里 host 之后的整段——**path 与 query 串都算**，因为公共 query 参数在签名前已拼进
  URL。`Client-Time` 是另一个网关头（GMT+8 整点**秒**级 epoch），**不进 HMAC**。另有两条路径
  （`signData = MD5(SHA256(...))` 与 appapi 的 `CQEncrypt`）。来源类：
  `EncryptAndSignUtil` / `EncryptAndSignUtil$SignKey` / `SignFor51` / `CommonParamInterceptor`。
  实现见 [`job51cli/client.py`](job51cli/client.py)（`sign_cupid` / `sign_legacy`）。
- **Host** —— 老接口 `https://appapi.51job.com/api/2|3/*.php` 与现代 REST
  `https://cupid.51job.com/open/*`，外加 `aceapi` / `51gpt` / `app`。
- **554 个端点** —— [`docs/endpoints_full.txt`](docs/endpoints_full.txt)。如职位搜索
  `open/good-job-tab/search-new-job-list`、发短信 `open/noauth/sms/send-sms-verification-code`。
- **公共参数 / 鉴权** —— `partner` / `guid` / `uuid` / `device` / `version` / `timestamp` + `sign`，
  以及 Authorization / access-token 头。

## 为什么签名不需要 FART

抽取壳的抽取是**惰性**的：**运行期被调用过**的方法才恢复进内存，没调用的仍是 nop 桩。`EncryptAndSignUtil`
/ `SignFor51` 在 App 每次签名时都会走到，所以它们在 `/proc/mem` dump 里是完整方法体（`insns_size` 31–439），
直接可反汇编。ArtMethod 级 FART（Vector 脱壳器的 `dexfind`+`trigger`）是拿那些始终 nop 的方法的通用手段，
签名用不到。详见 `docs/`。

## 签名密钥

全部 7 个 per-host `EncryptAndSignUtil$SignKey`（含 cupid/young 默认的 `SIGN_KEY_51JOB`）都是 **App 内写死
的 HMAC 常量**——每个安装一样、与账号无关、反编译 APK 即得。签名是防篡改 HMAC、不是鉴权，所以密钥直接内置在
[`job51cli/client.py`](job51cli/client.py) 里；`sign_key_for(host, api_key, clientid)` 复刻 `getSignKeyForHost`。

## 运行

```bash
pip install requests
python tests/test_sign.py                # 离线：原语 + 签名形态（5/5）
python -m job51cli java 010000           # 线上：拉真实 51job 岗位，免登录
python -m job51cli detail 173534695      # 线上：完整职位详情（描述/公司/薪资/HR）
```

`python -m job51cli <关键词> [城市码]` 会对免登录的公开职位搜索接口签名并打印真实岗位（`resultbody.job.items`，
每条带 职位名 / 薪资 / 公司 / HR / 经验）——例如 `java`：

```
[173534695] Java开发工程师  |  1-1.8万  |  深圳·龙华区
    深圳市新佳邮科技物流有限公司  (民营 150-500人)  |  2年及以上 本科
```

无需登录、无需真实设备值——免登录接口只校验签名，随机 `uuid` / `partner` 也能取到。编程接口：
`Job51Client().search_jobs(keyword, jobarea)` 与 `Job51Client().job_detail(job_id)`（返回
`detailJobInfo`——描述、公司、薪资、HR、地址）。免账号即可拿到大量数据。

### 登录（本项目范围外）

登录态接口（`job_search` 的个性化结果、投递、简历等）需要 `user-token`。登录是
`POST open/noauth/login/loginbyphone`（form `nationCode`/`mobile`/`phoneCode` → `LoginInfo.token`），
短信码来自 `sendPhoneCodeWithGeetest`——即被 **Geetest 验证码 + 短信 OTP** 挡着，且首次登录**自动注册账号**。
本客户端只走免登录接口（已能搜索 + 完整详情）；要用登录态，把你自己的 `user-token` 放进 `session['access_token']`。

## 目录结构

```
job51cli/api.py       host + 关键端点
job51cli/client.py    签名（sign_cupid / sign_legacy）+ 带签请求客户端
docs/sign.md          签名算法 + 恢复过程
docs/unpacking.md     s.h.e.l.l 壳如何从 /proc/<pid>/mem 内存脱壳
docs/endpoints_full.txt   从脱壳 DEX 里恢复的 554 个端点
```

逆向自 `com.job.android` v16.15.0。

## 免责声明

仅供安全研究与学习。请勿以任何违反 51job 服务条款或适用法律的方式使用；使用后果自负。

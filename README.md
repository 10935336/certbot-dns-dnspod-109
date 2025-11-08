[English](#english) | [简体中文](#%E7%AE%80%E4%BD%93%E4%B8%AD%E6%96%87)


# English


## Just Another DNSPod DNS Authenticator plugin for Certbot
The `certbot-dns-dnspod-109` plugin automates the process of
completing a `dns-01` challenge (`~acme.challenges.DNS01`)
by creating, and subsequently removing, TXT records using the
Dnspod API (Tencent Cloud API 3.0).

If you are using [Dnspod](https://www.dnspod.cn/) ([Tencent Cloud](https://cloud.tencent.com)) as your DNS provider,
then this is your plugin.


Tested on
- Certbot 3.0.1
- Certbot 5.1.0


## Usage

### 1. Install

#### pip:
```bash
pip install certbot-dns-dnspod-109
```
or
```bash
pip install git+https://github.com/10935336/certbot-dns-dnspod-109.git
```


#### snap:
```bash
snap install certbot-dns-dnspod-10935336
snap set certbot trust-plugin-with-root=ok
snap connect certbot:plugin certbot-dns-dnspod-10935336
```

### 2. Obtain SecretId and SecretKey
1. Visit https://console.cloud.tencent.com/cam to create a sub-user
2. Select "Programmatic access" for the sub-user access method
3. Grant the sub-user QcloudDNSPodFullAccess (Cloud DNS full read and write access rights) permission
4. Record SecretId and SecretKey

### 3. Prepare Credentials File

foobar.ini:
```ini
dns_dnspod_109_secret_id=foo
dns_dnspod_109_secret_key=bar
```

### 4. Ready to go

#### Usage Examples

To acquire a certificate for `example.com`

```bash
certbot certonly \
  -a dns-dnspod-109 \
  --dns-dnspod-109-credentials ~/.secrets/certbot/dnspod-109.ini \
  -d example.com
```

To acquire a single certificate for both example.com and www.example.com
```bash
certbot certonly \
  -a dns-dnspod-109 \
  --dns-dnspod-109-credentials ~/.secrets/certbot/dnspod-109.ini \
  -d example.com \
  -d www.example.com
```

To acquire a certificate for example.com, waiting 60 seconds for DNS propagation
```bash
certbot certonly \
  -a dns-dnspod-109 \
  --dns-dnspod-109-credentials ~/.secrets/certbot/dnspod-109.ini \
  --dns-dnspod-109-propagation-seconds 60 \
  -d example.com
```

Test run
```bash
certbot certonly \
  --register-unsafely-without-email \
  -a dns-dnspod-109 \
  --dns-dnspod-109-credentials ~/.secrets/certbot/dnspod-109.ini \
  --dns-dnspod-109-propagation-seconds 60 \
  -v \
  --dry-run
```

## Parameter Description
``--dns-dnspod-109-credentials <path>`` points to the credentials file. (Required)

``--dns-dnspod-109-propagation-seconds`` The number of seconds to wait for DNS propagation before asking the ACME server to verify DNS records. If DNS records appear to be added successfully but verification fails, try increasing this value. (Default: 10)




<br>
<br>
<br>
<br>
<br>

# 简体中文

## 只是另一个适用于 Certbot 的 DNSPod DNS Authenticator 插件

`certbot-dns-dnspod-109` 插件通过使用 Dnspod API（腾讯云 API 3.0）创建并随后删除 TXT 记录，自动完成`dns-01` 质询（`~acme.challenges.DNS01`）。

如果你使用 [Dnspod](https://www.dnspod.cn/) ([腾讯云](https://cloud.tencent.com)) 作为你的域名解析服务提供商，那么这就是你的插件。

在以下版本中测试通过
- Certbot 3.0.1
- Certbot 5.1.0

## 使用方法

### 1. 安装

#### pip:
```bash
pip install certbot-dns-dnspod-109
```
或者
```bash
pip install git+https://github.com/10935336/certbot-dns-dnspod-109.git
```

#### snap:
```bash
snap install certbot-dns-dnspod-10935336
snap set certbot trust-plugin-with-root=ok
snap connect certbot:plugin certbot-dns-dnspod-10935336
```

### 2. 获取 SecretId 和 SecretKey
1. 访问 https://console.cloud.tencent.com/cam 创建子用户
2. 子用户访问方式选择“编程访问”
3. 授予子用户 QcloudDNSPodFullAccess（Cloud DNS 完全读写访问权限）权限
4. 记录 SecretId 和 SecretKey

### 3. 准备凭证文件

foobar.ini:
```ini
dns_dnspod_109_secret_id=foo
dns_dnspod_109_secret_key=bar
```

### 4. 准备就绪

#### 使用示例

获取 `example.com` 的证书

```bash
certbot certonly \
-a dns-dnspod-109 \
--dns-dnspod-109-credentials ~/.secrets/certbot/dnspod-109.ini \
-d example.com
```

获取同时有 `example.com` 和 `www.example.com` 的单个证书
```bash
certbot certonly \
-a dns-dnspod-109 \
--dns-dnspod-109-credentials ~/.secrets/certbot/dnspod-109.ini \
-d example.com \
-d www.example.com
```

获取 `example.com` 的证书，但设置等待 60 秒（等待 DNS 传播）
```bash
certbot certonly \
-a dns-dnspod-109 \
--dns-dnspod-109-credentials ~/.secrets/certbot/dnspod-109.ini \
--dns-dnspod-109-propagation-seconds 60 \
-d example.com
```

测试运行
```bash
certbot certonly \
  --register-unsafely-without-email \
  -a dns-dnspod-109 \
  --dns-dnspod-109-credentials ~/.secrets/certbot/dnspod-109.ini \
  --dns-dnspod-109-propagation-seconds 60 \
  -v \
  --dry-run
```

## 参数说明
``--dns-dnspod-109-credentials <路径>`` 指向凭证文件。（必需）

``--dns-dnspod-109-propagation-seconds`` 在要求 ACME 服务器验证 DNS 记录之前等待 DNS 传播的秒数。如果显示 DNS 记录添加成功但验证失败，则尝试增加此值 。 （默认值：10）


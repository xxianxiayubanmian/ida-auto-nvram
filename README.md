# nvram_fake

`nvram_fake.py` 是一个 IDA Python 插件，用于自动分析路由器 / IoT 固件中的 NVRAM 配置项，并自动生成 `nvram.ini` 和 `nvram_fake.c`。

它适合用于固件仿真、漏洞复现、Web 服务启动、缺失 `libnvram.so` 时的环境补全等场景。

---

## 功能特性

- IDA 插件菜单一键运行
- 自动扫描 NVRAM 相关 API 调用
- 自动提取常见配置 key
- 自动生成 `nvram.ini`
- 自动生成 fake `libnvram` 源码 `nvram_fake.c`
- 自动生成分析报告和 JSON 结果

支持识别的常见 API 包括：

```text
nvram_get
nvram_bufget
nvram_set
nvram_bufset
nvram_commit
nvram_init
nvram_getall
nvram_match
nvram_invmatch
acosNvramConfig_get
acosNvramConfig_set
bcm_nvram_get
bcm_nvram_set
tcapi_get
tcapi_set
uci_get
uci_set
xmldbc_get
xmldbc_set
```

---

## 默认值策略

脚本会自动对部分关键字段设置适合仿真的默认值。

账号、密码、用户名类字段统一设置为：

```ini
admin
```

例如：

```ini
Login=admin
Password=admin
username=admin
password=admin
passwd=admin
admin_password=admin
```

LAN IP 类字段统一设置为：

```ini
192.168.10.200
```

例如：

```ini
lan_ipaddr=192.168.10.200
lan_ip=192.168.10.200
lan_ip_addr=192.168.10.200
lan_ipaddress=192.168.10.200
```

---

## 安装方法

将 `nvram_fake.py` 复制到 IDA 插件目录。

### Windows

```text
%APPDATA%\Hex-Rays\IDA Pro\plugins\nvram_fake.py
```

例如：

```text
C:\Users\<username>\AppData\Roaming\Hex-Rays\IDA Pro\plugins\nvram_fake.py
```

### Linux

```text
~/.idapro/plugins/nvram_fake.py
```

### macOS

```text
~/.idapro/plugins/nvram_fake.py
```

复制完成后，重启 IDA。

---

## 使用方法

1. 使用 IDA 打开固件中的目标二进制文件，例如：

```text
goahead
httpd
boa
uhttpd
cgi
```

2. 等待 IDA 自动分析完成。

3. 点击菜单：

```text
Edit -> Plugins -> nvram_fake
```

4. 插件运行完成后，会在目标二进制所在目录生成结果文件。

---

## 输出文件

假设当前分析的文件是：

```text
goahead
```

插件会生成：

```text
当前二进制目录/
├── nvram.ini
├── nvram_fake.c
└── goahead_nvram_auto/
    ├── nvram.ini
    ├── nvram_fake.c
    ├── nvram_all_kv.ini
    ├── nvram_findings.json
    └── nvram_report.txt
```

文件说明：

| 文件 | 说明 |
|---|---|
| `nvram.ini` | 自动生成的 NVRAM 配置文件 |
| `nvram_fake.c` | fake libnvram 源码 |
| `nvram_all_kv.ini` | 低置信度 key=value 结果 |
| `nvram_findings.json` | 结构化分析结果 |
| `nvram_report.txt` | 人工可读分析报告 |

---

## 编译 nvram_fake.c

### 本机测试

```bash
gcc -shared -fPIC -O2 -o libnvram.so.0 nvram_fake.c
```

### MIPS 小端固件

```bash
mipsel-linux-uclibc-gcc -shared -fPIC -O2 -o libnvram.so.0 nvram_fake.c
```

### ARM 固件

```bash
arm-linux-gnueabi-gcc -shared -fPIC -O2 -o libnvram.so.0 nvram_fake.c
```

---

## 运行目标程序

```bash
export NVRAM_FAKE_INI=/path/to/nvram.ini
LD_PRELOAD=./libnvram.so.0 ./goahead
```

如果程序默认在当前目录读取 `nvram.ini`，也可以直接：

```bash
LD_PRELOAD=./libnvram.so.0 ./goahead
```

---

## 命令行运行 IDA 分析

也可以通过 IDA 命令行自动运行：

```bash
ida64 -A -Snvram_fake.py ./goahead
```

或 32 位 IDA：

```bash
ida -A -Snvram_fake.py ./goahead
```

---

## 注意事项

- 建议等待 IDA 自动分析完成后再运行插件。
- 如果生成的 `nvram.ini` 不完整，可以查看 `nvram_all_kv.ini` 和 `nvram_report.txt`。
- 不同厂商固件的 NVRAM API 形式不同，脚本会尽量兼容常见调用方式。
- 生成的配置主要用于固件仿真和漏洞复现，不保证完全等价于真实设备 NVRAM。


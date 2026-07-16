# CVE Hunter 网络拓扑

## 整体架构

```
你的电脑 (192.168.124.36)          210.45.123.115                   1.1.60.21
┌──────────────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│ CVE Hunter               │ PoC  │ http2pcap (引擎)  │ HTTP │ IPS 设备         │
│                          │─────▶│ :3012             │─────▶│ (防火墙/检测)    │
│                          │      │                  │      │                  │
│  ┌────────────────────┐  │      │ IPS API           │ 查日志│                  │
│  │ Vulhub Docker      │  │      │ :3013             │◀─────│                  │
│  │ aiohttp 3.9.1      │◀─┼──────┼──────────────────┼──转发─│                  │
│  │ localhost:8080     │  │      │                  │      │                  │
│  └────────────────────┘  │      └──────────────────┘      └──────────────────┘
└──────────────────────────┘
```

## 各节点说明

| 地址 | 角色 | 说明 |
|------|------|------|
| 你的本机 | CVE Hunter + Docker 靶场 | 运行 CVE Hunter 工作流，同时用 Docker 跑 vulhub 漏洞容器 |
| 210.45.123.115 | http2pcap / IPS API | 远程发包引擎和 IPS 日志查询接口 |
| 1.1.60.21 | IPS 检测设备 | 流量必经点，检测恶意请求并生成日志记录 |

## PoC 请求流转路径

### 第一步：提交 PoC
CVE Hunter 将 PoC 请求（raw HTTP 或 nuclei yaml）发送到 http2pcap 服务：
```
POST http://210.45.123.115:3012/
```

### 第二步：发包
http2pcap 根据 PoC 内容构造 HTTP 请求，目标地址为 **ATTACK_ENV_TARGET_URL**（当前 `http://1.1.60.21`）。

### 第三步：IPS 检测
请求到达 `1.1.60.21`（IPS 设备），IPS 引擎：
1. 检测请求内容，匹配 CVE 特征
2. 记录检测日志（包含 CVE 编号）
3. 转发请求到后端靶场服务

### 第四步：查询 IPS 日志
CVE Hunter 向 IPS API 查询命中结果：
```
POST http://210.45.123.115:3013/api/cve-match
```
如果返回的日志中 CVE 字段匹配 `CVE-2024-23334`，判定为 **验证成功**。

## 关键配置说明

### ATTACK_ENV_TARGET_URL 不能改

```ini
ATTACK_ENV_TARGET_URL=http://1.1.60.21
```

**这是 PoC 请求流经 IPS 的唯一路径。** 如果改为 `127.0.0.1:8080`，流量不会经过 IPS，等于绕过检测，"作弊"式验证。

### AUTO_ENV_ENABLED 控制 Docker 拉起

```ini
AUTO_ENV_ENABLED=true
```

开启后，系统自动执行 `docker compose pull && up -d`，漏洞容器在本地运行。容器提供靶场服务，但 **PoC 攻击流量仍走 IPS 路径**，不受影响。

### 两者关系

```
AUTO_ENV_ENABLED=true  →  负责让靶场"活"（本地 Docker 容器运行）
                            ↓
ATTACK_ENV_TARGET_URL   →  负责让攻击"经过 IPS"（http2pcap → IPS → 转发到你的 Docker）
```

两者各司其职，不互相冲突。

## 复现成功的必要条件

1. Docker Desktop 运行正常，容器启动成功（本地 8080 端口有 aiohttp 监听）
2. 实验室网络连通（你的电脑能访问 210.45.123.115）
3. IPS 设备转发规则正确（`1.1.60.21:8080` → 你的电脑 `192.168.124.36:8080`）
4. IPS 检测规则包含 CVE-2024-23334 特征

## 验证成功的标志

- IPS API 返回日志中 `cve` 字段值为 `CVE-2024-23334`
- Workflow 状态变为 `SUCCESS / CAPTURE_SUCCESS`

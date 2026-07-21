# Docker 数据迁移到 F 盘方案

生成日期：2026-07-20  
原因：D 盘已约 **99% 满**（~2.3GB 可用），Docker 数据约 **65GB** 在 `D:\Docker\data`；C 盘也紧（~19GB 可用）。**F 盘约 107GB 可用**，适合承接镜像层。

## 1. 现状

| 项 | 路径/数值 |
|---|---|
| WSL 数据目录 | `D:\Docker\data`（`CustomWslDistroDir`） |
| 关键文件 | `D:\Docker\data\disk\docker_data.vhdx`（~65GB） |
| DataFolder | `D:\Docker\hyper-v` |
| C: | **禁止**作为 Docker 数据盘 |
| 目标 | `F:\Docker\data` + `F:\Docker\hyper-v` |

## 2. 迁移步骤（推荐）

### 2.1 准备

1. **停止继续 `docker pull`**（已因 D 盘满需要停止）。  
2. 完全退出 Docker Desktop：托盘图标 → **Quit Docker Desktop**。  
3. 确认 F 盘可用空间 **> 80GB**（数据 ~65GB + 余量）。

### 2.2 一键脚本（推荐）

```powershell
# 在「已退出 Docker」后执行
powershell -ExecutionPolicy Bypass -File F:\wangyi_0\tools\migrate_docker_data_to_f.ps1
```

脚本会：

1. `wsl --shutdown`  
2. `robocopy D:\Docker\data -> F:\Docker\data`  
3. 同步 `hyper-v` 目录（若有）  
4. 备份并改写 `%APPDATA%\Docker\settings-store.json`：  
   - `CustomWslDistroDir = F:\Docker\data`  
   - `DataFolder = F:\Docker\hyper-v`  
5. **不会自动删除 D:\ 旧数据**（验证成功后再删）

日志：`output/queue/docker_migrate_to_f.log`

### 2.3 手工等价步骤

```text
1. Quit Docker Desktop
2. wsl --shutdown
3. mkdir F:\Docker\data F:\Docker\hyper-v
4. robocopy D:\Docker\data F:\Docker\data /E /COPY:DAT /R:2 /W:5 /MT:8
5. 编辑 %APPDATA%\Docker\settings-store.json
   CustomWslDistroDir -> F:\Docker\data
   DataFolder         -> F:\Docker\hyper-v
6. 启动 Docker Desktop
7. docker images / docker run hello-world 验证
8. 确认无误后删除 D:\Docker\data 释放 D 盘
```

## 3. 验证清单

```bash
docker info
docker images
# 抽查已有成功环境
python main.py CVE-2012-2122 --local-container
```

设置复查：

```text
%APPDATA%\Docker\settings-store.json
  CustomWslDistroDir = F:\Docker\data
```

## 4. 风险与注意

| 风险 | 处理 |
|---|---|
| 迁移中 Docker 仍在运行 | 必须先 Quit + wsl --shutdown，否则 vhdx 锁死/损坏 |
| 复制中断 | 可重跑 robocopy；成功前不要删 D:\ |
| 路径写错回 C | 迁移脚本只写 F:\；禁止改到 C:\Users\...\Docker |
| D 盘旧数据 | 验证通过后再删，可先改名 `D:\Docker\data.bak` |

## 5. 迁移完成后的环境下载策略

1. 确认 Docker 使用 F 盘后，继续：  
   `python tools/inventory_and_pull_images.py --pull --limit 20`  
2. DB 相关已 17/17 拉完；后续分批 A/B，避免一次拉爆磁盘。  
3. 蓝图 §9.6 存储约束改为 **F:\Docker\data**。

## 6. 与项目的关系

- 镜像层在 Docker 数据目录，**不会**写到 `F:\wangyi_0` 仓库树内。  
- 清单/日志仍在 `F:\wangyi_0\output\queue\`。  
- C 盘始终不作为 data-root。

## 7. 执行记录（2026-07-20）

| 步骤 | 结果 |
|---|---|
| 退出 Docker / `wsl --shutdown` | 完成 |
| `robocopy D:\Docker\data → F:\Docker\data` | 完成（`docker_data.vhdx` ~65GB） |
| 修改 `settings-store.json` | `CustomWslDistroDir=F:\Docker\data`，`DataFolder=F:\Docker\hyper-v` |
| 启动 Docker Desktop | 完成（路径 `D:\Docker\DockerDesktop\Docker Desktop.exe`） |
| `docker images` | 可见约 88 个标签，含 vulhub/postgres、mysql、redis 等 |
| D:\ 旧数据 | **仍保留**（约 65GB）；确认无误后请手动删除 `D:\Docker\data` 释放 D 盘 |
| 当前磁盘 | C~19GB 可用；D~7GB 可用；F~42GB 可用（承接数据后） |

**注意：** 后续 `docker pull` 将写入 **F:\Docker\data**，不再写入 C:。

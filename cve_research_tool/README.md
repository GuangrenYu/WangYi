# CVE 参考信息调查工具

独立于主程序的批量调查工具，用来读取 `待补充cve.xlsx`，查询 CVE 参考信息数量，汇总可用信息，并按信息量排序分类。

## 默认行为

- 默认输入：`F:\wangyi_0\待补充cve.xlsx`
- 默认只处理 `工作流是否已生成` 不是 `是` 的 CVE
- 默认数据源：NVD、CVE.org、FIRST EPSS、CISA KEV、本地 PoC KB、nuclei
- 默认输出目录：`cve_research_tool\output`
- 每个 CVE 的查询记录会保存到 `output\records\CVE-*.json`，下次运行可断点续查

## 直接运行

在项目根目录执行：

```powershell
python .\cve_research_tool\cve_research.py
```

先试跑 20 个：

```powershell
python .\cve_research_tool\cve_research.py --limit 20 --delay 0
```

包含已经生成过工作流的 CVE：

```powershell
python .\cve_research_tool\cve_research.py --include-generated
```

启用深度源，包括 Exploit-DB、imfht、Web 搜索：

```powershell
python .\cve_research_tool\cve_research.py --deep
```

强制重新查询，忽略缓存：

```powershell
python .\cve_research_tool\cve_research.py --refresh
```

## 输出文件

每次运行会生成：

- `cve_research_时间戳.xlsx`
- `cve_research_时间戳.csv`
- `cve_research_时间戳.jsonl`
- `cve_research_latest.xlsx`
- `cve_research_latest.csv`

XLSX 里有四个工作表：

- `排序汇总`：按信息评分降序排列
- `分类统计`：按分类和建议动作统计
- `参考链接明细`：每条去重后的参考链接
- `查询错误`：每个 CVE 的源查询错误

## 分类逻辑

工具按描述、去重参考链接数、命中来源数、PoC 线索、本地 KB、nuclei、Exploit-DB 等计算 `信息评分`，并分为：

- `A_信息丰富`
- `B_信息中等`
- `C_信息较少`
- `D_信息稀少`
- `E_查询失败或空白`

`优先级评分` 会额外考虑 CVSS、EPSS、CISA KEV 和 PoC 线索，方便后续安排人工调查顺序。


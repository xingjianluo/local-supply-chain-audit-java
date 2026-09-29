# 本地依赖清单与漏洞风险审计服务

一个完全本地运行的依赖清单归一化 + 漏洞风险审计服务。输入本机的多工程模块依赖清单与本地漏洞库，
输出可追溯的扫描结论。**全程不接外网、不依赖数据库或任何外部服务**（漏洞匹配、解析、状态管理均在进程内完成）。

## 1. 功能概览

- 多模块、多格式清单归一为统一的 `组件坐标 (ecosystem, group, name) + 版本 + 引用模块` 模型。
- 重复引用、同一组件多版本、字段缺失、清单损坏、空清单、不支持格式、文件不可读等情形
  都有**明确且可区分的结论类型（ParseIssueType）**，绝不静默跳过；单个坏文件只影响该模块，
  不会让整次扫描失败。
- 多次扫描状态管理：同一时刻最多一个扫描在运行（单飞）；重复提交得到 409 冲突并返回正在运行的 scanId；
  扫描可协作式取消，取消后不发布半成品结论，槽位释放后可立即开始下一次扫描；
  所有对外状态均为不可变快照，并发提交 / 读取 / 取消互不串扰。
- 扫描结论与**当时使用的漏洞库版本绑定**（快照中带 `vulnLibraryId` / `vulnLibraryVersion`）：
  漏洞库更新后用新库重扫会得到新结论；历史快照保持不变，可按当时库版本复现。
- 同一组件被多个模块引用、或存在多版本时，漏洞风险按 `(ruleId, 坐标)` 合并去重为一条 Finding，
  聚合受影响版本与引用模块集合。
- 大清单友好：npm 清单与漏洞库均使用 Jackson **流式解析**，requirements 按行处理，
  扫描线程为独立单线程、历史有界（默认 10 条），单快照组件明细默认最多保留 10 万条
  （组件总数统计准确、findings/issues 完整，超量给 `COMPONENT_LIST_TRUNCATED` 结论），
  不阻塞 HTTP 接口、不出现整树读入与历史累积式的内存暴涨。

## 2. 清单兼容范围

| 格式 | 生态 | 取值方式 | 主要约定 |
| --- | --- | --- | --- |
| Maven `pom.xml` | maven | 显式 `format` / 文件名 / `<project` 嗅探 | 解析 `dependencies` 与 `dependencyManagement`；支持 `${project.version}`、`${project.groupId}`、pom properties 占位符；parent GAV 回退；离线模式下不解析远程 parent / BOM import，落地不了的版本记为 FIELD_MISSING |
| npm `package-lock.json` | npm | 显式 / 文件名 / `lockfileVersion` 嗅探 | 支持 lockfileVersion 2/3 的 `packages` 表（scoped 包、`node_modules` 嵌套提升）与 v1 嵌套 `dependencies`；根节点 `""` 与 `link=true` 的 workspace 链接不计入第三方依赖 |
| pip `requirements.txt` | pypi | 显式 / 文件名 / PEP508 风格行嗅探 | 注释空行跳过；剥离 extras 与环境标记；PEP440 常见操作符；名称按 PEP503 归一（小写、`._-` 归一为 `-`）；`-r/-e/--index-url` 选项行与无固定版本条目形成可区分结论 |

模块输入字段：

```json
{
  "module": "模块名（缺省时用 module-序号）",
  "path": "本机清单文件的绝对/相对路径（与 content 二选一或同时提供，content 优先）",
  "content": "清单文本内容（直接内联）",
  "format": "POM_XML | PACKAGE_LOCK_JSON | REQUIREMENTS_TXT（可空，按文件名/内容探测）"
}
```

解析结论类型 `ParseIssueType`：

- `MALFORMED_MANIFEST`：清单整体损坏（非法 XML/JSON、无法识别的行）。
- `FIELD_MISSING`：条目缺 name/version、link 包无版本、范围版本未固定、BOM import 不解析等。
- `EMPTY_MANIFEST`：清单可解析但无任何有效依赖。
- `UNSUPPORTED_FORMAT`：无法识别或未注册的格式。
- `UNREADABLE_SOURCE`：本地路径不存在 / 不可读 / 读取失败。
- `DUPLICATE_REFERENCE`：同模块内完全重复条目去重；跨模块共享同一组件的汇总说明。
- `MULTIPLE_VERSIONS`：同组件出现多个不同版本（模块内与跨模块分别给出），各版本分别参与漏洞判定。
- `MISSING_SOURCE`：模块既没给 path 也没给 content。
- `COMPONENT_LIST_TRUNCATED`：合并组件超过快照明细上限（默认 10 万），仅截断 components 明细，
  componentCount 总数与 findings/issues 完整保留。

## 3. 扫描状态约定

状态机：`RUNNING -> COMPLETED | CANCELLED | FAILED`。

- 提交后立即返回 `202 Accepted` 与一条 `RUNNING` 不可变快照；同一时刻已有 RUNNING 扫描时返回
  `409 Conflict`，body 形如：

  ```json
  {"code":"SCAN_ALREADY_RUNNING","message":"...","activeScanId":"<正在运行的 scanId>"}
  ```

- 取消为**协作式**：置取消标记并中断扫描线程，引擎在每个模块边界与批次检查点
  （`audit.cancel-batch-size`）感知；取消的扫描发布 `CANCELLED` 终态，
  `components/findings` 为空（不发布半成品），管理器等待执行线程退出后才释放单飞槽位
  （最长等待 `audit.cancel-await-millis`），因此取消不影响下一次扫描。
- `FAILED` 仅用于整体性错误（如漏洞库不可用）；模块级问题永远是该模块的 issue 而非扫描失败。
- 历史按提交顺序有界保留（`audit.history-limit`，默认 10，超出淘汰最旧），
  快照对象一旦发布不再变化，读写用锁 + 不可变集合隔离。
- 单快照组件明细默认最多保留 10 万条（`audit.max-components-in-snapshot`，0/负数为不限）：
  `componentCount` 仍为组件总数，findings/issues 完整，超量只截断 `components` 明细并给
  `COMPONENT_LIST_TRUNCATED` 结论，为大清单与多轮历史的内存占用封顶。

## 4. 漏洞库版本关联方式

漏洞库为本机 UTF-8 JSON 文件（样例：`samples/vuln-db.json`）：

```json
{
  "id": "local-vuln-db",
  "version": "2026.09.30",
  "rules": [
    {
      "id": "CVE-2020-8203",
      "ecosystem": "npm",
      "group": "",
      "name": "lodash",
      "rangeLow": "4.0.0",
      "rangeHigh": "4.17.20",
      "fixedIn": "4.17.20",
      "title": "Prototype Pollution in lodash",
      "severity": "high"
    }
  ]
}
```

- 区间为**左闭右开** `[rangeLow, rangeHigh)`，任一端为空表示不限制；
  版本比较为数字段按数值 + 常见限定符（alpha/beta/rc/snapshot/ga）排序。
- 库的 `id/version` 由文件内容声明，缺失或 JSON 损坏会得到明确的 `VulnLibraryLoadException`，
  扫描以 `FAILED` + 可区分错误信息结束。
- 每次扫描在开始时加载并锁定一个库版本，快照与 Finding 永久绑定该版本；
  更新库文件后重新提交扫描即可得到新结论，旧快照仍可通过 scanId 按旧版本复现。
- 库路径解析：请求体 `vulnLibraryPath` 优先，否则使用 `audit.vuln-library-path`。

## 5. HTTP 接口

| 方法与路径 | 说明 | 关键状态码 |
| --- | --- | --- |
| `POST /api/scans` | 提交扫描 | 202 已接受 / 409 已有扫描运行 / 400 请求非法 |
| `GET /api/scans/{scanId}` | 查询某次扫描快照（含历史） | 200 / 404 |
| `GET /api/scans/latest` | 最新一次扫描 | 200 / 404 |
| `GET /api/scans` | 有界历史列表 | 200 |
| `POST /api/scans/{scanId}/cancel` | 协作式取消，返回终态 | 200 / 404 |

> `componentCount` 是合并去重后的组件总数；`components` 为进入快照的明细，超大清单会截断。

返回快照字段：`scanId, status, vulnLibraryId, vulnLibraryVersion, moduleCount,
componentCount, components[], findings[], issues[], error, submittedAtEpochMillis, finishedAtEpochMillis`。

请求示例：

```json
{
  "vulnLibraryPath": "samples/vuln-db.json",
  "modules": [
    {"module": "frontend", "path": "samples/manifests/frontend-package-lock.json"},
    {"module": "service", "path": "samples/manifests/service-pom.xml"},
    {"module": "data", "path": "samples/manifests/data-requirements.txt"},
    {"module": "broken", "content": "{\"lockfileVersion\":3,\"packages\":{\"node_modules/x\":{\"version\":", "format": "PACKAGE_LOCK_JSON"}
  ]
}
```

## 6. 本地验证方法（全程离线）

要求：JDK 21+、Maven 3.9+，依赖已在本地 `~/.m2` 缓存。

```bash
# 1) 离线编译
mvn -o compile

# 2) 离线运行全部单测/集成测试（27 个用例，覆盖畸形清单、多版本冲突、重复扫描、取消等）
mvn -o test

# 3) 启动服务（默认端口随机；也可在 application.properties 指定 server.port）
mvn -o spring-boot:run

# 4) 用样例清单发起一次本地扫描
curl -s -X POST http://127.0.0.1:${PORT}/api/scans \
  -H 'Content-Type: application/json' \
  -d '{
        "vulnLibraryPath": "samples/vuln-db.json",
        "modules": [
          {"module":"frontend","path":"samples/manifests/frontend-package-lock.json"},
          {"module":"admin","path":"samples/manifests/admin-package-lock.json"},
          {"module":"service","path":"samples/manifests/service-pom.xml"},
          {"module":"data","path":"samples/manifests/data-requirements.txt"},
          {"module":"broken","content":"not a manifest"}
        ]
      }'

# 5) 查询 / 历史 / 取消（<scanId> 用上一步返回值替换）
curl -s http://127.0.0.1:${PORT}/api/scans/<scanId>
curl -s http://127.0.0.1:${PORT}/api/scans
curl -s -X POST http://127.0.0.1:${PORT}/api/scans/<scanId>/cancel
```

测试清单：

- `VersionMatcherTest`：版本比较与左闭右开区间判定依据。
- `ManifestParserTest`：三种格式的正常解析、损坏清单、空清单、字段缺失、重复与多版本。
- `VulnLibraryLoaderTest`：库 id/version 绑定、索引、损坏/缺字段/缺失文件错误。
- `ScanEngineIntegrationTest`：多模块多生态归一、坏文件隔离、跨模块风险合并去重、
  漏洞库更新后结论变化与历史按版本复现、库缺失时整体 FAILED、超大清单组件明细截断但统计/命中完整。
- `ScanManagerConcurrencyTest`：重复提交 409、8 线程并发只允许一个运行、
  取消不留半成品且下一次扫描正常、取消不存在 id 不误伤运行中的扫描。
- `ScanControllerWebTest`：提交/查询/历史/取消链路、409 携带 activeScanId、400 坏请求。

单测日志统一打印 `[输入]`、`[关键状态变化]`、`[判定依据]`，便于审计与复盘。

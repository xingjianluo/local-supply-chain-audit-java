# 本地依赖清单与漏洞风险审计服务（Local Supply Chain Audit）

一个完全本地运行的 Spring Boot 服务：输入本机各工程模块的依赖清单与本地漏洞库，
输出可追溯的扫描结论。**全程不接外网、不依赖数据库或任何外部服务**。

- 解析在本地完成（XML/JSON 均使用 JDK / Jackson，无网络调用）；
- 漏洞库是本地目录下的 JSON 文件，快照内容寻址；
- 无持久化中间件，扫描状态保存在进程内存中。

---

## 1. 清单兼容范围

### 1.1 支持的格式

| 格式 | 识别方式 | 说明 |
| --- | --- | --- |
| Maven `pom.xml`（`MAVEN_POM`） | 显式指定、`.xml`/`pom.xml` 后缀或内容以 `<` 开头 | 提取文档内任意位置的 `<dependency>`（含 dependencyManagement、profiles 中的）以及 `<plugins>` 中的 `<plugin>` 坐标；`<plugin>` 缺 groupId 时按 Maven 约定补 `org.apache.maven.plugins`。XML 解析禁用 DOCTYPE/外部实体。 |
| 本地 JSON 清单 / 简化 SBOM（`JSON_SBOM`） | 显式指定、`.json` 后缀或内容以 `{` 开头 | 形如 `{"components":[{"group":"g","name":"n","version":"v","scope":"compile"}]}`。 |

请求中可以为每个清单显式指定 `format`；不指定时按“显式值 > 文件后缀 > 内容嗅探”顺序自动识别。
无法识别的格式不会静默跳过，会得到 `CORRUPT + UNSUPPORTED_FORMAT` 结论。

### 1.2 输入方式

每个 `ManifestInput` 支持二选一：

- `content`：直接内联清单文本；
- `path`：本机文件绝对/相对路径（服务直接读本地文件，不发起任何网络请求）。

`moduleId` 可由调用方指定；缺省时取文件名，再缺省取内联占位名。单文件上限 8 MiB，
超出按 `UNREADABLE_FILE` 明确报错（防止大文件拖垮内存）。

### 1.3 明确且可区分的处理结论（不静默跳过、不因单文件失败整扫）

每个清单产出独立的 `ManifestResult`，`status` 三态互斥：

| status | 触发条件 | issue 类型（`IssueType`） |
| --- | --- | --- |
| `PARSED` | 完全解析成功 | 无 |
| `PARTIALLY_PARSED` | 文件结构可解析，但个别条目字段有缺陷；有效条目仍保留 | `MISSING_COORDINATE`（缺 group/name）、`MISSING_VERSION`（缺 version）、`MALFORMED_JSON`（数组中混入非对象条目） |
| `CORRUPT` | 文件整体无法使用；**只影响该文件，不影响其它清单与整次扫描** | `UNREADABLE_FILE`（文件不存在/读不了/超限）、`MALFORMED_XML`、`MALFORMED_JSON`（根非对象或无 `components` 数组）、`UNSUPPORTED_FORMAT` |

跨模块归一阶段还有两类显式结论：

- `DUPLICATE_REFERENCE`：同一模块重复声明同一 `group:name:version`，归一后只保留一份；
- `MULTI_VERSION_CONFLICT`：同一组件在多个模块（或多处）出现不同版本，**所有版本都保留并分别参与匹配**，结论中同时给出各版本对应的模块集合；
- 缺 group/name 的条目无法聚合，会计入 `<uncoordinated>` 占位项并汇总计数，条目级原因仍挂在所属清单上。

---

## 2. 扫描状态约定

### 2.1 状态机

```
PENDING ──worker 启动──> RUNNING ──成功──> SUCCEEDED   （终态）
                           │  └──────失败──> FAILED     （终态）
                           └──────取消────> CANCELED    （终态）
```

- **单飞（single-flight）**：任意时刻最多一个非终态扫描。重复提交立即得到
  `409 Conflict`，响应体形如
  `{"error":"SCAN_ALREADY_RUNNING","runningScanId":"scan-xxx", ...}`，
  可与其它错误明确区分；
- **取消**：`POST /api/scans/{id}/cancel` 设置协作取消标志。扫描在“阶段之间、
  每批（50 个清单）之间”检查标志；一旦观察到取消，引擎直接停止且**不发布任何半成品**，
  协调器发布空内容的终态 `CANCELED` 结果并释放单飞槽位，因此不影响下一次扫描；
- **并发隔离**：start/get/cancel 的状态迁移在同一把锁内串行化；对外只读不可变快照，
  并发提交、读取、取消不会互相串数据；
- **历史保留**：终态扫描按提交顺序保留（默认最近 50 个），每条都绑定当时的漏洞库版本。

### 2.2 扫描分阶段（便于取消与内存可控）

1. `PARSE`：清单分批（每批 50）独立解析，损坏文件只产生 `CORRUPT` 结果；
2. `NORMALIZE`：跨模块/跨格式归并，输出唯一 `group:name` 组件、版本集合、模块集合；
3. `EVALUATE`：先绑定不可变漏洞库快照，再按每个具体版本匹配，组件被多模块引用时
   风险按 `vulnId` 合并去重、模块集合合并。

### 2.3 HTTP 接口

| 方法与路径 | 语义 | 状态码 |
| --- | --- | --- |
| `POST /api/scans` | 提交扫描（body 为 `ScanRequest`） | 202 已接受（返回 PENDING 快照）；409 已有扫描在跑；400 请求为空/不可读 |
| `GET /api/scans/{scanId}` | 查询某次扫描（运行中或终态） | 200；404 不存在 |
| `GET /api/scans` | 查看历史终态/当前扫描列表 | 200 |
| `POST /api/scans/{scanId}/cancel` | 取消运行中的扫描 | 200 已发出取消；404 无匹配的活动扫描 |

请求体示例：

```json
{
  "manifests": [
    {"moduleId": "module-a", "format": "MAVEN_POM", "path": "/path/to/pom.xml"},
    {"moduleId": "module-b", "format": "JSON_SBOM",
     "content": "{\"components\":[{\"group\":\"com.example\",\"name\":\"risky-lib\",\"version\":\"1.1.0\"}]}"}
  ]
}
```

结论中可追溯字段：每个清单的 `path/moduleId/status/issues`、每条风险的 `vulnId/
affectedVersions/fixedIn/level`、组件的 `versions/modules`，以及扫描级的
`vulnDbVersion` 与汇总计数 `ScanSummary`。

---

## 3. 漏洞库版本关联方式

- 漏洞库目录默认是 `src/main/resources/local-vulndb`，可用启动参数
  `--audit.vulndb.path=/your/local/vulndb`（或配置项 `audit.vulndb.path`）覆盖，
  目录内一个或多个 `*.json`，格式：

  ```json
  {
    "entries": [
      {
        "vulnId": "LOCAL-CVE-2024-0001",
        "group": "com.example",
        "name": "risky-lib",
        "ranges": [{"startInclusive": "1.0.0", "endExclusive": "1.2.0"}],
        "fixedIn": "1.2.0",
        "level": "HIGH",
        "title": "...",
        "description": "..."
      }
    ]
  }
  ```

  `ranges` 为**下界包含、上界不包含**的区间；任一边界为 `null` 表示开放；
  `level ∈ {CRITICAL,HIGH,MEDIUM,LOW}`。
- **版本号 = 内容哈希**：按排序后的文件名 + 文件字节计算 SHA-256，取前 16 位形成
  `vdb-xxxxxxxxxxxxxxxx`。内容不变，多次加载版本号一致；内容更新，版本号必然变化。
- **结论与快照强绑定**：扫描启动时先 `loadSnapshot`，结果中的 `vulnDbVersion`
  记录所用快照。漏洞库更新后 `refresh` 得到新版本，重扫结论即体现新库（如严重等级修订、
  新增条目）；所有历史快照不可变且继续保留，可按 `versionId` 取回，因此**历史扫描能按
  当时的库版本复现**（见 `LocalVulnRepositoryTest` 与 `ScanCoordinatorTest`）。
- 版本比较：按 `.`/`-` 分段，数字段按数值比较（`1.10 > 1.9`），文本段按字典序，
  数字发布段排在文本限定符之前（`1.0-rc1 < 1.0`）；缺失版本不参与匹配。

---

## 4. 本地验证方法

环境：JDK 21+（在 JDK 25 上同样可编译运行）、Maven 3.9+，依赖需已在本机 `.m2`
缓存中（**全程使用离线模式，不联网**）。

### 4.1 运行全部测试

```bash
mvn -o test
```

覆盖的关键场景（39 个用例，均打印“输入 / 关键状态变化 / 判定依据”日志）：

- 畸形 XML/JSON、缺字段、非对象条目、文件缺失（`ManifestParserTest`）；
- 同模块重复引用、跨模块同版本、多版本冲突、缺坐标（`DependencyNormalizerTest`）；
- 漏洞库同内容版本稳定、更新产生新版本且旧快照仍可复现（`LocalVulnRepositoryTest`）；
- 漏洞匹配、多版本/多模块风险合并去重、安全版本不命中（`RiskEvaluatorTest`）；
- 8 路并发提交仅 1 个运行其余 409、取消不留半成品且不影响下次、空请求 400、
  库更新后重扫结论变化而历史可复现（`ScanCoordinatorTest`）；
- 多格式 + 损坏文件隔离的端到端扫描（`ScanEndToEndTest`）；
- HTTP 202/409/400/404 契约（`ScanControllerTest`）；
- 1 万组件大清单有界完成、预取消不产生结果（`LargeManifestScanTest`）。

### 4.2 启动服务并手工验证

```bash
mvn -o spring-boot:run        # 使用随机本地端口（见 application.properties）
```

另一个终端：

```bash
# 提交扫描（内联 + 本地文件混合）
curl -s -X POST http://127.0.0.1:${PORT}/api/scans \
  -H 'Content-Type: application/json' \
  -d @- <<'JSON'
{
  "manifests": [
    {"moduleId": "module-a", "format": "MAVEN_POM",
     "path": "src/test/resources/sample-manifests/module-a-pom.xml"},
    {"moduleId": "module-b",
     "content": "{\"components\":[{\"group\":\"com.example\",\"name\":\"risky-lib\",\"version\":\"1.1.0\"},{\"group\":\"com.example\",\"name\":\"risky-lib\",\"version\":\"1.2.0\"}]}"}
  ]
}
JSON

# 查询（把 scan-xxx 换成返回的 id）
curl -s http://127.0.0.1:${PORT}/api/scans/scan-xxx | jq .

# 立即重复提交 -> 409 冲突，body 中带 runningScanId
# 取消
curl -s -X POST http://127.0.0.1:${PORT}/api/scans/scan-xxx/cancel

# 历史
curl -s http://127.0.0.1:${PORT}/api/scans | jq '.[].status'
```

随仓库自带的样例：

- 清单：`src/test/resources/sample-manifests/module-a-pom.xml`、`module-b-sbom.json`；
- 漏洞库：`src/main/resources/local-vulndb/vuln-entries.json`。

### 4.3 验证“库更新后重扫 + 历史复现”

1. 用现有漏洞库扫描一次，记录 `vulnDbVersion` 与命中等级；
2. 修改 `local-vulndb/*.json`（如把 `LOCAL-CVE-2024-0001` 的 `level` 改为 `CRITICAL`），
   再次扫描，`vulnDbVersion` 改变、结论体现新内容；
3. 通过仓库按旧 `versionId` 仍可取回旧快照——自动测试 `ScanCoordinatorTest
   .rescanAfterLibraryUpdateReflectsNewConclusionAndHistoryKeepsOldVersion`
   使用测试资源 `src/test/resources/test-vulndb` 与 `src/test/resources/test-vulndb-v2` 固化了这一过程，可直接：

   ```bash
   mvn -o test -Dtest=ScanCoordinatorTest#rescanAfterLibraryUpdateReflectsNewConclusionAndHistoryKeepsOldVersion
   ```

---

## 5. 关键包结构

```
model/      统一数据模型：清单结果、归一组件、漏洞条目/快照、风险结论、扫描结果与枚举
parse/      格式识别 + pom.xml / JSON 清单解析（损坏文件 -> 显式结论，不抛穿）
vuln/       本地漏洞库快照仓库（内容寻址版本）+ 版本区间匹配
scan/       归一化、风险评估、分批+可取消的扫描引擎、单飞状态协调器
web/        REST 控制器与 409/400 异常映射
```

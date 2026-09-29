package com.github.xingjianluo.localsupplychainauditjava.tests;

import com.github.xingjianluo.localsupplychainauditjava.core.CancelToken;
import com.github.xingjianluo.localsupplychainauditjava.engine.DefaultScanEngine;
import com.github.xingjianluo.localsupplychainauditjava.engine.VulnMatcher;
import com.github.xingjianluo.localsupplychainauditjava.model.Finding;
import com.github.xingjianluo.localsupplychainauditjava.model.ManifestFormat;
import com.github.xingjianluo.localsupplychainauditjava.model.ModuleSpec;
import com.github.xingjianluo.localsupplychainauditjava.model.ParseIssueType;
import com.github.xingjianluo.localsupplychainauditjava.model.ScanRequest;
import com.github.xingjianluo.localsupplychainauditjava.model.ScanSnapshot;
import com.github.xingjianluo.localsupplychainauditjava.model.ScanStatus;
import com.github.xingjianluo.localsupplychainauditjava.parser.FormatDetector;
import com.github.xingjianluo.localsupplychainauditjava.parser.ManifestParserRegistry;
import com.github.xingjianluo.localsupplychainauditjava.parser.PackageLockJsonParser;
import com.github.xingjianluo.localsupplychainauditjava.parser.PomXmlParser;
import com.github.xingjianluo.localsupplychainauditjava.parser.RequirementsTxtParser;
import com.github.xingjianluo.localsupplychainauditjava.service.AuditProperties;
import com.github.xingjianluo.localsupplychainauditjava.vuln.JsonFileVulnLibraryLoader;
import com.github.xingjianluo.localsupplychainauditjava.vuln.VersionMatcher;
import com.github.xingjianluo.localsupplychainauditjava.vuln.VulnLibraryLoadException;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 扫描引擎端到端单测（直接装配真实组件，不启动 Web）：
 * 多格式归一、坏文件隔离、跨模块风险合并去重、漏洞库版本绑定与更新复现。
 */
class ScanEngineIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(ScanEngineIntegrationTest.class);

    private DefaultScanEngine newEngine() {
        AuditProperties props = new AuditProperties();
        ManifestParserRegistry registry = new ManifestParserRegistry(List.of(
                new PomXmlParser(props), new PackageLockJsonParser(props), new RequirementsTxtParser(props)));
        return new DefaultScanEngine(new FormatDetector(), registry,
                new VulnMatcher(new VersionMatcher()),
                new JsonFileVulnLibraryLoader(props), props);
    }

    private Path writeLib(String id, String version, String rulesJson) throws Exception {
        Path file = Files.createTempFile("vulnlib-" + version, ".json");
        String json = "{\"id\":\"" + id + "\",\"version\":\"" + version + "\",\"rules\":"
                + rulesJson + "}";
        Files.writeString(file, json);
        return file;
    }

    private String lodashRules(String fixedHigh) {
        return """
                [{"id":"CVE-LODASH","ecosystem":"npm","group":"","name":"lodash",
                  "rangeLow":"4.0.0","rangeHigh":"%s","fixedIn":"%s",
                  "title":"prototype pollution","severity":"high"}]
                """.formatted(fixedHigh, fixedHigh);
    }

    @Test
    void multiModuleScanNormalizesMergesAndIsolatesBadFile() throws Exception {
        Path lib = writeLib("local-vuln-db", "2026.09.01", lodashRules("4.17.21"));
        log.info("[输入] 漏洞库 version=2026.09.01 path={}", lib);

        ModuleSpec npm1 = new ModuleSpec("web-app", null, """
                {"lockfileVersion":3,"packages":{
                  "node_modules/lodash":{"version":"4.17.20"},
                  "node_modules/react":{"version":"18.2.0"}
                }}
                """, ManifestFormat.PACKAGE_LOCK_JSON);
        ModuleSpec npm2 = new ModuleSpec("admin-app", null, """
                {"lockfileVersion":3,"packages":{
                  "node_modules/lodash":{"version":"4.17.20"}
                }}
                """, ManifestFormat.PACKAGE_LOCK_JSON);
        ModuleSpec py = new ModuleSpec("data-job", null, "requests==2.31.0\n",
                ManifestFormat.REQUIREMENTS_TXT);
        ModuleSpec broken = new ModuleSpec("broken-module", null,
                "{\"lockfileVersion\":3,\"packages\":{\"node_modules/x\":{\"version\":",
                ManifestFormat.PACKAGE_LOCK_JSON);
        ModuleSpec unreadable = new ModuleSpec("missing-module", "/no/such/pom.xml", null,
                ManifestFormat.POM_XML);
        ScanRequest request = new ScanRequest(List.of(npm1, npm2, py, broken, unreadable),
                lib.toString());
        log.info("[输入] 5 个模块: 2 个 npm(共享 lodash)、1 个 pypi、1 个损坏、1 个缺失文件");

        ScanSnapshot snap = newEngine().execute("scan-1", request, CancelToken.never());
        log.info("[关键状态变化] status={} libVersion={} 组件数={} 命中={} 结论类型={}",
                snap.status(), snap.vulnLibraryVersion(), snap.components().size(),
                snap.findings().size(),
                snap.issues().stream().map(i -> i.type().name()).distinct().toList());

        assertEquals(ScanStatus.COMPLETED, snap.status(), "坏文件不得让整次扫描失败");
        assertEquals("2026.09.01", snap.vulnLibraryVersion());
        assertEquals("local-vuln-db", snap.vulnLibraryId());

        List<Finding> lodashHits = snap.findings().stream()
                .filter(f -> f.ruleId().equals("CVE-LODASH")).toList();
        assertEquals(1, lodashHits.size(), "同一组件被多模块引用时风险必须合并去重为一条");
        assertEquals(2, lodashHits.get(0).referencedBy().size(), "命中需聚合两个引用模块");
        assertTrue(lodashHits.get(0).referencedBy().contains("web-app"));
        assertTrue(lodashHits.get(0).referencedBy().contains("admin-app"));

        assertTrue(snap.issues().stream()
                .anyMatch(i -> i.type() == ParseIssueType.MALFORMED_MANIFEST
                        && "broken-module".equals(i.module())), "损坏模块必须有明确结论");
        assertTrue(snap.issues().stream()
                .anyMatch(i -> i.type() == ParseIssueType.UNREADABLE_SOURCE
                        && "missing-module".equals(i.module())), "不可读文件必须有明确结论");
        assertTrue(snap.issues().stream()
                .anyMatch(i -> i.type() == ParseIssueType.DUPLICATE_REFERENCE
                        && i.detail() != null && i.detail().contains("lodash")),
                "跨模块共享组件要给出可追溯的合并结论");
        assertTrue(snap.components().stream()
                .anyMatch(c -> c.coordinate().ecosystem().equals("pypi")
                        && c.coordinate().name().equals("requests")), "多生态必须归一收录");
    }

    @Test
    void updatedLibraryChangesConclusionWhileHistorySnapshotsStayBound() throws Exception {
        Path oldLib = writeLib("local-vuln-db", "2026.09.01", lodashRules("4.17.21"));
        Path newLib = writeLib("local-vuln-db", "2026.09.30", lodashRules("4.17.22"));
        ModuleSpec npm = new ModuleSpec("web-app", null, """
                {"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}
                """, ManifestFormat.PACKAGE_LOCK_JSON);

        DefaultScanEngine engine = newEngine();
        ScanSnapshot oldSnap = engine.execute("scan-old",
                new ScanRequest(List.of(npm), oldLib.toString()), CancelToken.never());
        log.info("[判定依据] 旧库 {} 修复版本=4.17.21, lodash@4.17.21 落在开区间外, 命中={}",
                oldSnap.vulnLibraryVersion(), oldSnap.findings().size());
        assertEquals(0, oldSnap.findings().size());
        assertEquals("2026.09.01", oldSnap.vulnLibraryVersion());

        ScanSnapshot newSnap = engine.execute("scan-new",
                new ScanRequest(List.of(npm), newLib.toString()), CancelToken.never());
        log.info("[判定依据] 新库 {} 修复版本=4.17.22, lodash@4.17.21 仍受影响, 命中={}",
                newSnap.vulnLibraryVersion(), newSnap.findings().size());
        assertEquals(1, newSnap.findings().size(), "漏洞库更新后重扫必须体现新结论");
        assertEquals("2026.09.30", newSnap.vulnLibraryVersion());

        // 旧快照不可变，仍绑定当时库版本：历史可按库版本复现
        assertEquals("2026.09.01", oldSnap.vulnLibraryVersion());
        assertEquals(0, oldSnap.findings().size());
        assertNotNull(oldSnap);
    }

    @Test
    void componentDetailsAreTruncatedButCountsAndFindingsStayComplete() throws Exception {
        Path lib = writeLib("local-vuln-db", "2026.09.30",
                """
                [{"id":"V-EACH","ecosystem":"npm","group":"","name":"pkg-0",
                  "rangeLow":"1.0.0","rangeHigh":"1.1.0","fixedIn":"1.1.0",
                  "title":"t","severity":"low"}]
                """);
        // 5 个组件、每条带独立名称；库规则只命中 pkg-0
        StringBuilder packages = new StringBuilder("{\"lockfileVersion\":3,\"packages\":{");
        for (int i = 0; i < 5; i++) {
            if (i > 0) {
                packages.append(',');
            }
            packages.append("\"node_modules/pkg-").append(i).append("\":{\"version\":\"1.0.0\"}");
        }
        packages.append("}}");
        ModuleSpec npm = new ModuleSpec("big", null, packages.toString(),
                ManifestFormat.PACKAGE_LOCK_JSON);
        AuditProperties props = new AuditProperties();
        props.setMaxComponentsInSnapshot(2);
        ManifestParserRegistry registry = new ManifestParserRegistry(List.of(
                new PomXmlParser(props), new PackageLockJsonParser(props), new RequirementsTxtParser(props)));
        DefaultScanEngine engine = new DefaultScanEngine(new FormatDetector(), registry,
                new VulnMatcher(new VersionMatcher()),
                new JsonFileVulnLibraryLoader(props), props);

        log.info("[输入] 5 个组件 + 快照上限 2，pkg-0 命中漏洞");
        ScanSnapshot snap = engine.execute("scan-trunc",
                new ScanRequest(List.of(npm), lib.toString()), CancelToken.never());
        log.info("[关键状态变化] status={} componentCount={} 明细保留={} findings={} 截断结论={}",
                snap.status(), snap.componentCount(), snap.components().size(),
                snap.findings().size(),
                snap.issues().stream().filter(i ->
                        i.type() == ParseIssueType.COMPONENT_LIST_TRUNCATED).count());

        assertEquals(ScanStatus.COMPLETED, snap.status());
        assertEquals(5, snap.componentCount(), "组件总数统计必须准确");
        assertEquals(2, snap.components().size(), "明细只保留上限条数");
        assertEquals(1, snap.findings().size(), "漏洞命中不受组件明细截断影响");
        assertEquals(1, snap.issues().stream()
                .filter(i -> i.type() == ParseIssueType.COMPONENT_LIST_TRUNCATED).count(),
                "截断必须有明确可区分的结论");
    }

    @Test
    void missingLibraryFailsScanExplicitly() {
        ModuleSpec npm = new ModuleSpec("web-app", null, "{}",
                ManifestFormat.PACKAGE_LOCK_JSON);
        log.info("[输入] 不存在的漏洞库路径，期望整体性 FAILED 且错误信息可区分");
        ScanSnapshot snap = newEngine().execute("scan-nolib",
                new ScanRequest(List.of(npm), "/no/such/vuln.json"), CancelToken.never());
        assertEquals(ScanStatus.FAILED, snap.status());
        assertTrue(snap.error().contains("漏洞库不可用"));
        log.info("[关键状态变化] status=FAILED error={}", snap.error());
    }
}

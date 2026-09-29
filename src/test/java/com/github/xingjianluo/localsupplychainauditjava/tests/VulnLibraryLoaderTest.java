package com.github.xingjianluo.localsupplychainauditjava.tests;

import com.github.xingjianluo.localsupplychainauditjava.service.AuditProperties;
import com.github.xingjianluo.localsupplychainauditjava.vuln.JsonFileVulnLibraryLoader;
import com.github.xingjianluo.localsupplychainauditjava.model.VulnLibrary;
import com.github.xingjianluo.localsupplychainauditjava.vuln.VulnLibraryLoadException;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 漏洞库加载单测：库版本来自文件声明；损坏/缺字段/缺失文件要有明确错误。
 */
class VulnLibraryLoaderTest {

    private static final Logger log = LoggerFactory.getLogger(VulnLibraryLoaderTest.class);

    @Test
    void loadsIdVersionAndIndexesRules() throws Exception {
        String json = """
                {
                  "id": "local-vuln-db",
                  "version": "2026.09.01",
                  "rules": [
                    {"id": "VULN-1", "ecosystem": "npm", "group": "", "name": "lodash",
                     "rangeLow": "4.0.0", "rangeHigh": "4.17.21", "fixedIn": "4.17.21",
                     "title": "prototype pollution", "severity": "high"},
                    {"id": "VULN-2", "ecosystem": "pypi", "group": "", "name": "requests",
                     "rangeLow": "2.0", "rangeHigh": "2.31.0", "fixedIn": "2.31.0",
                     "title": "ssl issue", "severity": "medium"}
                  ]
                }
                """;
        Path file = Files.createTempFile("vulnlib-ok", ".json");
        Files.writeString(file, json);
        log.info("[输入] 漏洞库文件 path={} version=2026.09.01 rules=2", file);

        VulnLibrary lib = new JsonFileVulnLibraryLoader(new AuditProperties()).load(file.toString());
        log.info("[关键状态变化] 加载完成 id={} version={} ruleCount={}",
                lib.libraryId(), lib.version(), lib.ruleCount());

        assertEquals("local-vuln-db", lib.libraryId());
        assertEquals("2026.09.01", lib.version());
        assertEquals(2, lib.ruleCount());
        assertEquals(1, lib.rulesFor(new com.github.xingjianluo.localsupplychainauditjava.model
                .ComponentCoordinate("npm", "", "lodash")).size());
    }

    @Test
    void rejectsMissingVersionField() throws Exception {
        String json = "{\"id\":\"x\",\"rules\":[]}";
        Path file = Files.createTempFile("vulnlib-nover", ".json");
        Files.writeString(file, json);
        log.info("[输入] 缺 version 字段的漏洞库 path={}", file);
        VulnLibraryLoadException ex = assertThrows(VulnLibraryLoadException.class,
                () -> new JsonFileVulnLibraryLoader(new AuditProperties()).load(file.toString()));
        log.info("[判定依据] 抛出明确异常: {}", ex.getMessage());
        assertTrue(ex.getMessage().contains("version"));
    }

    @Test
    void rejectsCorruptJsonAndMissingFile() throws Exception {
        Path corrupt = Files.createTempFile("vulnlib-bad", ".json");
        Files.writeString(corrupt, "{ not json");
        log.info("[输入] 损坏漏洞库 path={}", corrupt);
        assertThrows(VulnLibraryLoadException.class,
                () -> new JsonFileVulnLibraryLoader(new AuditProperties()).load(corrupt.toString()));
        log.info("[关键状态变化] 损坏 JSON 被识别并抛出 VulnLibraryLoadException");

        log.info("[输入] 不存在的漏洞库路径 /no/such/db.json");
        assertThrows(VulnLibraryLoadException.class,
                () -> new JsonFileVulnLibraryLoader(new AuditProperties()).load("/no/such/db.json"));
    }
}

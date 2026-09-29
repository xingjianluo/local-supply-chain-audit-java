package com.github.xingjianluo.localsupplychainauditjava.vuln;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.github.xingjianluo.localsupplychainauditjava.model.ComponentCoordinate;
import com.github.xingjianluo.localsupplychainauditjava.model.VulnLibrary;
import com.github.xingjianluo.localsupplychainauditjava.model.VulnRule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 基于本地 JSON 文件的漏洞库加载器。
 *
 * <p>文件格式（UTF-8 JSON）：
 * <pre>
 * {
 *   "id": "local-vuln-db",
 *   "version": "2026.09.30",
 *   "rules": [
 *     {"id":"CVE-...","ecosystem":"npm","group":"","name":"lodash",
 *      "rangeLow":"4.0.0","rangeHigh":"4.17.21","fixedIn":"4.17.21",
 *      "title":"...","severity":"high"}
 *   ]
 * }
 * </pre>
 *
 * <p>流式逐条读取规则，避免大库一次性构树；库版本由文件内容声明，扫描快照永久绑定该版本。
 */
@Component
public class JsonFileVulnLibraryLoader implements VulnLibraryLoader {

    private static final Logger log = LoggerFactory.getLogger(JsonFileVulnLibraryLoader.class);

    private final JsonFactory jsonFactory = new JsonFactory();
    private final String defaultPath;
    private volatile VulnLibrary cached;

    public JsonFileVulnLibraryLoader(com.github.xingjianluo.localsupplychainauditjava.service.AuditProperties properties) {
        this.defaultPath = properties.getVulnLibraryPath();
    }

    @Override
    public VulnLibrary loadDefault() {
        if (defaultPath == null || defaultPath.isBlank()) {
            throw new VulnLibraryLoadException("未配置本地漏洞库路径 audit.vuln-library-path");
        }
        VulnLibrary lib = load(defaultPath);
        this.cached = lib;
        return lib;
    }

    @Override
    public VulnLibrary load(String path) {
        if (path == null || path.isBlank()) {
            throw new VulnLibraryLoadException("漏洞库路径为空");
        }
        Path file = Path.of(path);
        if (!Files.isRegularFile(file) || !Files.isReadable(file)) {
            throw new VulnLibraryLoadException("漏洞库文件不存在或不可读: " + file);
        }
        long size;
        try {
            size = Files.size(file);
        } catch (IOException e) {
            throw new VulnLibraryLoadException("无法读取漏洞库文件大小: " + file, e);
        }
        log.info("加载本地漏洞库: path={} bytes={}", file, size);
        try (JsonParser parser = jsonFactory.createParser(file.toFile())) {
            VulnLibrary lib = parseLibrary(parser, file.toString());
            cached = lib;
            log.info("漏洞库加载完成: id={} version={} rules={}", lib.libraryId(), lib.version(), lib.ruleCount());
            return lib;
        } catch (VulnLibraryLoadException e) {
            throw e;
        } catch (IOException | RuntimeException e) {
            throw new VulnLibraryLoadException(
                    "漏洞库 JSON 损坏: " + e.getClass().getSimpleName() + ": " + e.getMessage(), e);
        }
    }

    @Override
    public VulnLibrary current() {
        return cached;
    }

    private VulnLibrary parseLibrary(JsonParser parser, String source) throws IOException {
        if (parser.nextToken() != JsonToken.START_OBJECT) {
            throw new VulnLibraryLoadException("漏洞库根节点必须是 JSON 对象: " + source);
        }
        String id = null;
        String version = null;
        List<VulnRule> rules = null;
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            String field = parser.currentName();
            JsonToken t = parser.nextToken();
            switch (field) {
                case "id" -> id = t == JsonToken.VALUE_STRING ? parser.getText() : null;
                case "version" -> version = t == JsonToken.VALUE_STRING ? parser.getText() : null;
                case "rules" -> {
                    if (t != JsonToken.START_ARRAY) {
                        throw new VulnLibraryLoadException("漏洞库 rules 必须是数组: " + source);
                    }
                    rules = parseRules(parser);
                }
                default -> {
                    if (t == JsonToken.START_OBJECT || t == JsonToken.START_ARRAY) {
                        parser.skipChildren();
                    }
                }
            }
        }
        if (id == null || id.isBlank()) {
            throw new VulnLibraryLoadException("漏洞库缺少 id 字段: " + source);
        }
        if (version == null || version.isBlank()) {
            throw new VulnLibraryLoadException("漏洞库缺少 version 字段: " + source);
        }
        List<VulnRule> safeRules = rules == null ? List.of() : rules;
        Map<ComponentCoordinate, List<VulnRule>> indexed = new LinkedHashMap<>();
        for (VulnRule rule : safeRules) {
            indexed.computeIfAbsent(rule.coordinate(), k -> new ArrayList<>()).add(rule);
        }
        return new VulnLibrary(id, version, System.currentTimeMillis(), safeRules.size(),
                copyIndex(indexed));
    }

    private List<VulnRule> parseRules(JsonParser parser) throws IOException {
        List<VulnRule> rules = new ArrayList<>();
        int ordinal = 0;
        while (parser.nextToken() != JsonToken.END_ARRAY) {
            ordinal++;
            if (parser.currentToken() != JsonToken.START_OBJECT) {
                throw new VulnLibraryLoadException("rules 第" + ordinal + "项不是对象");
            }
            String ruleId = null;
            String ecosystem = null;
            String group = "";
            String name = null;
            String low = null;
            String high = null;
            String fixedIn = null;
            String title = null;
            String severity = null;
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                String field = parser.currentName();
                JsonToken t = parser.nextToken();
                if (t != JsonToken.VALUE_STRING && t != JsonToken.VALUE_NULL) {
                    if (t == JsonToken.START_OBJECT || t == JsonToken.START_ARRAY) {
                        parser.skipChildren();
                    }
                    continue;
                }
                String value = t == JsonToken.VALUE_NULL ? null : parser.getText();
                switch (field) {
                    case "id" -> ruleId = value;
                    case "ecosystem" -> ecosystem = value;
                    case "group" -> group = value == null ? "" : value;
                    case "name" -> name = value;
                    case "rangeLow" -> low = value;
                    case "rangeHigh" -> high = value;
                    case "fixedIn" -> fixedIn = value;
                    case "title" -> title = value;
                    case "severity" -> severity = value;
                    default -> { }
                }
            }
            if (ruleId == null || ruleId.isBlank() || ecosystem == null || name == null || name.isBlank()) {
                throw new VulnLibraryLoadException("rules 第" + ordinal
                        + "项缺少必填字段 id/ecosystem/name");
            }
            rules.add(new VulnRule(ruleId, new ComponentCoordinate(ecosystem, group, name),
                    emptyToNull(low), emptyToNull(high), emptyToNull(fixedIn), title,
                    severity == null ? "unknown" : severity));
        }
        return rules;
    }

    private Map<ComponentCoordinate, List<VulnRule>> copyIndex(Map<ComponentCoordinate, List<VulnRule>> src) {
        Map<ComponentCoordinate, List<VulnRule>> immutable = new LinkedHashMap<>();
        src.forEach((k, v) -> immutable.put(k, List.copyOf(v)));
        return Map.copyOf(immutable);
    }

    private String emptyToNull(String s) {
        return s == null || s.isBlank() ? null : s;
    }
}

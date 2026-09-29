package com.github.xingjianluo.localsupplychainauditjava.parser;

import com.github.xingjianluo.localsupplychainauditjava.model.ComponentCoordinate;
import com.github.xingjianluo.localsupplychainauditjava.model.DependencyRef;
import com.github.xingjianluo.localsupplychainauditjava.model.ManifestFormat;
import com.github.xingjianluo.localsupplychainauditjava.model.ParseIssue;
import com.github.xingjianluo.localsupplychainauditjava.model.ParseIssueType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 单模块依赖收集器：统一处理字段缺失、重复引用、同组件多版本三类结论，
 * 保证任何输入条目都有明确去向，绝不静默丢弃。
 *
 * <p>不是线程安全的；每个模块清单使用独立实例。
 */
class DependencyCollector {

    private static final Logger log = LoggerFactory.getLogger(DependencyCollector.class);

    private final String module;
    private final ManifestFormat format;
    private final List<ParseIssue> issues = new ArrayList<>();
    /** key 为组件归一化键，value 记录已出现版本，保持插入顺序。 */
    private final Map<String, Set<String>> versionsByComponent = new LinkedHashMap<>();
    private final Map<String, ComponentCoordinate> coordinates = new LinkedHashMap<>();
    private final Set<String> exactSeen = new HashSet<>();

    DependencyCollector(String module, ManifestFormat format) {
        this.module = module;
        this.format = format;
    }

    /**
     * 接收一条原始条目。
     *
     * @param coordinate 已归一坐标
     * @param version    原始版本字符串（可能为空）
     * @param rawSnippet 触发字段缺失时记录的原文片段，便于追溯
     */
    void accept(ComponentCoordinate coordinate, String version, String rawSnippet) {
        if (coordinate == null || coordinate.name() == null || coordinate.name().isBlank()) {
            ParseIssue issue = new ParseIssue(module, format, ParseIssueType.FIELD_MISSING,
                    "依赖条目缺少组件名称(name/artifactId)，已跳过该条目", rawSnippet);
            issues.add(issue);
            log.warn("模块[{}]字段缺失: {}", module, issue.detail());
            return;
        }
        if (version == null || version.isBlank()) {
            ParseIssue issue = new ParseIssue(module, format, ParseIssueType.FIELD_MISSING,
                    "组件[" + coordinate.normalizedKey() + "]缺少版本号，无法做版本级漏洞判定，已跳过", rawSnippet);
            issues.add(issue);
            log.warn("模块[{}]字段缺失: {}", module, issue.detail());
            return;
        }
        String key = coordinate.normalizedKey();
        String exact = key + "@" + version;
        if (!exactSeen.add(exact)) {
            ParseIssue issue = ParseIssue.of(module, format, ParseIssueType.DUPLICATE_REFERENCE,
                    "重复引用: " + key + "@" + version + "，去重后仅保留一条");
            issues.add(issue);
            log.info("模块[{}]{}", module, issue.detail());
            return;
        }
        Set<String> versions = versionsByComponent.computeIfAbsent(key, k -> {
            coordinates.put(k, coordinate);
            return new LinkedHashSet<>();
        });
        if (!versions.isEmpty()) {
            ParseIssue issue = ParseIssue.of(module, format, ParseIssueType.MULTIPLE_VERSIONS,
                    "同一组件[" + key + "]在本模块出现多版本: " + versions + " 与 " + version
                            + "，全部保留并在结论中标记版本冲突");
            issues.add(issue);
            log.warn("模块[{}]{}", module, issue.detail());
        }
        versions.add(version);
    }

    /** 清单解析结束后产出有效依赖（每个 组件+版本 一条，保持出现顺序）。 */
    List<DependencyRef> dependencies() {
        List<DependencyRef> refs = new ArrayList<>();
        for (Map.Entry<String, Set<String>> entry : versionsByComponent.entrySet()) {
            ComponentCoordinate coordinate = coordinates.get(entry.getKey());
            for (String version : entry.getValue()) {
                refs.add(new DependencyRef(coordinate, version, module));
            }
        }
        return refs;
    }

    List<ParseIssue> issues() {
        return issues;
    }
}

package com.github.xingjianluo.localsupplychainauditjava.engine;

import com.github.xingjianluo.localsupplychainauditjava.model.ComponentCoordinate;
import com.github.xingjianluo.localsupplychainauditjava.model.DependencyRef;
import com.github.xingjianluo.localsupplychainauditjava.model.MergedComponent;
import com.github.xingjianluo.localsupplychainauditjava.model.ParseIssue;
import com.github.xingjianluo.localsupplychainauditjava.model.ParseIssueType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 扫描级增量聚合器：各模块解析出的依赖引用按坐标即时合并，
 * 不再额外保留逐版本引用中间列表，保证大清单扫描时组件信息在内存中只存一份。
 *
 * <p>跨模块共享组件给出一条汇总式 DUPLICATE_REFERENCE 结论；
 * 跨模块多版本给出 MULTIPLE_VERSIONS 汇总（模块内多版本由解析器逐条给出）。
 * 非线程安全：扫描引擎在单线程执行模型内使用。
 */
class ComponentAccumulator {

    private static final Logger log = LoggerFactory.getLogger(ComponentAccumulator.class);

    private final Map<String, Entry> entries = new LinkedHashMap<>();

    void addAll(List<DependencyRef> refs) {
        for (DependencyRef ref : refs) {
            String key = ref.coordinate().normalizedKey();
            Entry entry = entries.computeIfAbsent(key,
                    k -> new Entry(ref.coordinate(), new LinkedHashSet<>(), new LinkedHashSet<>()));
            entry.versions.add(ref.version());
            entry.referencedBy.add(ref.module());
        }
    }

    /** 生成不可变合并组件及跨模块层面结论。 */
    MergeView snapshot() {
        List<MergedComponent> components = new ArrayList<>(entries.size());
        List<ParseIssue> issues = new ArrayList<>();
        for (Entry e : entries.values()) {
            components.add(new MergedComponent(e.coordinate,
                    Set.copyOf(e.versions), Set.copyOf(e.referencedBy)));
            if (e.referencedBy.size() > 1) {
                issues.add(ParseIssue.of(null, null, ParseIssueType.DUPLICATE_REFERENCE,
                        "组件[" + e.coordinate.normalizedKey() + "]被 " + e.referencedBy.size()
                                + " 个模块共同引用 " + e.referencedBy + "，已合并去重为单个风险对象"));
            }
            if (e.versions.size() > 1) {
                issues.add(ParseIssue.of(null, null, ParseIssueType.MULTIPLE_VERSIONS,
                        "组件[" + e.coordinate.normalizedKey() + "]跨模块存在 " + e.versions.size()
                                + " 个不同版本 " + e.versions + "（引用模块 " + e.referencedBy
                                + "），各版本分别参与漏洞判定"));
            }
        }
        log.info("跨模块增量聚合视图已生成: 去重后组件={} 汇总结论={}", components.size(), issues.size());
        return new MergeView(List.copyOf(components), List.copyOf(issues));
    }

    /** 紧凑匹配视图：坐标 -> 版本/模块集合，供漏洞匹配直接遍历。 */
    Map<ComponentCoordinate, VulnMatcher.ComponentVersionAggregate> matchingView() {
        Map<ComponentCoordinate, VulnMatcher.ComponentVersionAggregate> view = new LinkedHashMap<>();
        for (Entry e : entries.values()) {
            view.put(e.coordinate,
                    new VulnMatcher.ComponentVersionAggregate(e.versions, e.referencedBy));
        }
        return Map.copyOf(view);
    }

    private record Entry(ComponentCoordinate coordinate, Set<String> versions,
                         Set<String> referencedBy) {
    }

    record MergeView(List<MergedComponent> components, List<ParseIssue> issues) {
    }
}

package com.github.xingjianluo.localsupplychainauditjava.engine;

import com.github.xingjianluo.localsupplychainauditjava.model.ComponentCoordinate;
import com.github.xingjianluo.localsupplychainauditjava.model.Finding;
import com.github.xingjianluo.localsupplychainauditjava.model.VulnLibrary;
import com.github.xingjianluo.localsupplychainauditjava.model.VulnRule;
import com.github.xingjianluo.localsupplychainauditjava.vuln.VersionMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 漏洞匹配器：以 组件@版本 聚合粒度做区间判定，再按 (ruleId, 坐标) 合并命中。
 * 同一组件被多个模块引用、或存在多版本时，风险只输出一条并聚合版本/模块集合。
 * 遍历的是扫描期增量聚合结构，不额外构造逐版本引用列表。
 */
@Component
public class VulnMatcher {

    private static final Logger log = LoggerFactory.getLogger(VulnMatcher.class);

    private final VersionMatcher versionMatcher;

    public VulnMatcher(VersionMatcher versionMatcher) {
        this.versionMatcher = versionMatcher;
    }

    /**
     * 对聚合后的组件表做匹配。
     *
     * @param aggregated key=归一坐标，value=[版本集合, 引用模块集合]
     */
    public List<Finding> match(Map<ComponentCoordinate, ComponentVersionAggregate> aggregated,
                               VulnLibrary library) {
        Map<String, FindingAggregate> findings = new java.util.LinkedHashMap<>();
        long checks = 0;
        for (Map.Entry<ComponentCoordinate, ComponentVersionAggregate> e : aggregated.entrySet()) {
            ComponentCoordinate coordinate = e.getKey();
            List<VulnRule> rules = library.rulesFor(coordinate);
            if (rules.isEmpty()) {
                continue;
            }
            for (String version : e.getValue().versions()) {
                for (VulnRule rule : rules) {
                    checks++;
                    if (versionMatcher.isAffected(version,
                            rule.vulnerableRangeLowInclusive(),
                            rule.vulnerableRangeHighExclusive())) {
                        String key = rule.id() + "@" + coordinate.normalizedKey();
                        FindingAggregate agg = findings.computeIfAbsent(key,
                                k -> new FindingAggregate(rule, new LinkedHashSet<>(),
                                        new LinkedHashSet<>()));
                        agg.affectedVersions.add(version);
                        agg.referencedBy.addAll(e.getValue().referencedBy());
                        log.info("命中漏洞: rule={} component={} version={} modules={} lib={}/{}",
                                rule.id(), coordinate.normalizedKey(), version,
                                e.getValue().referencedBy(), library.libraryId(),
                                library.version());
                    }
                }
            }
        }
        List<Finding> result = new ArrayList<>(findings.size());
        for (FindingAggregate agg : findings.values()) {
            VulnRule rule = agg.rule;
            result.add(new Finding(rule.id(), rule.coordinate(), rule.title(), rule.severity(),
                    Set.copyOf(agg.affectedVersions), Set.copyOf(agg.referencedBy),
                    rule.fixedIn()));
        }
        log.info("漏洞匹配完成: 规则检查次数={} 合并后命中={} lib={}/{}",
                checks, result.size(), library.libraryId(), library.version());
        return List.copyOf(result);
    }

    /** 一个组件坐标下聚合到的版本集合与引用模块集合（与引擎聚合视图共用底层集合）。 */
    public record ComponentVersionAggregate(Set<String> versions, Set<String> referencedBy) {
    }

    private static final class FindingAggregate {
        private final VulnRule rule;
        private final Set<String> affectedVersions;
        private final Set<String> referencedBy;

        private FindingAggregate(VulnRule rule, Set<String> affectedVersions,
                                 Set<String> referencedBy) {
            this.rule = rule;
            this.affectedVersions = affectedVersions;
            this.referencedBy = referencedBy;
        }
    }
}

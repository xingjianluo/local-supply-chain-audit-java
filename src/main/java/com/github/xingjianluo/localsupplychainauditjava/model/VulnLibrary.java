package com.github.xingjianluo.localsupplychainauditjava.model;

import java.util.List;
import java.util.Map;

/**
 * 本地漏洞库的一个不可变版本。规则按组件坐标索引。
 */
public record VulnLibrary(String libraryId,
                          String version,
                          long loadedAtEpochMillis,
                          int ruleCount,
                          Map<ComponentCoordinate, List<VulnRule>> rulesByCoordinate) {

    public List<VulnRule> rulesFor(ComponentCoordinate coordinate) {
        return rulesByCoordinate.getOrDefault(coordinate, List.of());
    }
}

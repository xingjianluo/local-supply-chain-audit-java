package com.github.xingjianluo.localsupplychainauditjava.model;

/**
 * 本地漏洞库中的一条规则：组件坐标 + 受影响版本区间 + 修复版本。
 * 区间采用 [vulnerableRangeLow, vulnerableRangeHigh) 语义；高/低界可为空表示不限制。
 */
public record VulnRule(String id,
                       ComponentCoordinate coordinate,
                       String vulnerableRangeLowInclusive,
                       String vulnerableRangeHighExclusive,
                       String fixedIn,
                       String title,
                       String severity) {
}

package com.github.xingjianluo.localsupplychainauditjava.model;

import java.util.Set;

/**
 * 一条漏洞命中结论。同一 (ruleId, coordinate) 在多模块/多版本引用时合并去重，
 * affectedVersions / referencedBy 为合并后的集合。
 */
public record Finding(String ruleId,
                      ComponentCoordinate coordinate,
                      String title,
                      String severity,
                      Set<String> affectedVersions,
                      Set<String> referencedBy,
                      String fixedIn) {
}

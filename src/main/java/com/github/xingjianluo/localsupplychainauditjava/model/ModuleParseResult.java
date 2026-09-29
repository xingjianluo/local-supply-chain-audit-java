package com.github.xingjianluo.localsupplychainauditjava.model;

import java.util.List;

/**
 * 单个模块的解析产物：有效依赖引用 + 该模块清单上的全部结论（含去重/多版本/损坏等）。
 */
public record ModuleParseResult(String module,
                                ManifestFormat format,
                                List<DependencyRef> dependencies,
                                List<ParseIssue> issues) {
}

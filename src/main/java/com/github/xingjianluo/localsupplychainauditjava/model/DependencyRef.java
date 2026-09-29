package com.github.xingjianluo.localsupplychainauditjava.model;

/** 清单中解析出的一条依赖引用：组件坐标 + 版本 + 来源模块。 */
public record DependencyRef(ComponentCoordinate coordinate, String version, String module) {
}

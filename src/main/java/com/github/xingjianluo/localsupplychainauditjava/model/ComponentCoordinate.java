package com.github.xingjianluo.localsupplychainauditjava.model;

/**
 * 归一化后的组件坐标，跨生态统一为 (ecosystem, group, name)。
 * group 在无分组生态（npm/pypi）下为空串。
 */
public record ComponentCoordinate(String ecosystem, String group, String name) {

    public String normalizedKey() {
        return ecosystem + "|" + (group == null ? "" : group) + "|" + name;
    }
}

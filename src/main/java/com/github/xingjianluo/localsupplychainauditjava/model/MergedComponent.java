package com.github.xingjianluo.localsupplychainauditjava.model;

import java.util.List;
import java.util.Set;

/**
 * 跨模块合并去重后的组件视图。
 * 同一组件坐标下出现多个不同版本时 versions 含多值，referencedBy 为引用它的模块集合。
 */
public record MergedComponent(ComponentCoordinate coordinate,
                              Set<String> versions,
                              Set<String> referencedBy) {

    public boolean hasVersionConflict() {
        return versions.size() > 1;
    }
}

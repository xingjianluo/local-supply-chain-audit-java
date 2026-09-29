package com.github.xingjianluo.localsupplychainauditjava.model;

/**
 * Identifies one engineering module (manifest file) that a dependency was declared in.
 *
 * @param moduleId stable identifier of the module, e.g. module name or file path
 */
public record ModuleRef(String moduleId) {
    public ModuleRef {
        if (moduleId == null || moduleId.isBlank()) {
            throw new IllegalArgumentException("moduleId must not be blank");
        }
    }
}

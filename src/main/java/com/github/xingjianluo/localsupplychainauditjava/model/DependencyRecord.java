package com.github.xingjianluo.localsupplychainauditjava.model;

import java.util.Set;

/**
 * One raw dependency declaration as read from a manifest.
 *
 * @param group    component group / namespace (may be null when missing)
 * @param name     component name (may be null when missing)
 * @param version  declared version (may be null when missing)
 * @param scope    dependency scope such as compile/test (may be null)
 * @param modules  every module that references this exact coordinate/version
 * @param issues   field-level issues detected for this record
 */
public record DependencyRecord(String group, String name, String version, String scope,
                               Set<ModuleRef> modules, java.util.List<ManifestIssue> issues) {
}

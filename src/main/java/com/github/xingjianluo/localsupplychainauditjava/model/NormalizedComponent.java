package com.github.xingjianluo.localsupplychainauditjava.model;

import java.util.List;
import java.util.Set;

/**
 * A unique component (group:name) after normalization, aggregating every version
 * and every module reference found across all input manifests.
 *
 * @param group          component group / namespace
 * @param name           component name
 * @param versions       distinct versions declared for this component
 * @param modules        distinct modules referencing this component (any version)
 * @param versionModules maps each version to the modules declaring it
 * @param issues         aggregated field-level issues (duplicate / multi-version etc.)
 */
public record NormalizedComponent(String group, String name, Set<String> versions,
                                  Set<ModuleRef> modules,
                                  java.util.Map<String, Set<ModuleRef>> versionModules,
                                  List<ManifestIssue> issues) {
}

package com.github.xingjianluo.localsupplychainauditjava.model;

import java.util.Comparator;
import java.util.List;
import java.util.Set;

/**
 * Merged risk conclusion for one unique component (group:name).
 * Vulnerabilities matching any referenced version are de-duplicated by vulnId.
 *
 * @param group       component group
 * @param name        component name
 * @param versions    all declared versions
 * @param modules     all referencing modules, merged and de-duplicated
 * @param matched     de-duplicated findings for this component
 */
public record ComponentRisk(String group, String name, Set<String> versions,
                            Set<ModuleRef> modules, List<RiskFinding> matched) {

    /** Highest severity among matched findings, or null when nothing matched. */
    public RiskLevel highestLevel() {
        return matched.stream().map(RiskFinding::level)
                .min(Comparator.comparingInt(Enum::ordinal))
                .orElse(null);
    }
}

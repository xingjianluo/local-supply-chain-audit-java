package com.github.xingjianluo.localsupplychainauditjava.scan;

import com.github.xingjianluo.localsupplychainauditjava.model.*;
import com.github.xingjianluo.localsupplychainauditjava.vuln.VersionMatcher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Evaluates normalized components against one immutable {@link VulnDatabase}
 * snapshot. Each concrete version is tested; when one vulnId matches several
 * versions the findings are merged into one {@link RiskFinding} (de-duplicated).
 * Components referenced by several modules carry the merged module set so risk
 * is never double-counted per module.
 */
@Component
public class RiskEvaluator {

    private static final Logger log = LoggerFactory.getLogger(RiskEvaluator.class);

    public List<ComponentRisk> evaluate(Map<String, NormalizedComponent> components,
                                        VulnDatabase db) {
        // group:name -> entries, built once per evaluation for O(1) lookup on large inputs.
        Map<String, List<VulnerabilityEntry>> index = new LinkedHashMap<>();
        for (VulnerabilityEntry entry : db.entries()) {
            index.computeIfAbsent(entry.group() + ":" + entry.name(), k -> new ArrayList<>()).add(entry);
        }

        List<ComponentRisk> risks = new ArrayList<>();
        int componentsAtRisk = 0;
        int findingsTotal = 0;
        for (Map.Entry<String, NormalizedComponent> mapEntry : components.entrySet()) {
            NormalizedComponent component = mapEntry.getValue();
            if (component.group() == null || component.name() == null) {
                // uncoordinated placeholder; it has no risk evaluation
                continue;
            }
            List<VulnerabilityEntry> candidates =
                    index.get(component.group() + ":" + component.name());
            Map<String, RiskFinding> merged = new LinkedHashMap<>();
            if (candidates != null) {
                for (String version : component.versions()) {
                    if (DependencyNormalizer.MISSING_VERSION.equals(version)) {
                        log.debug("Version missing for '{}', skipped in vuln matching", mapEntry.getKey());
                        continue;
                    }
                    for (VulnerabilityEntry entry : candidates) {
                        boolean affected = entry.ranges().isEmpty()
                                || entry.ranges().stream().anyMatch(r -> VersionMatcher.inRange(version, r));
                        if (affected) {
                            mergeFinding(merged, entry, version);
                            log.info("MATCH {}:{} -> {} ({}) [vulndb {}]",
                                    mapEntry.getKey(), version, entry.vulnId(), entry.level(),
                                    db.versionId());
                        }
                    }
                }
            }
            List<RiskFinding> findings = new ArrayList<>(merged.values());
            findings.sort(Comparator
                    .comparing((RiskFinding f) -> f.level().ordinal())
                    .thenComparing(RiskFinding::vulnId));
            if (!findings.isEmpty()) {
                componentsAtRisk++;
                findingsTotal += findings.size();
            }
            risks.add(new ComponentRisk(component.group(), component.name(),
                    new LinkedHashSet<>(component.versions()),
                    new LinkedHashSet<>(component.modules()), findings));
        }
        log.info("Risk evaluation against vulndb {} complete: {} component(s) at risk, {} finding(s)",
                db.versionId(), componentsAtRisk, findingsTotal);
        return risks;
    }

    private void mergeFinding(Map<String, RiskFinding> merged,
                              VulnerabilityEntry entry, String affectedVersion) {
        RiskFinding existing = merged.get(entry.vulnId());
        if (existing == null) {
            Set<String> versions = new LinkedHashSet<>();
            versions.add(affectedVersion);
            merged.put(entry.vulnId(), new RiskFinding(entry.vulnId(), entry.level(),
                    entry.title(), versions, entry.fixedIn()));
        } else {
            existing.affectedVersions().add(affectedVersion);
        }
    }
}

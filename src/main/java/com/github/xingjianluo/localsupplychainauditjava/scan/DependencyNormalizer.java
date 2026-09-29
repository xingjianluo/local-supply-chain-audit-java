package com.github.xingjianluo.localsupplychainauditjava.scan;

import com.github.xingjianluo.localsupplychainauditjava.model.DependencyRecord;
import com.github.xingjianluo.localsupplychainauditjava.model.IssueType;
import com.github.xingjianluo.localsupplychainauditjava.model.ManifestIssue;
import com.github.xingjianluo.localsupplychainauditjava.model.ManifestResult;
import com.github.xingjianluo.localsupplychainauditjava.model.ModuleRef;
import com.github.xingjianluo.localsupplychainauditjava.model.NormalizedComponent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Merges raw dependency records across multiple modules/formats into unique
 * {@code group:name} components. Nothing is dropped: duplicate references
 * (same coordinate+version declared more than once by the same module) and
 * multi-version conflicts (one component resolving to several versions) are
 * recorded as distinguishable issues on the normalized component, and records
 * lacking coordinates are counted and reported separately.
 */
@Component
public class DependencyNormalizer {

    private static final Logger log = LoggerFactory.getLogger(DependencyNormalizer.class);

    /** Sentinel used internally when a declared version is missing. */
    static final String MISSING_VERSION = "<missing-version>";

    /**
     * Normalize all manifests.
     *
     * @param manifests per-manifest parser conclusions
     * @return ordered map of componentKey -> normalized component; also contains a
     *         synthetic key {@code <uncoordinated>} counting records with missing
     *         group/name when such records exist
     */
    public Map<String, NormalizedComponent> normalize(List<ManifestResult> manifests) {
        Map<String, Accumulator> accumulators = new LinkedHashMap<>();
        int uncoordinated = 0;
        int rawRecordCount = 0;

        for (ManifestResult manifest : manifests) {
            ModuleRef module = new ModuleRef(manifest.moduleId());
            for (DependencyRecord record : manifest.records()) {
                rawRecordCount++;
                if (record.group() == null || record.name() == null) {
                    uncoordinated++;
                    log.warn("Skipping aggregation for uncoordinated record {}:{} in module '{}' "
                            + "(already reported as manifest issue)", record.group(), record.name(),
                            manifest.moduleId());
                    continue;
                }
                String key = componentKey(record.group(), record.name());
                Accumulator acc = accumulators.computeIfAbsent(key,
                        k -> new Accumulator(record.group(), record.name()));
                acc.add(record, module);
            }
        }

        Map<String, NormalizedComponent> result = new LinkedHashMap<>();
        for (Map.Entry<String, Accumulator> entry : accumulators.entrySet()) {
            NormalizedComponent component = entry.getValue().build();
            if (!component.issues().isEmpty()) {
                log.warn("Component '{}' normalized with {} issue(s): duplicates={}, versions={}",
                        entry.getKey(), component.issues().size(), component.versions(), component.modules());
            } else {
                log.debug("Component '{}' normalized: versions={}, modules={}",
                        entry.getKey(), component.versions(), component.modules());
            }
            result.put(entry.getKey(), component);
        }
        if (uncoordinated > 0) {
            ManifestIssue issue = new ManifestIssue(IssueType.MISSING_COORDINATE,
                    uncoordinated + " record(s) lacked group or name and could not be aggregated; "
                            + "see per-manifest issues for details");
            NormalizedComponent placeholder = new NormalizedComponent(null, null, Set.of(),
                    Set.of(), Map.of(), List.of(issue));
            result.put("<uncoordinated>", placeholder);
            log.warn("{} uncoordinated record(s) reported under '<uncoordinated>'", uncoordinated);
        }
        log.info("Normalized {} raw record(s) into {} component(s) (uncoordinated={})",
                rawRecordCount, result.size(), uncoordinated);
        return result;
    }

    String componentKey(String group, String name) {
        return group + ":" + name;
    }

    /** Mutable per-component aggregation state. */
    private static final class Accumulator {
        private final String group;
        private final String name;
        private final Set<String> versions = new LinkedHashSet<>();
        private final Set<ModuleRef> modules = new LinkedHashSet<>();
        private final Map<String, Set<ModuleRef>> versionModules = new LinkedHashMap<>();
        private final List<ManifestIssue> issues = new ArrayList<>();
        /** coordinate+version -> modules already counted, for duplicate detection. */
        private final Map<String, Set<String>> seenByModule = new LinkedHashMap<>();

        private Accumulator(String group, String name) {
            this.group = group;
            this.name = name;
        }

        private void add(DependencyRecord record, ModuleRef module) {
            String version = record.version() == null ? MISSING_VERSION : record.version();
            String moduleId = module.moduleId();

            Set<String> seenModules = seenByModule.computeIfAbsent(version, k -> new LinkedHashSet<>());
            if (!seenModules.add(moduleId)) {
                issues.add(new ManifestIssue(IssueType.DUPLICATE_REFERENCE,
                        "duplicate reference of " + group + ":" + name + ":" + version
                                + " in module '" + moduleId + "'"));
            }
            versions.add(version);
            modules.add(module);
            versionModules.computeIfAbsent(version, v -> new LinkedHashSet<>()).add(module);
        }

        private NormalizedComponent build() {
            long realVersions = versions.stream().filter(v -> !MISSING_VERSION.equals(v)).count();
            if (realVersions > 1) {
                issues.add(new ManifestIssue(IssueType.MULTI_VERSION_CONFLICT,
                        "component '" + group + ":" + name + "' is referenced with multiple versions "
                                + sorted(versions) + "; all versions are evaluated"));
            }
            return new NormalizedComponent(group, name,
                    new LinkedHashSet<>(versions), new LinkedHashSet<>(modules),
                    new LinkedHashMap<>(versionModules), List.copyOf(issues));
        }

        private List<String> sorted(Set<String> values) {
            List<String> list = new ArrayList<>(values);
            list.sort(String::compareTo);
            return list;
        }
    }
}

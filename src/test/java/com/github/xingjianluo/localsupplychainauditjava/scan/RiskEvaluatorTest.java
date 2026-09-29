package com.github.xingjianluo.localsupplychainauditjava.scan;

import com.github.xingjianluo.localsupplychainauditjava.model.*;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** Risk matching against a bound snapshot: de-duplication, merged versions/modules, safe versions. */
class RiskEvaluatorTest {

    private static final Logger log = LoggerFactory.getLogger(RiskEvaluatorTest.class);
    private final RiskEvaluator evaluator = new RiskEvaluator();

    private NormalizedComponent component(String group, String name,
                                          List<String> versions, List<String> modules) {
        Map<String, Set<ModuleRef>> versionModules = new LinkedHashMap<>();
        Set<ModuleRef> moduleRefs = new LinkedHashSet<>();
        for (String v : versions) {
            Set<ModuleRef> refs = new LinkedHashSet<>();
            for (String m : modules) {
                refs.add(new ModuleRef(m));
            }
            versionModules.put(v, refs);
            moduleRefs.addAll(refs);
        }
        return new NormalizedComponent(group, name, new LinkedHashSet<>(versions),
                moduleRefs, versionModules, List.of());
    }

    private VulnDatabase db(VulnerabilityEntry... entries) {
        return new VulnDatabase("vdb-test", Instant.now(), null, List.of(entries));
    }

    private VulnerabilityEntry entry() {
        return new VulnerabilityEntry("V-1", "g", "n",
                List.of(new AffectedRange("1.0", "2.0")), "2.0",
                RiskLevel.HIGH, "title", "desc");
    }

    @Test
    void findingMergedAcrossVersionsAndModules() {
        // Component present in two modules, one vulnerable and one fixed version.
        NormalizedComponent c = component("g", "n", List.of("1.1", "2.0"), List.of("a", "b"));
        log.info("INPUT g:n versions [1.1,2.0] modules [a,b]; BASIS: range [1.0,2.0)");
        List<ComponentRisk> risks = evaluator.evaluate(Map.of("g:n", c), db(entry()));
        ComponentRisk risk = risks.get(0);
        assertEquals(2, risk.modules().size(), "modules merged/deduplicated");
        assertEquals(1, risk.matched().size(), "one vulnId merged into one finding");
        assertEquals(Set.of("1.1"), risk.matched().get(0).affectedVersions(),
                "only the vulnerable version is listed; 2.0 is fixed");
        assertEquals(RiskLevel.HIGH, risk.highestLevel());
        log.info("STATE/VERDICT: finding V-1 affectedVersions={}, modules={}",
                risk.matched().get(0).affectedVersions(), risk.modules());
    }

    @Test
    void noMatchForSafeVersion() {
        NormalizedComponent c = component("g", "n", List.of("2.0"), List.of("a"));
        log.info("INPUT g:n version 2.0; BASIS: upper bound 2.0 exclusive -> safe");
        List<ComponentRisk> risks = evaluator.evaluate(Map.of("g:n", c), db(entry()));
        assertTrue(risks.get(0).matched().isEmpty());
        assertNull(risks.get(0).highestLevel());
        log.info("STATE/VERDICT: no finding, highestLevel=null");
    }

    @Test
    void componentsAreBoundToSpecificSnapshotVersion() {
        NormalizedComponent c = component("g", "n", List.of("1.1"), List.of("a"));
        VulnDatabase emptyDb = new VulnDatabase("vdb-empty", Instant.now(), null, List.of());
        log.info("INPUT same component vs snapshot vdb-empty; BASIS: snapshot has no matching entry");
        List<ComponentRisk> risks = evaluator.evaluate(Map.of("g:n", c), emptyDb);
        assertTrue(risks.get(0).matched().isEmpty(),
                "conclusion depends solely on the bound snapshot version");
        log.info("STATE/VERDICT: empty/older snapshot -> clean result, reproducible by version");
    }
}

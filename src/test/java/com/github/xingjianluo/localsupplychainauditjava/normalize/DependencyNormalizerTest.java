package com.github.xingjianluo.localsupplychainauditjava.normalize;

import com.github.xingjianluo.localsupplychainauditjava.model.*;
import com.github.xingjianluo.localsupplychainauditjava.scan.DependencyNormalizer;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** Cross-module normalization: duplicate references, multi-version conflicts, missing coordinates. */
class DependencyNormalizerTest {

    private static final Logger log = LoggerFactory.getLogger(DependencyNormalizerTest.class);
    private final DependencyNormalizer normalizer = new DependencyNormalizer();

    private DependencyRecord dep(String group, String name, String version, String moduleId) {
        return new DependencyRecord(group, name, version, "compile",
                new LinkedHashSet<>(Set.of(new ModuleRef(moduleId))), List.of());
    }

    private ManifestResult manifest(String moduleId, DependencyRecord... records) {
        return new ManifestResult(moduleId, ManifestFormat.JSON_SBOM, ManifestStatus.PARSED,
                moduleId, List.of(records), List.of());
    }

    @Test
    void duplicateReferenceInSameModuleIsDetectedButKeptOnce() {
        log.info("INPUT: g:n:1.0 declared twice by module 'a'");
        var result = normalizer.normalize(List.of(
                manifest("a", dep("g", "n", "1.0", "a"), dep("g", "n", "1.0", "a"))));
        NormalizedComponent c = result.get("g:n");
        assertNotNull(c);
        assertEquals(1, c.versions().size());
        assertEquals(1, c.modules().size());
        assertTrue(c.issues().stream().anyMatch(i -> i.type() == IssueType.DUPLICATE_REFERENCE));
        log.info("STATE/VERDICT: one component/version/module kept, DUPLICATE_REFERENCE issued");
    }

    @Test
    void sameVersionAcrossDifferentModulesIsNotDuplicate() {
        log.info("INPUT: g:n:1.0 referenced by modules 'a' and 'b'");
        var result = normalizer.normalize(List.of(
                manifest("a", dep("g", "n", "1.0", "a")),
                manifest("b", dep("g", "n", "1.0", "b"))));
        NormalizedComponent c = result.get("g:n");
        assertEquals(2, c.modules().size());
        assertTrue(c.issues().isEmpty(), "shared dependency across modules is legitimate");
        log.info("STATE/VERDICT: modules merged to 2, no duplicate issue");
    }

    @Test
    void multiVersionConflictIsReportedExplicitly() {
        log.info("INPUT: g:n versions 1.0 (module a) and 2.0 (module b)");
        var result = normalizer.normalize(List.of(
                manifest("a", dep("g", "n", "1.0", "a")),
                manifest("b", dep("g", "n", "2.0", "b"))));
        NormalizedComponent c = result.get("g:n");
        assertEquals(Set.of("1.0", "2.0"), c.versions());
        assertTrue(c.issues().stream().anyMatch(i -> i.type() == IssueType.MULTI_VERSION_CONFLICT),
                "multiple versions must produce an explicit conflict conclusion");
        log.info("STATE/VERDICT: both versions retained and MULTI_VERSION_CONFLICT issued");
    }

    @Test
    void uncoordinatedRecordsAreReportedNotDropped() {
        log.info("INPUT: record with null group and name, plus one valid record");
        var result = normalizer.normalize(List.of(
                manifest("a", dep(null, null, "1.0", "a"), dep("g", "n", "1.0", "a"))));
        assertTrue(result.containsKey("<uncoordinated>"));
        assertEquals(IssueType.MISSING_COORDINATE,
                result.get("<uncoordinated>").issues().get(0).type());
        assertNotNull(result.get("g:n"));
        log.info("STATE/VERDICT: uncoordinated record counted under placeholder, valid record still normalized");
    }
}

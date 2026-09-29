package com.github.xingjianluo.localsupplychainauditjava.scan;

import com.github.xingjianluo.localsupplychainauditjava.model.*;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end tests through the Spring-managed coordinator: mixed formats,
 * multi-module dedup, corrupt-file isolation and version-bound conclusions.
 */
@SpringBootTest
class ScanEndToEndTest {

    private static final Logger log = LoggerFactory.getLogger(ScanEndToEndTest.class);

    @Autowired
    private ScanCoordinator coordinator;

    private String resourcePath(String name) {
        return "src/test/resources/sample-manifests/" + name;
    }

    @Test
    void mixedFormatsMultiModulesCorruptFileAndRiskMerge() throws Exception {
        String corruptJson = "{ this is not json";
        ScanRequest request = new ScanRequest(List.of(
                new ManifestInput("module-a", null, resourcePath("module-a-pom.xml"), null),
                new ManifestInput("module-b", null, resourcePath("module-b-sbom.json"), null),
                new ManifestInput("broken-module", ManifestFormat.JSON_SBOM, null, corruptJson)));

        log.info("INPUT: 3 manifests (POM file, JSON file, inline corrupt JSON)");
        ScanResult accepted = coordinator.start(request);
        coordinator.awaitIdle(10000);
        ScanResult result = coordinator.get(accepted.scanId()).orElseThrow();

        assertEquals(ScanStatus.SUCCEEDED, result.status(), "one bad file must not fail the scan");
        assertNotNull(result.vulnDbVersion(), "conclusion must be bound to a vulndb version");
        log.info("STATE: scan succeeded bound to vulndb {}", result.vulnDbVersion());

        // Per-manifest outcomes must be distinguishable.
        assertEquals(3, result.manifests().size());
        assertEquals(ManifestStatus.PARSED, statusOf(result, "module-a"));
        assertEquals(ManifestStatus.PARSED, statusOf(result, "module-b"));
        assertEquals(ManifestStatus.CORRUPT, statusOf(result, "broken-module"));
        log.info("STATE: manifest statuses a=PARSED b=PARSED broken=CORRUPT (counted, not fatal)");

        // risky-lib 1.1.0 appears in both modules -> merged once, with both modules.
        ComponentRisk risky = riskFor(result, "com.example", "risky-lib");
        assertNotNull(risky);
        assertEquals(2, risky.modules().size(), "modules referencing the component are merged");
        assertEquals(1, risky.matched().size(), "vuln findings de-duplicated by vulnId");
        assertTrue(risky.matched().get(0).affectedVersions().contains("1.1.0"));
        // module-b also declares the fixed 1.2.0 -> it appears as a version but is not flagged.
        assertTrue(risky.versions().contains("1.2.0"));
        assertFalse(risky.matched().get(0).affectedVersions().contains("1.2.0"));
        log.info("VERDICT: risky-lib finding merged; affected={}, allVersions={}, modules={}",
                risky.matched().get(0).affectedVersions(), risky.versions(), risky.modules());

        // CRITICAL logkit 1.9.0 flagged; safe-lib 4.0.0 present without findings.
        assertNotNull(riskFor(result, "org.apache.logging", "logkit"));
        ComponentRisk safe = riskFor(result, "com.example", "safe-lib");
        assertNotNull(safe);
        assertTrue(safe.matched().isEmpty());
        // Default-plugin-group plugin from the POM participates in matching too.
        ComponentRisk plugin = riskFor(result, "org.apache.maven.plugins", "build-plugin");
        assertNotNull(plugin);
        assertEquals(1, plugin.matched().size());

        ScanSummary summary = result.summary();
        assertEquals(3, summary.manifestTotal());
        assertEquals(1, summary.manifestCorrupt());
        assertTrue(summary.componentsAtRisk() >= 3);
        assertTrue(summary.critical() >= 1);
        log.info("VERDICT: summary corrupt={}, componentsAtRisk={}, critical={}, findings={}",
                summary.manifestCorrupt(), summary.componentsAtRisk(),
                summary.critical(), summary.findingTotal());
    }

    private ManifestStatus statusOf(ScanResult result, String moduleId) {
        return result.manifests().stream()
                .filter(m -> m.moduleId().equals(moduleId)).findFirst().orElseThrow().status();
    }

    private ComponentRisk riskFor(ScanResult result, String group, String name) {
        return result.risks().stream()
                .filter(r -> r.group().equals(group) && r.name().equals(name))
                .findFirst().orElse(null);
    }
}

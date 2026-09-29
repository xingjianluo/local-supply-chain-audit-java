package com.github.xingjianluo.localsupplychainauditjava.scan;

import com.github.xingjianluo.localsupplychainauditjava.model.*;
import com.github.xingjianluo.localsupplychainauditjava.parse.FormatDetector;
import com.github.xingjianluo.localsupplychainauditjava.parse.JsonSbomParser;
import com.github.xingjianluo.localsupplychainauditjava.parse.PomManifestParser;
import com.github.xingjianluo.localsupplychainauditjava.vuln.LocalVulnRepository;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Boundedness smoke test: a 10k-component manifest completes with compact
 * per-component results, and cancellation between batches leaves no result.
 */
class LargeManifestScanTest {

    private static final Logger log = LoggerFactory.getLogger(LargeManifestScanTest.class);
    private static final int N = 10_000;

    private ScanEngine engine() {
        return new ScanEngine(new LocalVulnRepository(), TestPaths.vulndbV1(),
                new FormatDetector(),
                List.of(new PomManifestParser(), new JsonSbomParser()),
                new DependencyNormalizer(), new RiskEvaluator());
    }

    private String largeJson() {
        StringBuilder sb = new StringBuilder("{\"components\":[");
        for (int i = 0; i < N; i++) {
            if (i > 0) {
                sb.append(',');
            }
            // Mostly unique components so normalization holds N compact entries.
            sb.append("{\"group\":\"g").append(i % 50).append("\",\"name\":\"n").append(i)
                    .append("\",\"version\":\"").append(1 + i % 5).append(".0\"}");
        }
        return sb.append("]}").toString();
    }

    @Test
    void largeManifestCompletesWithBoundedSummary() {
        String body = largeJson();
        log.info("INPUT one JSON manifest with {} components ({} chars)", N, body.length());
        long heapBefore = usedHeapMb();
        ScanRequest request = new ScanRequest(List.of(
                new ManifestInput("big", ManifestFormat.JSON_SBOM, null, body)));
        ScanResult result = engine().run("scan-large", request, new AtomicBoolean(false));
        long heapAfter = usedHeapMb();
        assertEquals(ScanStatus.SUCCEEDED, result.status());
        assertEquals(N, result.summary().componentCount());
        log.info("VERDICT: {} components scanned; heap delta ~{}MB; findings={}",
                N, heapAfter - heapBefore, result.summary().findingTotal());
        assertTrue(result.summary().manifestCorrupt() == 0);
    }

    @Test
    void cancellationBeforeStartProducesNoResult() {
        log.info("INPUT pre-canceled flag with {} manifests; BASIS: first batch checks flag", N);
        AtomicBoolean canceled = new AtomicBoolean(true);
        ScanRequest request = new ScanRequest(List.of(
                new ManifestInput("big", ManifestFormat.JSON_SBOM, null, largeJson())));
        ScanResult result = engine().run("scan-canceled", request, canceled);
        assertNull(result, "cooperatively canceled scan must publish no half-finished result");
        log.info("VERDICT: engine returned null, coordinator turns this into CANCELED snapshot");
    }

    private long usedHeapMb() {
        System.gc();
        Runtime rt = Runtime.getRuntime();
        return (rt.totalMemory() - rt.freeMemory()) / (1024 * 1024);
    }
}

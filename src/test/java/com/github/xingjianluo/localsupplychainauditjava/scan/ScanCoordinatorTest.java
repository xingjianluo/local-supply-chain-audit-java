package com.github.xingjianluo.localsupplychainauditjava.scan;

import com.github.xingjianluo.localsupplychainauditjava.model.*;
import com.github.xingjianluo.localsupplychainauditjava.model.ManifestInput;
import com.github.xingjianluo.localsupplychainauditjava.parse.FormatDetector;
import com.github.xingjianluo.localsupplychainauditjava.parse.JsonSbomParser;
import com.github.xingjianluo.localsupplychainauditjava.parse.PomManifestParser;
import com.github.xingjianluo.localsupplychainauditjava.vuln.LocalVulnRepository;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Scan state management: single-flight conflict, cancellation without leftover
 * state, next-scan isolation, and vulndb-version binding across rescans.
 * Logs record inputs, state transitions and the basis of every verdict.
 */
class ScanCoordinatorTest {

    private static final Logger log = LoggerFactory.getLogger(ScanCoordinatorTest.class);

    private ScanEngine engine(Path dbDir) {
        return new ScanEngine(new LocalVulnRepository(), dbDir,
                new FormatDetector(),
                List.of(new PomManifestParser(), new JsonSbomParser()),
                new DependencyNormalizer(), new RiskEvaluator());
    }

    private ScanRequest jsonRequest(String moduleId, String body) {
        return new ScanRequest(List.of(
                new ManifestInput(moduleId, ManifestFormat.JSON_SBOM, null, body)));
    }

    private final String cleanManifest =
            "{\"components\":[{\"group\":\"g\",\"name\":\"n\",\"version\":\"1.0\"}]}";

    @Test
    void concurrentStartsYieldExactlyOneRunningAndOneConflict() throws Exception {
        BlockingScanEngine engine = new BlockingScanEngine("first");
        ScanCoordinator coordinator = new ScanCoordinator(engine);
        ScanRequest request = jsonRequest("m", cleanManifest);

        int threads = 8;
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger accepted = new AtomicInteger();
        AtomicInteger conflicted = new AtomicInteger();
        List<Thread> workers = new java.util.ArrayList<>();
        for (int i = 0; i < threads; i++) {
            Thread t = new Thread(() -> {
                try {
                    start.await();
                    coordinator.start(request);
                    accepted.incrementAndGet();
                    log.info("STATE: start ACCEPTED on thread {}", Thread.currentThread().getName());
                } catch (ScanConflictException e) {
                    conflicted.incrementAndGet();
                    log.info("STATE: start CONFLICT against running scan {}", e.getRunningScanId());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }, "submitter-" + i);
            workers.add(t);
            t.start();
        }
        start.countDown();
        for (Thread t : workers) {
            t.join(5000);
        }
        assertEquals(1, accepted.get(), "exactly one scan may start");
        assertEquals(threads - 1, conflicted.get(), "all other submissions get 409-style conflict");
        engine.release();
        coordinator.awaitIdle(5000);
        log.info("VERDICT: single-flight enforced under {} concurrent submissions", threads);
    }

    @Test
    void canceledScanLeavesNoHalfResultAndNextScanRuns() throws Exception {
        BlockingScanEngine slow = new BlockingScanEngine("only");
        // unused latch control is per-instance
        ScanCoordinator coordinator = new ScanCoordinator(slow);

        ScanResult accepted = coordinator.start(jsonRequest("m", cleanManifest));
        slow.awaitEntered();
        log.info("STATE: scan {} is RUNNING; requesting cancellation", accepted.scanId());
        boolean canceled = coordinator.cancel(accepted.scanId());
        assertTrue(canceled);
        slow.release();
        coordinator.awaitIdle(5000);

        ScanResult terminal = coordinator.get(accepted.scanId()).orElseThrow();
        assertEquals(ScanStatus.CANCELED, terminal.status());
        assertTrue(terminal.canceled());
        assertTrue(terminal.risks().isEmpty() && terminal.manifests().isEmpty(),
                "canceled scan publishes no half-finished findings");
        log.info("VERDICT: canceled result contains no partial manifests/risks");

        // The slot must be released and a follow-up scan unaffected.
        ScanResult next = coordinator.start(jsonRequest("m2", cleanManifest));
        coordinator.awaitIdle(5000);
        ScanResult nextTerminal = coordinator.get(next.scanId()).orElseThrow();
        assertEquals(ScanStatus.SUCCEEDED, nextTerminal.status());
        log.info("VERDICT: next scan {} SUCCEEDED, state did not leak from canceled scan",
                next.scanId());
    }

    @Test
    void cancelUnknownOrFinishedScanReturnsFalse() {
        ScanCoordinator coordinator = new ScanCoordinator(
                engine(TestPaths.vulndbV1()));
        log.info("INPUT cancel of unknown scan id");
        assertFalse(coordinator.cancel("scan-does-not-exist"));
    }

    @Test
    void emptyRequestIsRejected() {
        ScanCoordinator coordinator = new ScanCoordinator(
                engine(TestPaths.vulndbV1()));
        log.info("INPUT start with empty manifest list");
        assertThrows(IllegalArgumentException.class, () -> coordinator.start(new ScanRequest(List.of())));
        log.info("VERDICT: empty request rejected with BAD_REQUEST semantics");
    }

    @Test
    void rescanAfterLibraryUpdateReflectsNewConclusionAndHistoryKeepsOldVersion() throws Exception {
        LocalVulnRepository repo = new LocalVulnRepository();
        Path v1 = TestPaths.vulndbV1();
        Path v2 = TestPaths.vulndbV2();
        ScanEngine engineV1 = new ScanEngine(repo, v1, new FormatDetector(),
                List.of(new PomManifestParser(), new JsonSbomParser()),
                new DependencyNormalizer(), new RiskEvaluator());
        ScanEngine engineV2 = new ScanEngine(repo, v2, new FormatDetector(),
                List.of(new PomManifestParser(), new JsonSbomParser()),
                new DependencyNormalizer(), new RiskEvaluator());
        ScanCoordinator c1 = new ScanCoordinator(engineV1);
        String vulnerable = "{\"components\":[{\"group\":\"com.example\",\"name\":\"risky-lib\","
                + "\"version\":\"1.1.0\",\"modules\":[]}]}";
        ScanRequest req = jsonRequest("mod", vulnerable);

        ScanResult first = c1.start(req);
        c1.awaitIdle(5000);
        ScanResult firstDone = c1.get(first.scanId()).orElseThrow();
        assertEquals(ScanStatus.SUCCEEDED, firstDone.status());
        RiskLevel levelV1 = firstDone.risks().stream()
                .flatMap(r -> r.matched().stream()).findFirst().orElseThrow().level();
        String dbV1 = firstDone.vulnDbVersion();
        log.info("STATE: first scan bound to vulndb {}; verdict level {}", dbV1, levelV1);
        assertEquals(RiskLevel.HIGH, levelV1);

        // Library updated and re-scanned.
        ScanCoordinator c2 = new ScanCoordinator(engineV2);
        ScanResult second = c2.start(req);
        c2.awaitIdle(5000);
        ScanResult secondDone = c2.get(second.scanId()).orElseThrow();
        assertNotEquals(dbV1, secondDone.vulnDbVersion(),
                "new library content must bind a new snapshot version");
        RiskLevel levelV2 = secondDone.risks().stream()
                .flatMap(r -> r.matched().stream()).findFirst().orElseThrow().level();
        assertEquals(RiskLevel.CRITICAL, levelV2, "revised severity must show in rescan");
        log.info("STATE: rescan bound to vulndb {}; verdict level {}", secondDone.vulnDbVersion(), levelV2);

        // Historical conclusion still retrievable and bound to the old snapshot.
        ScanResult historical = c1.get(first.scanId()).orElseThrow();
        assertEquals(dbV1, historical.vulnDbVersion());
        assertEquals(RiskLevel.HIGH, historical.risks().stream()
                .flatMap(r -> r.matched().stream()).findFirst().orElseThrow().level());
        log.info("VERDICT: history reproducible at {} while rescan uses {}",
                dbV1, secondDone.vulnDbVersion());
    }

    @Test
    void runningScanIsFetchableAsPendingAndNotInHistoryYet() throws Exception {
        BlockingScanEngine engine = new BlockingScanEngine("peek");
        ScanCoordinator coordinator = new ScanCoordinator(engine);
        ScanResult accepted = coordinator.start(jsonRequest("m", cleanManifest));
        engine.awaitEntered();
        log.info("STATE: fetching running scan {}", accepted.scanId());
        ScanResult live = coordinator.get(accepted.scanId()).orElseThrow();
        assertEquals(ScanStatus.PENDING, live.status(),
                "running scan must be observable by its id (no 404 window)");
        assertTrue(coordinator.history().stream().noneMatch(r -> r.scanId().equals(accepted.scanId())),
                "history only contains terminal scans");
        log.info("VERDICT: GET while running -> PENDING; history excludes non-terminal scans");
        engine.release();
        coordinator.awaitIdle(5000);
    }

    @Test
    void workerCrashIsRecordedAsFailedNotCanceled() {
        ScanCoordinator coordinator = new ScanCoordinator(new CrashingScanEngine());
        ScanResult accepted = coordinator.start(jsonRequest("m", cleanManifest));
        ScanResult terminal = coordinator.get(accepted.scanId()).orElseThrow();
        // synchronous execution is serialized on the single worker; allow it to finish
        for (int i = 0; i < 50 && terminal.status() == ScanStatus.PENDING; i++) {
            try { Thread.sleep(20); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            terminal = coordinator.get(accepted.scanId()).orElseThrow();
        }
        log.info("STATE: crashing worker terminal status={}, reason={}",
                terminal.status(), terminal.failureReason());
        assertEquals(ScanStatus.FAILED, terminal.status());
        assertFalse(terminal.canceled());
        assertNotNull(terminal.failureReason());
        log.info("VERDICT: worker failure is distinguishable from cancellation");
    }

    /** Engine stub that always throws, simulating an unexpected worker failure. */
    public static final class CrashingScanEngine extends ScanEngine {
        CrashingScanEngine() {
            super(new LocalVulnRepository());
        }

        @Override
        public ScanResult run(String scanId, ScanRequest request, AtomicBoolean cancelFlag) {
            throw new IllegalStateException("simulated worker crash");
        }
    }

    /** Engine stub that blocks in PARSE until released, to exercise live cancellation. */
    public static final class BlockingScanEngine extends ScanEngine {
        private final CountDownLatch entered = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);
        private final String id;

        BlockingScanEngine(String id) {
            super(new LocalVulnRepository());
            this.id = id;
        }

        @Override
        public ScanResult run(String scanId, ScanRequest request, AtomicBoolean cancelFlag) {
            try {
                log.info("[{}] BLOCKING engine '{}' entered, waiting for test control", scanId, id);
                entered.countDown();
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            log.info("[{}] BLOCKING engine released, cancelFlag={}", scanId, cancelFlag.get());
            return cancelFlag.get() ? null
                    : new ScanResult(scanId, ScanStatus.SUCCEEDED, false,
                            java.time.Instant.now(), java.time.Instant.now(), "vdb-block", null,
                            List.of(), List.of(),
                            new ScanSummary(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
        }

        void awaitEntered() throws InterruptedException {
            assertTrue(entered.await(5, java.util.concurrent.TimeUnit.SECONDS));
        }

        public void release() {
            release.countDown();
        }
    }
}

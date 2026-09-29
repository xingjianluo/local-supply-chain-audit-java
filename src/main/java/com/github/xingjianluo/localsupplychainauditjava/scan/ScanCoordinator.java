package com.github.xingjianluo.localsupplychainauditjava.scan;

import com.github.xingjianluo.localsupplychainauditjava.model.ScanRequest;
import com.github.xingjianluo.localsupplychainauditjava.model.ScanResult;
import com.github.xingjianluo.localsupplychainauditjava.model.ScanStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * State manager for scans.
 *
 * <p>Concurrency contract:
 * <ul>
 *   <li>at most one non-terminal scan (PENDING/RUNNING) may exist at any time —
 *       a second start gets {@link ScanConflictException} (HTTP 409);</li>
 *   <li>all start/get/cancel transitions are serialized through a single lock,
 *       while result reads are served from published immutable snapshots, so
 *       concurrent callers can never observe another scan's data;</li>
 *   <li>cancellation is cooperative: the running task is signaled and its
 *       engine run publishes nothing; the coordinator then records an immutable
 *       CANCELED result and releases the single-flight slot, so the next scan is
 *       unaffected and no half-finished data remains;</li>
 *   <li>finished scans (SUCCEEDED/FAILED/CANCELED) are retained in insertion
 *       order; each is permanently bound to its vulndb version.</li>
 * </ul>
 */
@Component
public class ScanCoordinator {

    private static final Logger log = LoggerFactory.getLogger(ScanCoordinator.class);
    private static final int HISTORY_LIMIT = 50;

    private final ScanEngine engine;
    private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "scan-worker");
        t.setDaemon(true);
        return t;
    });

    private final Object lock = new Object();
    private final ConcurrentLinkedQueue<ScanResult> history = new ConcurrentLinkedQueue<>();
    private final ConcurrentHashMap<String, ScanResult> byId = new ConcurrentHashMap<>();

    private final AtomicReference<ActiveScan> active = new AtomicReference<>();

    public ScanCoordinator(ScanEngine engine) {
        this.engine = engine;
    }

    /**
     * Start a new scan.
     *
     * @throws IllegalArgumentException when the request is empty/invalid
     * @throws ScanConflictException    when another scan is currently running
     */
    public ScanResult start(ScanRequest request) {
        if (request == null || request.manifests() == null || request.manifests().isEmpty()) {
            throw new IllegalArgumentException("scan request must contain at least one manifest");
        }

        String scanId = "scan-" + UUID.randomUUID();
        ActiveScan handle;
        synchronized (lock) {
            ActiveScan current = active.get();
            if (current != null) {
                log.warn("Start conflict: requested {} while {} is still RUNNING",
                        scanId, current.scanId);
                throw new ScanConflictException(current.scanId,
                        "scan " + current.scanId + " is already running; only one scan at a time");
            }
            handle = new ActiveScan(scanId, new AtomicBoolean(false));
            active.set(handle);
            ScanResult pending = pendingSnapshot(scanId);
            byId.put(scanId, pending);
            log.info("Scan {} transitioned -> PENDING ({} manifest(s))",
                    scanId, request.manifests().size());
        }

        Future<?> future = executor.submit(() -> execute(handle, request));
        handle.future = future;
        return byId.get(scanId);
    }

    private void execute(ActiveScan handle, ScanRequest request) {
        String scanId = handle.scanId;
        log.info("Scan {} transitioned -> RUNNING", scanId);
        ScanResult result = null;
        Throwable workerFailure = null;
        try {
            result = engine.run(scanId, request, handle.cancelFlag);
        } catch (Throwable t) {
            workerFailure = t;
            log.error("Scan {} worker threw: {}", scanId, t.getMessage(), t);
        }
        synchronized (lock) {
            if (workerFailure != null) {
                result = failedSnapshot(scanId, workerFailure);
                log.info("Scan {} transitioned -> FAILED (slot released)", scanId);
            } else if (result == null || handle.cancelFlag.get()) {
                result = canceledSnapshot(scanId);
                log.info("Scan {} transitioned -> CANCELED (published terminal result, slot released)",
                        scanId);
            }
            publish(result);
            active.set(null);
            lock.notifyAll();
        }
    }

    public Optional<ScanResult> get(String scanId) {
        return Optional.ofNullable(byId.get(scanId));
    }

    public List<ScanResult> history() {
        return List.of(history.toArray(new ScanResult[0]));
    }

    /**
     * Request cancellation.
     *
     * @return true if a running/pending scan was signaled; false if unknown or
     *         already terminal
     */
    public boolean cancel(String scanId) {
        synchronized (lock) {
            ActiveScan current = active.get();
            if (current == null || !current.scanId.equals(scanId)) {
                log.warn("Cancel of '{}' ignored: no matching active scan (active={})",
                        scanId, current == null ? "none" : current.scanId);
                return false;
            }
            current.cancelFlag.set(true);
            log.info("Scan {} cancellation requested", scanId);
            // Wait briefly for the worker to observe the flag between phases/batches so
            // callers polling immediately usually see the terminal CANCELED state.
            try {
                lock.wait(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            // The flag was just set on the matching active scan: that is the acceptance
            // contract. Terminal CANCELED state is observable shortly afterwards via GET;
            // the brief wait above just makes immediate polling more likely to see it.
            log.info("Cancel of '{}' accepted; terminal CANCELED state follows on next worker check",
                    scanId);
            return true;
        }
    }

    /** Block until the active scan (if any) becomes terminal. Used by tests. */
    public void awaitIdle(long timeoutMillis) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMillis;
        synchronized (lock) {
            while (active.get() != null) {
                long remaining = deadline - System.currentTimeMillis();
                if (remaining <= 0) {
                    throw new InterruptedException("timeout waiting for scan to finish");
                }
                lock.wait(remaining);
            }
        }
    }

    private void publish(ScanResult result) {
        byId.put(result.scanId(), result);
        history.add(result);
        while (history.size() > HISTORY_LIMIT) {
            ScanResult old = history.poll();
            if (old != null) {
                byId.remove(old.scanId());
            }
        }
        log.info("Scan {} published as {} (bound to vulndb {})",
                result.scanId(), result.status(), result.vulnDbVersion());
    }

    private ScanResult pendingSnapshot(String scanId) {
        return new ScanResult(scanId, ScanStatus.PENDING, false, java.time.Instant.now(),
                null, null, null, List.of(), List.of(),
                new com.github.xingjianluo.localsupplychainauditjava.model.ScanSummary(
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
    }

    private ScanResult failedSnapshot(String scanId, Throwable cause) {
        String reason = cause.getClass().getSimpleName()
                + (cause.getMessage() != null ? ": " + cause.getMessage() : "");
        return new ScanResult(scanId, ScanStatus.FAILED, false, java.time.Instant.now(),
                java.time.Instant.now(), null, reason, List.of(), List.of(),
                new com.github.xingjianluo.localsupplychainauditjava.model.ScanSummary(
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
    }

    private ScanResult canceledSnapshot(String scanId) {
        return new ScanResult(scanId, ScanStatus.CANCELED, true, java.time.Instant.now(),
                java.time.Instant.now(), null, null, List.of(), List.of(),
                new com.github.xingjianluo.localsupplychainauditjava.model.ScanSummary(
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
    }

    /** Mutable handle to the active scan, guarded by {@link #lock}. */
    private static final class ActiveScan {
        private final String scanId;
        private final AtomicBoolean cancelFlag;
        private volatile Future<?> future;

        private ActiveScan(String scanId, AtomicBoolean cancelFlag) {
            this.scanId = scanId;
            this.cancelFlag = cancelFlag;
        }
    }
}

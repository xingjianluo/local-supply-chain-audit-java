package com.github.xingjianluo.localsupplychainauditjava.model;

import java.time.Instant;
import java.util.List;

/**
 * Full, traceable conclusion of one scan, bound to the exact vulnerability library
 * snapshot version it was evaluated against.
 *
 * @param scanId         unique scan identifier
 * @param status         terminal or current lifecycle state
 * @param canceled       true when the scan was canceled (no half-finished result is published)
 * @param startedAt      start instant
 * @param finishedAt     completion instant, null while running
 * @param vulnDbVersion  vulnerability library snapshot version bound to this result
 * @param failureReason  populated only when status is FAILED
 * @param manifests      per-manifest processing conclusions
 * @param risks          merged per-component risk conclusions (empty while running)
 * @param summary        aggregate counters
 */
public record ScanResult(String scanId, ScanStatus status, boolean canceled,
                         Instant startedAt, Instant finishedAt, String vulnDbVersion,
                         String failureReason,
                         List<ManifestResult> manifests, List<ComponentRisk> risks,
                         ScanSummary summary) {

    public static ScanResult empty() {
        return null;
    }
}

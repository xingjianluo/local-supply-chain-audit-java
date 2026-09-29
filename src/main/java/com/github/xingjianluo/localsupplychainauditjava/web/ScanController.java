package com.github.xingjianluo.localsupplychainauditjava.web;

import com.github.xingjianluo.localsupplychainauditjava.model.ScanRequest;
import com.github.xingjianluo.localsupplychainauditjava.model.ScanResult;
import com.github.xingjianluo.localsupplychainauditjava.scan.ScanCoordinator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * REST endpoints for local scan orchestration.
 * <ul>
 *   <li>{@code POST /api/scans} – start a scan (202 while pending, 409 on conflict, 400 on bad input)</li>
 *   <li>{@code GET  /api/scans/{id}} – fetch a scan snapshot (running or terminal)</li>
 *   <li>{@code GET  /api/scans} – list retained scan history</li>
 *   <li>{@code POST /api/scans/{id}/cancel} – cancel a running scan</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/scans")
public class ScanController {

    private static final Logger log = LoggerFactory.getLogger(ScanController.class);

    private final ScanCoordinator coordinator;

    public ScanController(ScanCoordinator coordinator) {
        this.coordinator = coordinator;
    }

    @PostMapping
    public ResponseEntity<ScanResult> start(@RequestBody ScanRequest request) {
        log.info("Received start request with {} manifest(s)",
                request == null || request.manifests() == null ? 0 : request.manifests().size());
        ScanResult snapshot = coordinator.start(request);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(snapshot);
    }

    @GetMapping("/{scanId}")
    public ResponseEntity<ScanResult> get(@PathVariable String scanId) {
        return coordinator.get(scanId)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).build());
    }

    @GetMapping
    public List<ScanResult> history() {
        return coordinator.history();
    }

    @PostMapping("/{scanId}/cancel")
    public ResponseEntity<Map<String, Object>> cancel(@PathVariable String scanId) {
        log.info("Received cancel request for scan '{}'", scanId);
        boolean signaled = coordinator.cancel(scanId);
        if (!signaled) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("scanId", scanId, "canceled", false,
                            "reason", "no active scan with this id"));
        }
        return ResponseEntity.ok(Map.of("scanId", scanId, "canceled", true));
    }
}

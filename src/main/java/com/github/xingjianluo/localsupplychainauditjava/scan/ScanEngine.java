package com.github.xingjianluo.localsupplychainauditjava.scan;

import com.github.xingjianluo.localsupplychainauditjava.model.*;
import com.github.xingjianluo.localsupplychainauditjava.parse.FormatDetector;
import com.github.xingjianluo.localsupplychainauditjava.parse.JsonSbomParser;
import com.github.xingjianluo.localsupplychainauditjava.parse.ManifestParser;
import com.github.xingjianluo.localsupplychainauditjava.parse.PomManifestParser;
import com.github.xingjianluo.localsupplychainauditjava.vuln.VulnRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Executes one scan end to end, in three phases:
 * <ol>
 *   <li><b>PARSE</b> – each manifest is parsed independently in bounded batches,
 *       so one corrupt file only produces a CORRUPT {@link ManifestResult} and
 *       never fails the whole scan;</li>
 *   <li><b>NORMALIZE</b> – records are merged across modules/formats;</li>
 *   <li><b>EVALUATE</b> – an immutable vulnerability library snapshot is bound
 *       to the scan and matched against every concrete version.</li>
 * </ol>
 * Cancellation is checked between phases and between every batch; when canceled
 * the engine simply stops and returns no result, leaving no half-finished state.
 * Large manifests stay memory bounded because results are accumulated as
 * compact records and parsing never holds the whole input twice.
 */
@Component
public class ScanEngine {

    private static final Logger log = LoggerFactory.getLogger(ScanEngine.class);
    static final int BATCH_SIZE = 50;

    private final VulnRepository vulnRepository;
    private final Path vulnDbPath;
    private final FormatDetector formatDetector;
    private final List<ManifestParser> parsers;
    private final DependencyNormalizer normalizer;
    private final RiskEvaluator riskEvaluator;

    @org.springframework.beans.factory.annotation.Autowired
    public ScanEngine(VulnRepository vulnRepository,
                      FormatDetector formatDetector,
                      PomManifestParser pomParser,
                      JsonSbomParser jsonParser,
                      DependencyNormalizer normalizer,
                      RiskEvaluator riskEvaluator,
                      @org.springframework.beans.factory.annotation.Value("${audit.vulndb.path:src/main/resources/local-vulndb}")
                      String vulnDbPathProperty) {
        this(vulnRepository, Path.of(vulnDbPathProperty), formatDetector,
                List.of(pomParser, jsonParser), normalizer, riskEvaluator);
    }

    /** Test-only constructor for engine stubs that override {@link #run}. */
    ScanEngine(VulnRepository vulnRepository) {
        this(vulnRepository, Path.of("src/main/resources/local-vulndb"),
                new FormatDetector(), List.of(), new DependencyNormalizer(), new RiskEvaluator());
    }

    ScanEngine(VulnRepository vulnRepository, Path vulnDbPath,
               FormatDetector formatDetector, List<ManifestParser> parsers,
               DependencyNormalizer normalizer, RiskEvaluator riskEvaluator) {
        this.vulnRepository = vulnRepository;
        this.vulnDbPath = vulnDbPath;
        this.formatDetector = formatDetector;
        this.parsers = parsers;
        this.normalizer = normalizer;
        this.riskEvaluator = riskEvaluator;
    }

    /**
     * Run the scan.
     *
     * @return immutable final result, or {@code null} when cancellation was observed
     *         before a result was published
     */
    public ScanResult run(String scanId, ScanRequest request, AtomicBoolean cancelFlag) {
        Instant startedAt = Instant.now();
        log.info("[{}] scan started with {} manifest(s)", scanId, request.manifests().size());
        try {
            // Bind the vulnerability library snapshot up front: conclusions are tied
            // to this exact version for the whole scan.
            VulnDatabase db = vulnRepository.loadSnapshot(vulnDbPath);
            log.info("[{}] bound vulnerability library snapshot {}", scanId, db.versionId());

            List<ManifestInput> inputs = request.manifests();
            List<ManifestResult> manifestResults = new ArrayList<>(inputs.size());
            for (int start = 0; start < inputs.size(); start += BATCH_SIZE) {
                if (cancelFlag.get()) {
                    log.info("[{}] canceled during PARSE phase at index {}; no result published",
                            scanId, start);
                    return null;
                }
                int end = Math.min(start + BATCH_SIZE, inputs.size());
                for (int i = start; i < end; i++) {
                    manifestResults.add(parseOne(scanId, inputs.get(i)));
                }
            }
            log.info("[{}] PARSE phase done: {} manifest result(s)", scanId, manifestResults.size());

            if (cancelFlag.get()) {
                log.info("[{}] canceled before NORMALIZE; no result published", scanId);
                return null;
            }
            Map<String, NormalizedComponent> components = normalizer.normalize(manifestResults);
            log.info("[{}] NORMALIZE phase done: {} unique component(s)", scanId, components.size());

            if (cancelFlag.get()) {
                log.info("[{}] canceled before EVALUATE; no result published", scanId);
                return null;
            }
            List<ComponentRisk> risks = riskEvaluator.evaluate(components, db);
            if (cancelFlag.get()) {
                log.info("[{}] canceled during EVALUATE; no result published", scanId);
                return null;
            }

            ScanSummary summary = summarize(manifestResults, components, risks);
            ScanResult result = new ScanResult(scanId, ScanStatus.SUCCEEDED, false,
                    startedAt, Instant.now(), db.versionId(), null,
                    List.copyOf(manifestResults), List.copyOf(risks), summary);
            log.info("[{}] scan SUCCEEDED: components={}, atRisk={}, findings={}, corrupt={}, partial={}",
                    scanId, summary.componentCount(), summary.componentsAtRisk(),
                    summary.findingTotal(), summary.manifestCorrupt(), summary.manifestPartiallyParsed());
            return result;
        } catch (Exception e) {
            log.error("[{}] scan FAILED unexpectedly: {}", scanId, e.getMessage(), e);
            return new ScanResult(scanId, ScanStatus.FAILED, false, startedAt, Instant.now(),
                    null, e.getMessage(), List.of(), List.of(),
                    new ScanSummary(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
        }
    }

    private ManifestResult parseOne(String scanId, ManifestInput input) {
        ManifestInput effective = ensureFormat(input);
        for (ManifestParser parser : parsers) {
            if (parser.supports(effective)) {
                ManifestResult result = parser.parse(effective);
                log.info("[{}] manifest module='{}' status={} records={} issues={}",
                        scanId, result.moduleId(), result.status(),
                        result.records().size(), result.issues().size());
                return result;
            }
        }
        String moduleId = input.moduleId() != null && !input.moduleId().isBlank()
                ? input.moduleId()
                : (input.path() != null ? input.path() : "<unknown>");
        log.warn("[{}] manifest module='{}' UNSUPPORTED_FORMAT", scanId, moduleId);
        return new ManifestResult(moduleId, effective.format(), ManifestStatus.CORRUPT,
                input.path(), List.of(),
                List.of(new ManifestIssue(IssueType.UNSUPPORTED_FORMAT,
                        "cannot determine or handle manifest format")));
    }

    private ManifestInput ensureFormat(ManifestInput input) {
        if (input.format() != null) {
            return input;
        }
        ManifestFormat detected = formatDetector.detect(input);
        return new ManifestInput(input.moduleId(), detected, input.path(), input.content());
    }

    private ScanSummary summarize(List<ManifestResult> manifests,
                                  Map<String, NormalizedComponent> components,
                                  List<ComponentRisk> risks) {
        int parsed = 0;
        int partial = 0;
        int corrupt = 0;
        int issueCount = 0;
        for (ManifestResult m : manifests) {
            switch (m.status()) {
                case PARSED -> parsed++;
                case PARTIALLY_PARSED -> {
                    partial++;
                    parsed++;
                }
                case CORRUPT -> corrupt++;
            }
            issueCount += m.issues().size();
        }
        // Include normalization-level issues (duplicates / multi-version / uncoordinated).
        for (NormalizedComponent c : components.values()) {
            issueCount += c.issues().size();
        }
        int componentCount = 0;
        int atRisk = 0;
        int findingTotal = 0;
        int critical = 0, high = 0, medium = 0, low = 0;
        for (ComponentRisk risk : risks) {
            componentCount++;
            if (!risk.matched().isEmpty()) {
                atRisk++;
            }
            findingTotal += risk.matched().size();
            for (RiskFinding f : risk.matched()) {
                switch (f.level()) {
                    case CRITICAL -> critical++;
                    case HIGH -> high++;
                    case MEDIUM -> medium++;
                    case LOW -> low++;
                }
            }
        }
        return new ScanSummary(manifests.size(), parsed, partial, corrupt, issueCount,
                componentCount, atRisk, findingTotal, critical, high, medium, low);
    }
}

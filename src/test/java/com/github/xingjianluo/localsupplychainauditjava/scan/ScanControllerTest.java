package com.github.xingjianluo.localsupplychainauditjava.scan;

import com.github.xingjianluo.localsupplychainauditjava.model.*;
import com.github.xingjianluo.localsupplychainauditjava.vuln.LocalVulnRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;

import com.github.xingjianluo.localsupplychainauditjava.web.GlobalExceptionHandler;
import com.github.xingjianluo.localsupplychainauditjava.web.ScanController;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * HTTP contract tests: 202 accepted, 409 distinguishable conflict, 400 bad input,
 * 404 unknown scan, and GET of terminal results.
 */
class ScanControllerTest {

    private static final Logger log = LoggerFactory.getLogger(ScanControllerTest.class);
    private final ObjectMapper mapper = new ObjectMapper();

    private ScanEngine realEngine() {
        return new ScanEngine(new LocalVulnRepository(),
                TestPaths.vulndbV1(),
                new com.github.xingjianluo.localsupplychainauditjava.parse.FormatDetector(),
                List.of(new com.github.xingjianluo.localsupplychainauditjava.parse.PomManifestParser(),
                        new com.github.xingjianluo.localsupplychainauditjava.parse.JsonSbomParser()),
                new DependencyNormalizer(), new RiskEvaluator());
    }

    private String validBody() throws Exception {
        ScanRequest req = new ScanRequest(List.of(new ManifestInput("m",
                ManifestFormat.JSON_SBOM, null,
                "{\"components\":[{\"group\":\"g\",\"name\":\"n\",\"version\":\"1.0\"}]}")));
        return mapper.writeValueAsString(req);
    }

    @Test
    void startReturns202AndResultIsFetchable() throws Exception {
        ScanCoordinator coordinator = new ScanCoordinator(realEngine());
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new ScanController(coordinator))
                .setControllerAdvice(new GlobalExceptionHandler()).build();

        log.info("INPUT POST /api/scans with one valid manifest");
        String response = mockMvc.perform(post("/api/scans")
                        .contentType(MediaType.APPLICATION_JSON).content(validBody()))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.status").value("PENDING"))
                .andReturn().getResponse().getContentAsString();
        String scanId = mapper.readTree(response).get("scanId").asText();
        log.info("STATE: accepted scan {}", scanId);
        coordinator.awaitIdle(5000);
        mockMvc.perform(get("/api/scans/" + scanId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("SUCCEEDED"))
                .andExpect(jsonPath("$.vulnDbVersion").isNotEmpty());
        log.info("VERDICT: terminal result retrievable and bound to vulndb version");
    }

    @Test
    void conflictReturns409WithRunningScanId() throws Exception {
        ScanCoordinatorTest.BlockingScanEngine engine = null;
        // Build blocking engine via the coordinator test's package-private stub class.
        engine = newBlockingEngine();
        ScanCoordinator coordinator = new ScanCoordinator(engine);
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new ScanController(coordinator))
                .setControllerAdvice(new GlobalExceptionHandler()).build();

        String first = mockMvc.perform(post("/api/scans")
                        .contentType(MediaType.APPLICATION_JSON).content(validBody()))
                .andExpect(status().isAccepted())
                .andReturn().getResponse().getContentAsString();
        String firstId = mapper.readTree(first).get("scanId").asText();
        log.info("STATE: first scan {} RUNNING; submitting duplicate concurrently", firstId);

        mockMvc.perform(post("/api/scans")
                        .contentType(MediaType.APPLICATION_JSON).content(validBody()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("SCAN_ALREADY_RUNNING"))
                .andExpect(jsonPath("$.runningScanId").value(firstId));
        log.info("VERDICT: duplicate submission got 409 naming running scan {}", firstId);
        releaseBlockingEngine(engine);
        coordinator.awaitIdle(5000);
    }

    @Test
    void emptyRequestReturns400() throws Exception {
        ScanCoordinator coordinator = new ScanCoordinator(realEngine());
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new ScanController(coordinator))
                .setControllerAdvice(new GlobalExceptionHandler()).build();

        log.info("INPUT POST with empty manifests list");
        mockMvc.perform(post("/api/scans")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"manifests\":[]}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("BAD_REQUEST"));
        log.info("VERDICT: empty request -> 400");
    }

    @Test
    void unknownScanReturns404() throws Exception {
        ScanCoordinator coordinator = new ScanCoordinator(realEngine());
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new ScanController(coordinator))
                .setControllerAdvice(new GlobalExceptionHandler()).build();
        log.info("INPUT GET unknown scan id");
        mockMvc.perform(get("/api/scans/scan-nope")).andExpect(status().isNotFound());
        log.info("VERDICT: unknown scan -> 404");
    }

    // Bridge helpers to the blocking engine defined in ScanCoordinatorTest.
    private ScanCoordinatorTest.BlockingScanEngine newBlockingEngine() {
        return new ScanCoordinatorTest.BlockingScanEngine("http");
    }

    private void releaseBlockingEngine(ScanCoordinatorTest.BlockingScanEngine engine) throws Exception {
        engine.release();
    }
}

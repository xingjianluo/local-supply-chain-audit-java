package com.github.xingjianluo.localsupplychainauditjava.parse;

import com.github.xingjianluo.localsupplychainauditjava.model.*;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Covers malformed manifests, missing fields, corrupt files and format detection.
 * Inputs, state changes and judgment basis are logged for traceability.
 */
class ManifestParserTest {

    private static final Logger log = LoggerFactory.getLogger(ManifestParserTest.class);
    private final PomManifestParser pomParser = new PomManifestParser();
    private final JsonSbomParser jsonParser = new JsonSbomParser();
    private final FormatDetector detector = new FormatDetector();

    @Test
    void malformedXmlProducesCorruptNotException() {
        String broken = "<project><dependencies><dependency></project>";
        log.info("INPUT malformed POM content: {}", broken);
        ManifestResult result = pomParser.parse(
                new ManifestInput("bad", ManifestFormat.MAVEN_POM, null, broken));
        assertEquals(ManifestStatus.CORRUPT, result.status());
        assertEquals(IssueType.MALFORMED_XML, result.issues().get(0).type());
        log.info("STATE/VERDICT: status={} (one bad file must not fail the scan)", result.status());
    }

    @Test
    void malformedJsonProducesCorruptNotException() {
        String broken = "{\"components\": [ ";
        log.info("INPUT malformed JSON content: '{}'", broken);
        ManifestResult result = jsonParser.parse(
                new ManifestInput("bad", ManifestFormat.JSON_SBOM, null, broken));
        assertEquals(ManifestStatus.CORRUPT, result.status());
        assertEquals(IssueType.MALFORMED_JSON, result.issues().get(0).type());
        log.info("STATE/VERDICT: status={} issue={}", result.status(), result.issues().get(0).type());
    }

    @Test
    void jsonMissingComponentsArrayIsCorrupt() {
        String body = "{\"notComponents\": []}";
        log.info("INPUT JSON without components array: {}", body);
        ManifestResult result = jsonParser.parse(
                new ManifestInput("m", ManifestFormat.JSON_SBOM, null, body));
        assertEquals(ManifestStatus.CORRUPT, result.status());
        log.info("STATE/VERDICT: missing components member -> CORRUPT");
    }

    @Test
    void missingFieldsProducePartiallyParsedButKeepRecords() {
        String body = """
                {"components":[
                  {"name":"no-group","version":"1.0"},
                  {"group":"g","name":"has-version","version":"2.0"},
                  {"group":"g","name":"no-version"}
                ]}
                """;
        log.info("INPUT JSON with missing group/version entries:\n{}", body);
        ManifestResult result = jsonParser.parse(
                new ManifestInput("partial", ManifestFormat.JSON_SBOM, null, body));
        assertEquals(ManifestStatus.PARTIALLY_PARSED, result.status(),
                "field-level defects must yield PARTIALLY_PARSED, not a dropped file");
        assertEquals(3, result.records().size(), "all entries retained, nothing silently skipped");
        assertTrue(result.issues().stream().anyMatch(i -> i.type() == IssueType.MISSING_COORDINATE));
        assertTrue(result.issues().stream().anyMatch(i -> i.type() == IssueType.MISSING_VERSION));
        log.info("STATE/VERDICT: status={}, records kept={}, issues={}",
                result.status(), result.records().size(), result.issues().size());
    }

    @Test
    void nonObjectEntryIsKeptAsideWithIssue() {
        String body = "{\"components\":[\"oops\", {\"group\":\"g\",\"name\":\"n\",\"version\":\"1\"}]}";
        log.info("INPUT JSON containing a non-object entry: {}", body);
        ManifestResult result = jsonParser.parse(
                new ManifestInput("mixed", ManifestFormat.JSON_SBOM, null, body));
        assertEquals(ManifestStatus.PARTIALLY_PARSED, result.status());
        assertEquals(1, result.records().size());
        log.info("STATE/VERDICT: invalid entry isolated, valid entries still parsed");
    }

    @Test
    void missingFileProducesCorruptUnreadable() {
        String path = "/nonexistent/local-supply-chain/manifest-" + System.nanoTime() + ".json";
        log.info("INPUT missing file path: {}", path);
        ManifestResult result = jsonParser.parse(
                new ManifestInput("ghost", ManifestFormat.JSON_SBOM, path, null));
        assertEquals(ManifestStatus.CORRUPT, result.status());
        assertEquals(IssueType.UNREADABLE_FILE, result.issues().get(0).type());
        log.info("STATE/VERDICT: unreadable file -> CORRUPT with UNREADABLE_FILE");
    }

    @Test
    void pomParsesDependenciesAndPluginsAndDefaultsPluginGroup() {
        String pom = """
                <project>
                  <dependencies>
                    <dependency><groupId>com.example</groupId><artifactId>risky-lib</artifactId>
                      <version>1.1.0</version></dependency>
                  </dependencies>
                  <build><plugins>
                    <plugin><artifactId>build-plugin</artifactId><version>1.2</version></plugin>
                  </plugins></build>
                </project>
                """;
        log.info("INPUT valid POM with one dependency and one plugin:\n{}", pom);
        ManifestResult result = pomParser.parse(
                new ManifestInput("pom-module", ManifestFormat.MAVEN_POM, null, pom));
        assertEquals(ManifestStatus.PARSED, result.status());
        assertEquals(2, result.records().size());
        DependencyRecord plugin = result.records().get(1);
        assertEquals("org.apache.maven.plugins", plugin.group(),
                "plugin without groupId resolves to Maven default plugin group");
        log.info("STATE/VERDICT: parsed 2 records; plugin group defaulted, verdict based on Maven convention");
    }

    @Test
    void pomDependencyWithoutVersionIsPartial() {
        String pom = """
                <project><dependencies>
                  <dependency><groupId>com.example</groupId><artifactId>managed</artifactId></dependency>
                </dependencies></project>
                """;
        log.info("INPUT POM dependency with no explicit version:\n{}", pom);
        ManifestResult result = pomParser.parse(
                new ManifestInput("p", ManifestFormat.MAVEN_POM, null, pom));
        assertEquals(ManifestStatus.PARTIALLY_PARSED, result.status());
        assertEquals(IssueType.MISSING_VERSION, result.issues().get(0).type());
        log.info("STATE/VERDICT: versionless coordinate kept and marked MISSING_VERSION");
    }

    @Test
    void detectsFormatFromContentAndSuffix() {
        ManifestFormat byXml = detector.detect(
                new ManifestInput(null, null, null, "  <project/>"));
        ManifestFormat byJson = detector.detect(
                new ManifestInput(null, null, "/tmp/x.json", null));
        ManifestFormat unknown = detector.detect(
                new ManifestInput(null, null, null, "plain text"));
        log.info("INPUT content='<project/>', path='x.json', text='plain text'");
        assertEquals(ManifestFormat.MAVEN_POM, byXml);
        assertEquals(ManifestFormat.JSON_SBOM, byJson);
        assertNull(unknown, "undetectable format stays null and later becomes UNSUPPORTED_FORMAT");
        log.info("STATE/VERDICT: XML->MAVEN_POM, .json->JSON_SBOM, text->null");
    }
}

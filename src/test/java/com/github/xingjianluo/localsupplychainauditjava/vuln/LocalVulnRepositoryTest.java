package com.github.xingjianluo.localsupplychainauditjava.vuln;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.xingjianluo.localsupplychainauditjava.model.VulnDatabase;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies content-addressed vulndb versioning: identical files produce the same
 * version id; changed files produce a new one; old snapshots stay retrievable so
 * historical scans remain reproducible.
 */
class LocalVulnRepositoryTest {

    private static final Logger log = LoggerFactory.getLogger(LocalVulnRepositoryTest.class);

    private static final String V1 = """
            {"entries":[
              {"vulnId":"V-1","group":"g","name":"n","fixedIn":"2.0",
               "ranges":[{"startInclusive":null,"endExclusive":"2.0"}],"level":"HIGH","title":"t"}
            ]}
            """;

    private static final String V2 = """
            {"entries":[
              {"vulnId":"V-1","group":"g","name":"n","fixedIn":"2.0",
               "ranges":[{"startInclusive":null,"endExclusive":"2.0"}],"level":"HIGH","title":"t"},
              {"vulnId":"V-2","group":"g","name":"n2","fixedIn":"3.0",
               "ranges":[{"startInclusive":null,"endExclusive":"3.0"}],"level":"LOW","title":"t2"}
            ]}
            """;

    @Test
    void identicalContentYieldsSameVersionId(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("vuln.json");
        Files.writeString(file, V1);
        LocalVulnRepository repo = new LocalVulnRepository();

        log.info("INPUT identical vulndb content loaded twice; BASIS: SHA-256 over sorted file names + bytes");
        VulnDatabase first = repo.loadSnapshot(dir);
        VulnDatabase second = repo.loadSnapshot(dir);
        assertEquals(first.versionId(), second.versionId());
        assertEquals(1, first.entries().size());
        log.info("STATE/VERDICT: stable version id {}", first.versionId());
    }

    @Test
    void updatedContentProducesNewVersionAndOldSnapshotStays(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("vuln.json");
        Files.writeString(file, V1);
        LocalVulnRepository repo = new LocalVulnRepository();

        VulnDatabase old = repo.loadSnapshot(dir);
        log.info("STATE: initial snapshot {} with {} entr(ies)", old.versionId(), old.entries().size());

        Files.writeString(file, V2);
        VulnDatabase refreshed = repo.refresh(dir);
        log.info("INPUT: vulndb file updated; STATE: new snapshot {} with {} entr(ies)",
                refreshed.versionId(), refreshed.entries().size());

        assertNotEquals(old.versionId(), refreshed.versionId(),
                "updated library must produce a new version id so rescans reflect new conclusions");
        assertEquals(2, refreshed.entries().size());

        VulnDatabase historical = repo.getByVersion(old.versionId());
        assertNotNull(historical, "old snapshot retained for historical scan reproduction");
        assertEquals(1, historical.entries().size());
        assertSame(old, historical);
        log.info("STATE/VERDICT: rescans use {}; historical scan still reproduces against {}",
                refreshed.versionId(), old.versionId());
    }

    @Test
    void missingDirectoryFailsLoudly(@TempDir Path dir) {
        Path missing = dir.resolve("does-not-exist");
        log.info("INPUT missing vulndb directory: {}", missing);
        LocalVulnRepository repo = new LocalVulnRepository();
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> repo.loadSnapshot(missing));
        assertTrue(ex.getMessage().contains("not found"));
        log.info("STATE/VERDICT: missing library is a loud failure, never a silent empty match");
    }
}

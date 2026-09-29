package com.github.xingjianluo.localsupplychainauditjava.model;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/**
 * An immutable snapshot of the local vulnerability library. Scan conclusions are
 * permanently bound to the snapshot they were produced against.
 *
 * @param versionId  content-derived version identifier (hash based), stable across reloads
 * @param loadedAt   instant this snapshot was loaded
 * @param sourcePath directory the library was loaded from
 * @param entries    all vulnerability entries
 */
public record VulnDatabase(String versionId, Instant loadedAt, Path sourcePath,
                           List<VulnerabilityEntry> entries) {
}

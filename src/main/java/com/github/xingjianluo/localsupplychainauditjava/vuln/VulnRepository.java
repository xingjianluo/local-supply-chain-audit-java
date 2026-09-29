package com.github.xingjianluo.localsupplychainauditjava.vuln;

import com.github.xingjianluo.localsupplychainauditjava.model.VulnDatabase;

import java.nio.file.Path;

/**
 * Loads and caches immutable snapshots of the local vulnerability library.
 * Snapshots are content-addressed: identical files yield the same version id,
 * and updated files produce a new version id so rescans reflect new conclusions
 * while historical scans stay reproducible against their bound version.
 */
public interface VulnRepository {

    /** Load (or return cached) snapshot for the given local directory. */
    VulnDatabase loadSnapshot(Path directory);

    /** Look up a previously loaded snapshot by its version id, or null. */
    VulnDatabase getByVersion(String versionId);

    /** Re-read the directory and cache a new snapshot if content changed. */
    VulnDatabase refresh(Path directory);
}

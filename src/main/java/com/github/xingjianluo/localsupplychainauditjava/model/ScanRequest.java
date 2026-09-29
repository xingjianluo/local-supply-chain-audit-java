package com.github.xingjianluo.localsupplychainauditjava.model;

import java.util.List;

/**
 * Request body for starting a scan.
 *
 * @param manifests one or more manifests from multiple engineering modules
 */
public record ScanRequest(List<ManifestInput> manifests) {
}

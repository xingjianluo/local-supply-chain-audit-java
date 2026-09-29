package com.github.xingjianluo.localsupplychainauditjava.model;

import java.util.List;

/**
 * Processing conclusion for one input manifest file.
 *
 * @param moduleId module identifier assigned to the manifest
 * @param format   format detected / requested
 * @param status   PARSED, PARTIALLY_PARSED or CORRUPT — never silently dropped
 * @param path     original input path for traceability
 * @param records  raw dependency records extracted from the manifest
 * @param issues   file-level and entry-level issues
 */
public record ManifestResult(String moduleId, ManifestFormat format, ManifestStatus status,
                             String path, List<DependencyRecord> records,
                             List<ManifestIssue> issues) {
}

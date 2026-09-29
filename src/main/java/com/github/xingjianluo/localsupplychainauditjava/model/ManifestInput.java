package com.github.xingjianluo.localsupplychainauditjava.model;

/**
 * One manifest submitted for a scan. Either {@code content} carries the manifest
 * text directly, or {@code path} points at a local file that will be read.
 *
 * @param moduleId caller assigned module identifier; when blank the file name is used
 * @param format   manifest format; null triggers auto detection by content/path
 * @param path     local file path, used when content is null and kept for traceability
 * @param content  inline manifest text; null means read from path
 */
public record ManifestInput(String moduleId, ManifestFormat format, String path, String content) {
}

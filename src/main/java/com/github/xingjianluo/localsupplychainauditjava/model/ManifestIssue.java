package com.github.xingjianluo.localsupplychainauditjava.model;

/**
 * A traceable problem found while processing one manifest, never silently skipped.
 *
 * @param type    distinguishable reason category
 * @param detail  human readable explanation, may contain offending coordinate text
 */
public record ManifestIssue(IssueType type, String detail) {
}

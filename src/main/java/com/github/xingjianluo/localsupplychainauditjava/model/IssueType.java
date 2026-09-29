package com.github.xingjianluo.localsupplychainauditjava.model;

/** Fine-grained reasons explaining why a manifest or a dependency entry is problematic. */
public enum IssueType {
    UNREADABLE_FILE,
    UNSUPPORTED_FORMAT,
    MALFORMED_XML,
    MALFORMED_JSON,
    MISSING_COORDINATE,
    MISSING_VERSION,
    DUPLICATE_REFERENCE,
    MULTI_VERSION_CONFLICT
}

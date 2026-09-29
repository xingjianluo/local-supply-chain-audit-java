package com.github.xingjianluo.localsupplychainauditjava.model;

/** Distinct, traceable processing outcomes for a single manifest file. */
public enum ManifestStatus {
    PARSED,
    PARTIALLY_PARSED,
    CORRUPT
}

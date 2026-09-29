package com.github.xingjianluo.localsupplychainauditjava.model;

/** Lifecycle states of a scan. CANCELED/SUCCEEDED/FAILED are terminal. */
public enum ScanStatus {
    PENDING,
    RUNNING,
    CANCELED,
    SUCCEEDED,
    FAILED
}

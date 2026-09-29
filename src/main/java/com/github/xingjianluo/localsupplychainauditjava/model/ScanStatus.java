package com.github.xingjianluo.localsupplychainauditjava.model;

/** 扫描生命周期状态。任一时刻最多只有一个 RUNNING 扫描。 */
public enum ScanStatus {
    RUNNING,
    COMPLETED,
    CANCELLED,
    FAILED
}

package com.github.xingjianluo.localsupplychainauditjava.service;

/** 已有扫描在运行时重复提交产生的冲突。 */
public class ScanConflictException extends RuntimeException {

    private final String activeScanId;

    public ScanConflictException(String activeScanId) {
        super("another scan is already running: " + activeScanId);
        this.activeScanId = activeScanId;
    }

    public String activeScanId() {
        return activeScanId;
    }
}

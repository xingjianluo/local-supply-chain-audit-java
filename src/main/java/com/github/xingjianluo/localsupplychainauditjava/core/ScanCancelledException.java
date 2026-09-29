package com.github.xingjianluo.localsupplychainauditjava.core;

/** 扫描在执行过程中被协作式取消。 */
public class ScanCancelledException extends RuntimeException {
    public ScanCancelledException() {
        super("scan cancelled");
    }
}

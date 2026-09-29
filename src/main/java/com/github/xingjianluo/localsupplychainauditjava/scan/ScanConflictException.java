package com.github.xingjianluo.localsupplychainauditjava.scan;

/**
 * Raised when a start request conflicts with an already running scan,
 * so callers receive an explicit, distinguishable conflict response.
 */
public class ScanConflictException extends RuntimeException {

    private final String runningScanId;

    public ScanConflictException(String runningScanId, String message) {
        super(message);
        this.runningScanId = runningScanId;
    }

    public String getRunningScanId() {
        return runningScanId;
    }
}
